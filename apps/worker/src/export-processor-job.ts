import { createCipheriv, createHash, hkdfSync, randomBytes, randomUUID } from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { getDatabaseClient } from '@sda/database';
import { formatExportPayload } from './exports/export-formatter.js';
import {
  resolveWorkerExportS3Config,
  uploadExportCiphertextToS3,
} from './exports/export-s3-storage.js';
import { parseFilterParams, queryExportDataset } from './export-query.helper.js';
import { publishWorkerRealtimeEvent } from './realtime-redis-publisher.js';
import { recordWorkerJobRun, setExportQueueDepth } from './worker-metrics.js';

/**
 * Thuật toán / Tổng quan module:
 * Bộ xử lý hàng đợi kết xuất báo cáo bất đồng bộ (`ExportProcessorJob`) trên bảng `async_export_jobs`:
 * - Chiếm giữ nguyên tử công việc `PENDING` sang `PROCESSING` bằng `FOR UPDATE SKIP LOCKED` (hoặc điều kiện `updateMany`).
 * - Mã hóa `AES-256-GCM` tại chỗ (`SDEA\x01`, AAD = `jobId`, HKDF-SHA256 từ `EXPORT_ENCRYPTION_KEY`/`AUDIT_INTEGRITY_KEY`),
 *   lưu đồng thời lên `STORAGE_BUCKET_DERIVATIVES` (`exports/<jobId>.dat` trên Cloudflare R2/S3 khi cấu hình có mặt)
 *   và ghi nguyên tử vào `EXPORT_STORAGE_DIR`, tính `sha256_hash` bản rõ và hoàn tất `COMPLETED`.
 */

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export const DEFAULT_EXPORT_STORAGE_DIR = path.resolve(
  import.meta.dirname,
  '../../../.local/exports',
);
const DEFAULT_BATCH_SIZE = 10;
const EXPORT_MAGIC = Buffer.from('SDEA\x01', 'binary');
const EPHEMERAL_FALLBACK_KEY = randomBytes(32);

function encryptExportArtifactBuffer(jobId: string, plaintext: Buffer): Buffer {
  const configured =
    process.env['EXPORT_ENCRYPTION_KEY']?.trim() || process.env['AUDIT_INTEGRITY_KEY']?.trim();
  const nodeEnv = process.env['NODE_ENV']?.trim().toLowerCase();
  if (!configured && (nodeEnv === 'production' || nodeEnv === 'staging')) {
    throw new Error(
      'EXPORT_ENCRYPTION_KEY (or AUDIT_INTEGRITY_KEY) is mandatory for worker export encryption in production and staging.',
    );
  }
  const ikm = configured ? Buffer.from(configured, 'utf8') : EPHEMERAL_FALLBACK_KEY;
  const key = Buffer.from(
    hkdfSync(
      'sha256',
      ikm,
      Buffer.from('sda-export-at-rest-salt-v1', 'utf8'),
      Buffer.from('sda-export-artifact-aes-256-gcm', 'utf8'),
      32,
    ),
  );
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(jobId, 'utf8'));
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([EXPORT_MAGIC, iv, cipher.getAuthTag(), encrypted]);
}

export interface ExportProcessorSummary {
  claimed: number;
  completed: number;
  failed: number;
}

interface PendingExportJobRow {
  id: string;
  requester_user_id?: bigint | string | null;
  export_type: string;
  format: string;
  filter_params: unknown;
  expires_at?: Date | string | null;
}

/**
 * Thuật toán: Chiếm giữ nguyên tử lô công việc kết xuất `PENDING` bằng `FOR UPDATE SKIP LOCKED` hoặc `updateMany` có điều kiện.
 */
async function claimPendingExportJobs(
  database: PrismaClient,
  batchSize: number,
): Promise<PendingExportJobRow[]> {
  if (typeof database.$queryRawUnsafe === 'function') {
    return database.$queryRawUnsafe<PendingExportJobRow[]>(
      `WITH claimed AS (
         SELECT id
         FROM async_export_jobs
         WHERE status = 'PENDING'
         ORDER BY created_at ASC
         LIMIT $1
         FOR UPDATE SKIP LOCKED
       )
       UPDATE async_export_jobs AS j
       SET status = 'PROCESSING'
       FROM claimed
       WHERE j.id = claimed.id
       RETURNING j.id, j.requester_user_id, j.export_type, j.format, j.filter_params, j.expires_at`,
      batchSize,
    );
  }

  const candidates = await database.asyncExportJob.findMany({
    where: { status: 'PENDING' },
    orderBy: { created_at: 'asc' },
    take: batchSize,
    select: {
      id: true,
      requester_user_id: true,
      export_type: true,
      format: true,
      filter_params: true,
      expires_at: true,
    },
  });
  const claimed: PendingExportJobRow[] = [];
  for (const job of candidates) {
    if (typeof database.asyncExportJob.updateMany === 'function') {
      const res = await database.asyncExportJob.updateMany({
        where: { id: job.id, status: 'PENDING' },
        data: { status: 'PROCESSING' },
      });
      if (res.count !== 1) continue;
    }
    claimed.push(job);
  }
  return claimed;
}

/**
 * Thuật toán: Xử lý lô công việc xuất báo cáo bất đồng bộ, ghi tệp nguyên tử vào `EXPORT_STORAGE_DIR` và cập nhật `sha256_hash`.
 */
export async function processPendingExportJobs(options?: {
  databaseClient?: PrismaClient;
  batchSize?: number;
  exportBaseDir?: string;
  now?: Date;
}): Promise<ExportProcessorSummary> {
  const database = options?.databaseClient ?? getDatabaseClient();
  const batchSize = options?.batchSize ?? DEFAULT_BATCH_SIZE;
  const now = options?.now ?? new Date();
  const resolvedBaseDir = path.resolve(
    options?.exportBaseDir ??
      (process.env['EXPORT_STORAGE_DIR']?.trim() || DEFAULT_EXPORT_STORAGE_DIR),
  );

  const s3Enabled = resolveWorkerExportS3Config() !== null;
  await fsp.mkdir(resolvedBaseDir, { recursive: true }).catch((err) => {
    if (!s3Enabled) throw err;
  });
  const claimedJobs = await claimPendingExportJobs(database, batchSize);
  if (typeof database.asyncExportJob?.count === 'function') {
    const remaining = await database.asyncExportJob.count({ where: { status: 'PENDING' } });
    setExportQueueDepth(remaining);
  }

  const summary: ExportProcessorSummary = {
    claimed: claimedJobs.length,
    completed: 0,
    failed: 0,
  };

  for (const job of claimedJobs) {
    const requesterUserId =
      job.requester_user_id !== undefined && job.requester_user_id !== null
        ? String(job.requester_user_id)
        : null;
    const expiresAtIso =
      job.expires_at instanceof Date
        ? job.expires_at.toISOString()
        : typeof job.expires_at === 'string'
          ? job.expires_at
          : undefined;
    if (requesterUserId) {
      void publishWorkerRealtimeEvent({
        type: 'EXPORT_JOB_UPDATED',
        targetUserIds: [requesterUserId],
        payload: {
          id: job.id,
          exportType: job.export_type,
          format: job.format,
          status: 'PROCESSING',
          ...(expiresAtIso ? { expiresAt: expiresAtIso } : {}),
        },
      });
    }
    try {
      const safeId = job.id.replace(/[^a-zA-Z0-9_-]/gu, '');
      if (!safeId) throw new Error('Invalid export job identifier');

      const filterParams = parseFilterParams(job.filter_params);
      const rows = await queryExportDataset(database, job.export_type, filterParams);
      const artifact = formatExportPayload(job.export_type, job.format, rows, now);

      const finalPath = path.resolve(resolvedBaseDir, `${safeId}.dat`);
      const rel = path.relative(resolvedBaseDir, finalPath);
      if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
        throw new Error('Export output path escaped storage containment boundary');
      }

      const encryptedEnvelope = encryptExportArtifactBuffer(job.id, artifact.buffer);
      // CONFLICT-RESOLVED: Lưu đồng thời bản mã `.dat` (`AES-256-GCM`) lên Cloudflare R2/S3 (`exports/<jobId>.dat`) và đĩa cục bộ để hỗ trợ đa container mà vẫn giữ tương thích 100% kiểm thử `.local/exports`.
      const s3Uri = s3Enabled ? await uploadExportCiphertextToS3(safeId, encryptedEnvelope) : null;

      let persistedPath = finalPath;
      try {
        const tempPath = `${finalPath}.${randomUUID()}.tmp`;
        await fsp.writeFile(tempPath, encryptedEnvelope, { mode: 0o600 });
        await fsp.rename(tempPath, finalPath);
      } catch (fsErr) {
        if (!s3Uri) throw fsErr;
        persistedPath = s3Uri;
      }

      const sha256Hash = createHash('sha256').update(artifact.buffer).digest('hex');
      await database.asyncExportJob.update({
        where: { id: job.id },
        data: {
          status: 'COMPLETED',
          file_path: persistedPath,
          file_size_bytes: BigInt(artifact.buffer.byteLength),
          sha256_hash: sha256Hash,
          mime_type: artifact.mimeType,
          row_count: rows.length,
          error_message: null,
          completed_at: now,
        },
      });
      if (requesterUserId) {
        void publishWorkerRealtimeEvent({
          type: 'EXPORT_JOB_UPDATED',
          targetUserIds: [requesterUserId],
          payload: {
            id: job.id,
            exportType: job.export_type,
            format: job.format,
            status: 'COMPLETED',
            rowCount: rows.length,
            fileSizeBytes: String(artifact.buffer.byteLength),
            sha256Hash,
            completedAt: now.toISOString(),
            ...(expiresAtIso ? { expiresAt: expiresAtIso } : {}),
          },
        });
      }
      summary.completed++;
    } catch (err) {
      const message = (err instanceof Error ? err.message : String(err)).slice(0, 500);
      await database.asyncExportJob
        .update({
          where: { id: job.id },
          data: {
            status: 'FAILED',
            error_message: message,
            completed_at: now,
          },
        })
        .catch(() => {});
      if (requesterUserId) {
        void publishWorkerRealtimeEvent({
          type: 'EXPORT_JOB_UPDATED',
          targetUserIds: [requesterUserId],
          payload: {
            id: job.id,
            exportType: job.export_type,
            format: job.format,
            status: 'FAILED',
            errorMessage: message,
            completedAt: now.toISOString(),
            ...(expiresAtIso ? { expiresAt: expiresAtIso } : {}),
          },
        });
      }
      summary.failed++;
    }
  }

  return summary;
}

/**
 * Thuật toán: Bộ lập lịch định kỳ chống chồng lấn chu kỳ (Non-Overlapping Interval Scheduler) cho `ExportProcessorJob`.
 */
export function startExportProcessorJob(intervalMs: number, signal: AbortSignal): void {
  if (signal.aborted) return;

  let isRunning = false;
  const timer = setInterval(async () => {
    if (signal.aborted) {
      clearInterval(timer);
      return;
    }
    if (isRunning) return;
    isRunning = true;
    try {
      const result = await processPendingExportJobs();
      recordWorkerJobRun('export_processor', 'success');
      if (result.claimed > 0) {
        console.info(
          `Export processor completed ${result.completed}/${result.claimed} job(s) (${result.failed} failed).`,
        );
      }
    } catch (err) {
      recordWorkerJobRun('export_processor', 'error');
      console.error(`Export processor cycle failed: ${err}`);
    } finally {
      isRunning = false;
    }
  }, intervalMs);

  signal.addEventListener(
    'abort',
    () => {
      clearInterval(timer);
      console.info('Export processor worker stopped cleanly.');
    },
    { once: true },
  );

  console.info(`Export processor worker started (interval: ${intervalMs}ms).`);
}

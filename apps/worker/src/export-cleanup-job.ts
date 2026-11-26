import { getDatabaseClient } from '@sda/database';
import fsp from 'node:fs/promises';
import path from 'node:path';
import {
  deleteExportCiphertextFromS3,
  isCrossContainerExportFilename,
  isValidExportS3UriForJob,
  resolveWorkerExportS3Config,
} from './exports/export-s3-storage.js';
import { recordWorkerJobRun } from './worker-metrics.js';

/**
 * Thuật toán / Tổng quan module:
 * Tiến trình thu hồi tệp kết xuất kiểm toán bất đồng bộ (`async_export_jobs`) đã hết hạn thời gian sống (`expires_at < now`),
 * neo thư mục dự phòng chuẩn theo `import.meta.dirname` (`../../../.local/exports` đồng bộ 100% với `@sda/api`),
 * xóa đồng bộ đối tượng `exports/<jobId>.dat` trên Cloudflare R2/S3 (nếu có) và kiểm tra giam cầm đường dẫn trước khi `unlink`.
 */

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export const DEFAULT_EXPORT_CLEANUP_DIR = path.resolve(
  import.meta.dirname,
  '../../../.local/exports',
);

export interface ExportCleanupResult {
  expiredJobsCleaned: number;
  filesDeleted: number;
}

/**
 * Thuật toán: Thu dọn công việc xuất dữ liệu hết hạn có kiểm soát biên thư mục (Bounded Path Containment Cleanup).
 * - Neo thư mục gốc mặc định vào `path.resolve(import.meta.dirname, '../../../.local/exports')` thay vì `process.cwd()`.
 * - Dùng `lstat` xác minh là tệp thường nằm bên trong `resolvedBaseDir` trước khi xóa tệp vật lý và bản ghi CSDL.
 */
export async function cleanExpiredExportJobs(options?: {
  databaseClient?: PrismaClient;
  now?: Date;
  exportBaseDir?: string;
}): Promise<ExportCleanupResult> {
  const database = options?.databaseClient ?? getDatabaseClient();
  const now = options?.now ?? new Date();
  const resolvedBaseDir = path.resolve(
    options?.exportBaseDir ??
      (process.env['EXPORT_STORAGE_DIR']?.trim() || DEFAULT_EXPORT_CLEANUP_DIR),
  );

  let expiredJobsCleaned = 0;
  let filesDeleted = 0;

  try {
    const expiredJobs = await database.asyncExportJob.findMany({
      where: {
        expires_at: { lt: now },
      },
      select: {
        id: true,
        file_path: true,
      },
    });

    const s3Enabled = resolveWorkerExportS3Config() !== null;

    for (const job of expiredJobs) {
      const safeId = job.id.replace(/[^a-zA-Z0-9_-]/gu, '');
      let deletedForCurrentJob = false;

      if (job.file_path?.startsWith('s3://')) {
        if (!safeId || !isValidExportS3UriForJob(job.file_path, safeId)) {
          console.warn(
            `Export cleanup refused invalid S3 export URI for job ${job.id}: ${job.file_path}`,
          );
          continue;
        }
        try {
          if (await deleteExportCiphertextFromS3(safeId)) {
            deletedForCurrentJob = true;
          }
        } catch (s3Err) {
          console.warn(
            `Export cleanup failed to delete S3 object for job ${job.id}: ${s3Err instanceof Error ? s3Err.message : String(s3Err)}`,
          );
          continue;
        }
        const mirrorLocal = path.resolve(resolvedBaseDir, `${safeId}.dat`);
        await fsp.unlink(mirrorLocal).catch(() => {});
      } else if (job.file_path) {
        const resolvedTarget = path.resolve(job.file_path);
        const relativePath = path.relative(resolvedBaseDir, resolvedTarget);
        const isInsideBaseDir =
          relativePath.length > 0 &&
          !relativePath.startsWith('..') &&
          !path.isAbsolute(relativePath);

        if (!isInsideBaseDir) {
          if (s3Enabled && safeId && isCrossContainerExportFilename(job.file_path, safeId)) {
            try {
              const removedRemote = await deleteExportCiphertextFromS3(safeId);
              deletedForCurrentJob = deletedForCurrentJob || removedRemote;
            } catch (s3Err) {
              console.warn(
                `Export cleanup failed to delete cross-container S3 mirror for job ${job.id}: ${s3Err instanceof Error ? s3Err.message : String(s3Err)}`,
              );
              continue;
            }
          } else {
            console.warn(
              `Export cleanup refused to unlink out-of-bounds file_path for job ${job.id}`,
            );
            continue;
          }
        } else {
          try {
            const stat = await fsp.lstat(resolvedTarget);
            if (!stat.isFile()) {
              console.warn(
                `Export cleanup refused to unlink non-regular file_path for job ${job.id}`,
              );
              continue;
            }
            await fsp.unlink(resolvedTarget);
            deletedForCurrentJob = true;
          } catch (fileErr: unknown) {
            const errCode = (fileErr as NodeJS.ErrnoException | null | undefined)?.code;
            if (errCode !== 'ENOENT') {
              console.warn(
                `Export cleanup failed to unlink file for job ${job.id} (${errCode ?? 'UNKNOWN'}): ${fileErr instanceof Error ? fileErr.message : String(fileErr)}`,
              );
              continue;
            }
          }

          if (s3Enabled && safeId) {
            try {
              const removedRemote = await deleteExportCiphertextFromS3(safeId);
              deletedForCurrentJob = deletedForCurrentJob || removedRemote;
            } catch (s3Err) {
              console.warn(
                `Export cleanup failed to delete S3 mirror for job ${job.id}: ${s3Err instanceof Error ? s3Err.message : String(s3Err)}`,
              );
              continue;
            }
          }
        }
      } else if (safeId) {
        // CONFLICT-RESOLVED: Xóa cả đối tượng `exports/<safeId>.dat` trên S3/R2 lẫn bản gương cục bộ khi `file_path === null` (ví dụ Worker sập ngay sau khi upload S3 nhưng trước khi cập nhật CSDL — BUG-067).
        if (s3Enabled) {
          try {
            const removedRemote = await deleteExportCiphertextFromS3(safeId);
            deletedForCurrentJob = deletedForCurrentJob || removedRemote;
          } catch (s3Err) {
            console.warn(
              `Export cleanup failed to delete orphaned S3 object for null-path job ${job.id}: ${s3Err instanceof Error ? s3Err.message : String(s3Err)}`,
            );
            continue;
          }
        }
        const mirrorLocal = path.resolve(resolvedBaseDir, `${safeId}.dat`);
        try {
          const stat = await fsp.lstat(mirrorLocal);
          if (stat.isFile()) {
            await fsp.unlink(mirrorLocal);
            deletedForCurrentJob = true;
          }
        } catch {
          // Ignore ENOENT when no orphaned local artifact exists
        }
      }

      if (deletedForCurrentJob) {
        filesDeleted++;
      }

      await database.asyncExportJob.delete({
        where: { id: job.id },
      });
      expiredJobsCleaned++;
    }
  } catch (err) {
    console.warn(`Export cleanup encountered error: ${err}`);
  }

  return { expiredJobsCleaned, filesDeleted };
}

/**
 * Thuật toán: Bộ lập lịch định kỳ chống chồng lấn chu kỳ (Non-Overlapping Interval Scheduler) cho `ExportCleanupJob`.
 */
export function startExportCleanupJob(intervalMs: number, signal: AbortSignal): void {
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
      const result = await cleanExpiredExportJobs();
      recordWorkerJobRun('export_cleanup', 'success');
      if (result.expiredJobsCleaned > 0) {
        console.info(
          `Export cleanup job purged ${result.expiredJobsCleaned} expired export job(s) and ${result.filesDeleted} file(s).`,
        );
      }
    } catch (err) {
      recordWorkerJobRun('export_cleanup', 'error');
      console.error(`Export cleanup cycle failed: ${err}`);
    } finally {
      isRunning = false;
    }
  }, intervalMs);

  signal.addEventListener(
    'abort',
    () => {
      clearInterval(timer);
      console.info('Export cleanup worker stopped cleanly.');
    },
    { once: true },
  );

  console.info(`Export cleanup worker started (interval: ${intervalMs}ms).`);
}

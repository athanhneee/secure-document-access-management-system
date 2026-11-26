/**
 * Module: Asynchronous Export Job Execution & Pending Queue Runner Helper
 * Thuật toán: Thực Thi Tác Vụ Xuất Báo Cáo & Xử Lý Hàng Đợi `PENDING` Có Phạm Vi Phòng Ban (`ExportJobRunnerHelper`).
 *   1. Chuẩn hóa đóng gói/khôi phục `__allowedDepartmentIds` trong `filter_params` để đồng bộ hợp đồng phạm vi phòng ban giữa `@sda/api` và `@sda/worker`.
 *   2. Chuyển trạng thái `PENDING -> PROCESSING -> COMPLETED | FAILED`, kết xuất dữ liệu, tính băm `SHA-256` và lưu tệp `.dat` mã hóa `AES-256-GCM` vào `.local/exports`.
 */
import type { Logger } from '@nestjs/common';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { getDatabaseClient } from '@sda/database';
import {
  extractPersistedExportScope as extractSharedPersistedExportScope,
  normalizeExportFilters as normalizeSharedExportFilters,
  serializePersistedExportFilters,
  type CreateExportJobInput,
  type ExportFormat,
  type ExportType,
  type NormalizedExportFilters,
} from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { RealtimeEventsService } from '../realtime/realtime-events.service.js';
import { renderExportBuffer } from './export-artifact.helper.js';
import { buildExportDataset } from './export-dataset.builder.js';
import { encryptExportArtifactBuffer } from './export-disk-cipher.helper.js';
import { resolveExportAuthorizationScope } from './export-filter-scope.helper.js';
import { resolveApiExportS3Config, uploadEncryptedExportToS3 } from './export-s3-storage.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Đóng gói tham số lọc đã chuẩn hóa kèm danh sách chuỗi mã phòng ban được phép (`__allowedDepartmentIds`) để lưu xuống cột JSON `filter_params`.
 */
export function buildPersistedExportFilters(
  filters: NormalizedExportFilters | Record<string, unknown>,
  allowedDepartmentIds: bigint[] | null,
): Record<string, unknown> {
  const normalized: NormalizedExportFilters =
    filters &&
    typeof filters === 'object' &&
    'effectiveDepartmentIds' in filters &&
    'fromDate' in filters
      ? (filters as NormalizedExportFilters)
      : normalizeSharedExportFilters(filters, allowedDepartmentIds);
  return serializePersistedExportFilters(normalized, allowedDepartmentIds);
}

/**
 * Thuật toán: Tách và khôi phục mảng `bigint[] | null` của `__allowedDepartmentIds` từ `filter_params` đã lưu trong PostgreSQL.
 */
export function extractPersistedExportScope(persistedFilterParams: unknown): {
  cleanFilterParams: Record<string, unknown>;
  allowedDepartmentIds: bigint[] | null;
} {
  return extractSharedPersistedExportScope(persistedFilterParams);
}

/**
 * Thuật toán: Thực thi đường ống kết xuất báo cáo, băm toàn vẹn `SHA-256` và lưu tệp `.dat` mã hóa `AES-256-GCM` trên đĩa.
 */
export async function executeExportJobPipeline(params: {
  database: PrismaClient;
  authorization: AuthorizationService | undefined;
  exportDir: string;
  logger: Logger;
  jobId: string;
  input: CreateExportJobInput;
  actor: AuthPrincipal;
  correlationId?: string | undefined;
  preResolvedDepartmentIds?: bigint[] | null | undefined;
  realtime?: RealtimeEventsService | undefined;
}): Promise<void> {
  const {
    database,
    authorization,
    exportDir,
    logger,
    jobId,
    input,
    actor,
    correlationId,
    preResolvedDepartmentIds,
    realtime,
  } = params;
  const activeCorrId = correlationId || 'worker-internal';
  logger.log(
    `[Worker][ExportJob: ${jobId}][CorrelationId: ${activeCorrId}] Processing ${input.exportType} (${input.format})`,
  );

  try {
    // MED-08: Cưỡng chế CAS nguyên tử `PENDING -> PROCESSING` để tránh API và Worker cùng chạy kép hoặc ghi đè trạng thái `COMPLETED`.
    if (typeof database.asyncExportJob.updateMany === 'function') {
      const claimed = await database.asyncExportJob.updateMany({
        where: { id: jobId, status: 'PENDING' },
        data: { status: 'PROCESSING' },
      });
      if (claimed.count === 0) {
        logger.log(`[Worker][ExportJob: ${jobId}] Already claimed or completed; skipping.`);
        return;
      }
    } else {
      await database.asyncExportJob.update({
        where: { id: jobId },
        data: { status: 'PROCESSING' },
      });
    }
    realtime?.publish({
      type: 'EXPORT_JOB_UPDATED',
      targetUserIds: [actor.userId.toString()],
      payload: {
        id: jobId,
        exportType: input.exportType,
        format: input.format,
        status: 'PROCESSING',
      },
    });

    const allowedDeptIds =
      preResolvedDepartmentIds !== undefined
        ? preResolvedDepartmentIds
        : await resolveExportAuthorizationScope(authorization, actor, input.exportType);
    const dataset = await buildExportDataset(
      database,
      input.exportType,
      input.filterParams,
      allowedDeptIds,
    );
    const { contentBuffer, mimeType } = await renderExportBuffer(input.format, dataset);
    const sha256Hash = createHash('sha256').update(contentBuffer).digest('hex');
    const encryptedEnvelope = encryptExportArtifactBuffer(jobId, contentBuffer);
    const s3Uri =
      resolveApiExportS3Config() !== null
        ? await uploadEncryptedExportToS3(jobId, encryptedEnvelope)
        : null;

    let filePath = path.join(exportDir, `${jobId}.dat`);
    try {
      if (!fs.existsSync(exportDir)) {
        fs.mkdirSync(exportDir, { recursive: true, mode: 0o700 });
      }
      fs.writeFileSync(filePath, encryptedEnvelope, { mode: 0o600 });
    } catch (fsErr) {
      if (!s3Uri) throw fsErr;
      filePath = s3Uri;
    }

    const completedAt = new Date();
    const updatedJob = await database.asyncExportJob.update({
      where: { id: jobId },
      data: {
        status: 'COMPLETED',
        completed_at: completedAt,
        file_path: filePath,
        file_size_bytes: BigInt(contentBuffer.length),
        sha256_hash: sha256Hash,
        mime_type: mimeType,
        row_count: dataset.rows.length,
      },
    });
    realtime?.publish({
      type: 'EXPORT_JOB_UPDATED',
      targetUserIds: [actor.userId.toString()],
      payload: {
        id: jobId,
        exportType: input.exportType,
        format: input.format,
        status: 'COMPLETED',
        rowCount: dataset.rows.length,
        fileSizeBytes: String(contentBuffer.length),
        sha256Hash,
        completedAt: completedAt.toISOString(),
        ...(updatedJob?.expires_at ? { expiresAt: updatedJob.expires_at.toISOString() } : {}),
      },
    });
  } catch (err) {
    logger.error(`Export job ${jobId} failed:`, err);
    const errorMessage = err instanceof Error ? err.message : String(err);
    await database.asyncExportJob
      .update({
        where: { id: jobId },
        data: { status: 'FAILED', error_message: errorMessage },
      })
      .catch((uErr) => logger.error(`Failed to persist FAILED status for job ${jobId}:`, uErr));
    realtime?.publish({
      type: 'EXPORT_JOB_UPDATED',
      targetUserIds: [actor.userId.toString()],
      payload: {
        id: jobId,
        exportType: input.exportType,
        format: input.format,
        status: 'FAILED',
        errorMessage,
      },
    });
  }
}

/**
 * Thuật toán: Nạp và xử lý một tác vụ xuất đang ở trạng thái `PENDING` theo `jobId` phục vụ tiến trình worker nền.
 */
export async function executePendingExportJobById(params: {
  database: PrismaClient;
  authorization: AuthorizationService | undefined;
  exportDir: string;
  logger: Logger;
  jobId: string;
}): Promise<void> {
  const { database, authorization, exportDir, logger, jobId } = params;
  const job = await database.asyncExportJob.findUnique({ where: { id: jobId } });
  if (!job || job.status !== 'PENDING') return;

  const { cleanFilterParams, allowedDepartmentIds } = extractPersistedExportScope(
    job.filter_params,
  );
  await executeExportJobPipeline({
    database,
    authorization,
    exportDir,
    logger,
    jobId: job.id,
    input: {
      exportType: job.export_type as ExportType,
      format: job.format as ExportFormat,
      filterParams: cleanFilterParams,
    },
    actor: {
      userId: job.requester_user_id,
      sessionId: 'worker-export-processor',
      username: 'worker',
      roles: [],
      mfa: true,
    },
    correlationId: 'worker-export-processor',
    preResolvedDepartmentIds: allowedDepartmentIds,
  });
}

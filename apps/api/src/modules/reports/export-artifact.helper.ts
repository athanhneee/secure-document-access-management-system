/**
 * Module: Export Artifact Serialization, Path-Traversal Verification & Job DTO Mapper
 * Algorithm: Serializes tabular datasets into JSON/PDF/XLSX/formula-safe CSV, enforces canonical directory
 *   containment + symlink rejection when reading disk artifacts, and projects TTL-aware `ExportJobDetail` DTOs.
 */
import { BadRequestException, ForbiddenException, type Logger } from '@nestjs/common';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { AppErrorCode, type ExportFormat, type ExportType } from '@sda/contracts';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import { generateCsv } from './csv-formula-sanitizer.js';
import { resolveExportAuthorizationScope } from './export-filter-scope.helper.js';
import { generateExcelTable, generatePdfTable, type ExportColumn } from './export-formatter.js';

export interface ExportJobDetail {
  id: string;
  requesterUserId: string;
  exportType: ExportType;
  format: ExportFormat;
  status: 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | 'EXPIRED';
  fileSizeBytes: string | null;
  sha256Hash: string | null;
  mimeType: string | null;
  rowCount: number;
  errorMessage: string | null;
  createdAt: string;
  completedAt: string | null;
  expiresAt: string;
  isExpired: boolean;
}

export interface ExportDatasetPayload {
  reportTitle: string;
  rawRecords: unknown[];
  columns: ExportColumn[];
  rows: Record<string, string>[];
}

/**
 * Algorithm: Multi-Format Report Serialization (JSON / PDF / XLSX / Formula-Safe CSV)
 */
export async function renderExportBuffer(
  format: ExportFormat,
  dataset: ExportDatasetPayload,
): Promise<{ contentBuffer: Buffer; mimeType: string }> {
  if (format === 'JSON') {
    return {
      mimeType: 'application/json',
      contentBuffer: Buffer.from(
        JSON.stringify(
          dataset.rawRecords,
          (_key, value) => (typeof value === 'bigint' ? value.toString() : value),
          2,
        ),
        'utf-8',
      ),
    };
  }
  if (format === 'PDF') {
    return {
      mimeType: 'application/pdf',
      contentBuffer: await generatePdfTable(dataset.reportTitle, dataset.columns, dataset.rows),
    };
  }
  if (format === 'EXCEL') {
    return {
      mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      contentBuffer: await generateExcelTable(dataset.reportTitle, dataset.columns, dataset.rows),
    };
  }
  return {
    mimeType: 'text/csv; charset=utf-8',
    contentBuffer: Buffer.from(generateCsv(dataset.rows, dataset.columns), 'utf-8'),
  };
}

/**
 * Thuật toán: Phân giải phần mở rộng tệp và kiểu MIME chuẩn theo định dạng xuất báo cáo.
 */
export function resolveExportDownloadMeta(format: string): { ext: string; mimeType: string } {
  const upper = format.toUpperCase();
  if (upper === 'EXCEL') {
    return {
      ext: 'xlsx',
      mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    };
  }
  if (upper === 'PDF') return { ext: 'pdf', mimeType: 'application/pdf' };
  if (upper === 'JSON') return { ext: 'json', mimeType: 'application/json' };
  return { ext: 'csv', mimeType: 'text/csv; charset=utf-8' };
}

/**
 * Algorithm / Thuật toán: Kiểm tra quyền sở hữu tác vụ xuất báo cáo hoặc vai trò giám sát tương ứng theo miền dữ liệu.
 */
export function assertExportJobAccess(
  job: { requester_user_id: bigint; export_type: string },
  actor: AuthPrincipal,
): void {
  if (job.requester_user_id === actor.userId) return;
  const roles = actor.roles ?? [];
  if (roles.includes('SYSTEM_ADMIN')) return;
  if (job.export_type === 'AUDIT_LOGS' && roles.includes('AUDITOR')) return;
  if (
    (job.export_type === 'SECURITY_ALERTS' ||
      job.export_type === 'INCIDENT_REPORTS' ||
      job.export_type === 'SYSTEM_REPORT') &&
    roles.includes('SECURITY_OFFICER')
  ) {
    return;
  }

  throw new ForbiddenException({
    errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
    message: 'You are not authorized to access or download this export job.',
  });
}

/**
 * Thuật toán: Ràng buộc phạm vi phòng ban khi quản trị viên/kiểm toán viên tra cứu hoặc tải tác vụ xuất của người dùng khác (HIGH-13).
 */
export async function assertCrossUserExportScope(
  database: {
    user?: {
      findUnique: (args: {
        where: { id: bigint };
        select: { department_id: true };
      }) => Promise<{ department_id: bigint | null } | null>;
    };
  },
  authorization: AuthorizationService | undefined,
  job: { requester_user_id: bigint; export_type: string; filter_params?: unknown },
  actor: AuthPrincipal,
): Promise<void> {
  if (job.requester_user_id === actor.userId) return;
  // CONFLICT-RESOLVED: Bắt buộc kiểm tra phạm vi phòng ban cho cả getExportJob và downloadExportJob khi truy cập chéo người dùng (HIGH-13)
  const allowedDepartmentIds = await resolveExportAuthorizationScope(
    authorization,
    actor,
    job.export_type as ExportType,
  );
  if (allowedDepartmentIds === null) return;

  const filterParams =
    job.filter_params && typeof job.filter_params === 'object' && !Array.isArray(job.filter_params)
      ? (job.filter_params as Record<string, unknown>)
      : null;
  const rawFilterDept = filterParams?.['departmentId'];
  if (
    rawFilterDept !== undefined &&
    rawFilterDept !== null &&
    /^\d+$/.test(String(rawFilterDept))
  ) {
    if (!allowedDepartmentIds.includes(BigInt(String(rawFilterDept)))) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
        message: 'Export job filter scope is outside your authorized departments.',
      });
    }
  }

  const requester = await database.user?.findUnique({
    where: { id: job.requester_user_id },
    select: { department_id: true },
  });
  if (
    !requester ||
    requester.department_id === null ||
    !allowedDepartmentIds.includes(requester.department_id)
  ) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
      message: 'Export job belongs to a department outside your authorized scope.',
    });
  }
}

/**
 * Algorithm: Export Job TTL & Lifecycle Readiness Gate
 */
export function assertExportJobReadyForDownload(job: {
  expires_at: Date;
  status: string;
  error_message: string | null;
}): void {
  if (job.expires_at < new Date() || job.status === 'EXPIRED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.EXPORT_JOB_EXPIRED,
      message: 'This export job has expired. Please initiate a new export request.',
    });
  }
  if (job.status === 'PENDING' || job.status === 'PROCESSING') {
    throw new BadRequestException({
      errorCode: AppErrorCode.EXPORT_JOB_PENDING,
      message: 'Export job is still processing. Please try again shortly.',
    });
  }
  if (job.status === 'FAILED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.INTERNAL_SERVER_ERROR,
      message: `Export job failed: ${job.error_message ?? 'Unknown error'}`,
    });
  }
}

/**
 * Algorithm: Bounded-FIFO (50-Entry) In-Memory & Disk Artifact Persistence
 */
export function persistBoundedExportArtifact(
  exportDir: string,
  memoryStorage: Map<string, Buffer>,
  jobId: string,
  contentBuffer: Buffer,
): string | null {
  if (memoryStorage.size >= 50) {
    const oldestKey = memoryStorage.keys().next().value;
    if (oldestKey !== undefined) memoryStorage.delete(oldestKey);
  }
  memoryStorage.set(jobId, contentBuffer);

  try {
    const filePath = path.join(exportDir, `${jobId}.dat`);
    fs.writeFileSync(filePath, contentBuffer);
    return filePath;
  } catch {
    return null;
  }
}

/**
 * Algorithm: Canonical Path-Traversal & Symlink-Hardened Artifact Reader
 */
export function readVerifiedExportArtifact(
  exportDir: string,
  memoryStorage: Map<string, Buffer>,
  id: string,
  filePath: string | null,
  logger: Logger,
): Buffer | null {
  const cached = memoryStorage.get(id);
  if (cached) return cached;
  if (!filePath) return null;

  const resolvedBase = path.resolve(exportDir);
  const resolvedTarget = path.resolve(filePath);
  if (!resolvedTarget.startsWith(`${resolvedBase}${path.sep}`) && resolvedTarget !== resolvedBase) {
    logger.error(`Blocked out-of-bounds export file_path read for job ${id}`);
    throw new ForbiddenException({
      errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
      message: 'Export artifact path is invalid.',
    });
  }
  if (fs.existsSync(resolvedTarget) && !fs.lstatSync(resolvedTarget).isSymbolicLink()) {
    return fs.readFileSync(resolvedTarget);
  }
  return null;
}

/**
 * Thuật toán: Ánh xạ bản ghi `async_export_jobs` sang DTO `ExportJobDetail` an toàn BigInt và tự động suy diễn trạng thái `EXPIRED`.
 */
export function mapExportJobToDetail(job: {
  id: string;
  requester_user_id: bigint;
  export_type: string;
  format: string;
  status: string;
  file_size_bytes: bigint | null;
  sha256_hash: string | null;
  mime_type: string | null;
  row_count: number;
  error_message: string | null;
  created_at: Date;
  completed_at: Date | null;
  expires_at: Date;
}): ExportJobDetail {
  const isExpired = job.expires_at < new Date() || job.status === 'EXPIRED';
  return {
    id: job.id,
    requesterUserId: job.requester_user_id.toString(),
    exportType: job.export_type as ExportType,
    format: job.format as ExportFormat,
    status: (isExpired ? 'EXPIRED' : job.status) as ExportJobDetail['status'],
    fileSizeBytes: job.file_size_bytes?.toString() ?? null,
    sha256Hash: job.sha256_hash,
    mimeType: job.mime_type,
    rowCount: job.row_count,
    errorMessage: job.error_message,
    createdAt: job.created_at.toISOString(),
    completedAt: job.completed_at?.toISOString() ?? null,
    expiresAt: job.expires_at.toISOString(),
    isExpired,
  };
}

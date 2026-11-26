/**
 * Module: Export Artifact Serialization, Encrypted Disk Persistence, Path-Traversal Verification & Job DTO Mapper
 * Thuật toán: Tuần Tự Hóa Báo Cáo Đa Định Dạng, Lưu Trữ Mã Hóa `AES-256-GCM` Trên Đĩa & Đọc Kiểm Chứng Chống Symlink/Path-Traversal (`ExportArtifactHelper`).
 *   1. Kết xuất bảng dữ liệu sang JSON / PDF / XLSX / CSV khử công thức độc hại.
 *   2. Ghi trực tiếp tệp `.dat` mã hóa `AES-256-GCM` (`0o600`) vào thư mục chia sẻ `.local/exports` mà không giữ bản sao `Map` trong RAM.
 *   3. Khi tải xuống, xác minh đường dẫn chuẩn hóa nằm trong `exportDir`, đọc qua file descriptor `O_NOFOLLOW`, giải mã `AES-256-GCM` và đối chiếu băm `SHA-256`.
 */
import { ForbiddenException, type Logger } from '@nestjs/common';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  AppErrorCode,
  formatUnifiedExportJson,
  type ExportFormat,
  type ExportType,
} from '@sda/contracts';
import { generateCsv } from './csv-formula-sanitizer.js';
import {
  decryptAndVerifyExportArtifactBuffer,
  encryptExportArtifactBuffer,
  readContainedExportArtifactBuffer,
} from './export-disk-cipher.helper.js';
import { generateExcelTable, generatePdfTable, type ExportColumn } from './export-formatter.js';
import {
  downloadEncryptedExportFromS3,
  isCrossContainerExportFilename,
  isValidExportS3UriForJob,
  resolveApiExportS3Config,
} from './export-s3-storage.helper.js';

export {
  assertCrossUserExportScope,
  assertExportJobAccess,
  assertExportJobReadyForDownload,
  assertLiveExportDownloadAuthorization,
  resolveWorkspaceExportDir,
} from './export-access-policy.helper.js';

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
  exportType: ExportType;
  reportTitle: string;
  rawRecords: unknown[];
  columns: ExportColumn[];
  rows: Record<string, string>[];
}

/**
 * Thuật toán: Kết xuất tập dữ liệu báo cáo sang bộ đệm nhị phân theo định dạng yêu cầu (JSON phong bì hợp nhất / PDF / XLSX / CSV khử công thức).
 */
export async function renderExportBuffer(
  format: ExportFormat,
  dataset: ExportDatasetPayload,
  generatedAt: Date = new Date(),
): Promise<{ contentBuffer: Buffer; mimeType: string }> {
  if (format === 'JSON') {
    const json = formatUnifiedExportJson(dataset.exportType, dataset.rows, generatedAt);
    return {
      mimeType: 'application/json; charset=utf-8',
      contentBuffer: Buffer.from(json, 'utf-8'),
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
export function resolveExportDownloadMeta(
  format: string,
  storedMimeType?: string | null,
): { ext: string; mimeType: string } {
  const upper = format.toUpperCase();
  if (upper === 'EXCEL') {
    if (storedMimeType?.includes('ms-excel')) {
      return { ext: 'xls', mimeType: storedMimeType };
    }
    return {
      ext: 'xlsx',
      mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    };
  }
  if (upper === 'PDF') return { ext: 'pdf', mimeType: 'application/pdf' };
  if (upper === 'JSON') return { ext: 'json', mimeType: storedMimeType ?? 'application/json' };
  return { ext: 'csv', mimeType: storedMimeType ?? 'text/csv; charset=utf-8' };
}

/**
 * Thuật toán: Ghi bền vững tệp báo cáo đã mã hóa `AES-256-GCM` xuống thư mục chia sẻ `.local/exports` với quyền hạn chế `0o600`.
 */
export function persistExportArtifact(
  exportDir: string,
  jobId: string,
  contentBuffer: Buffer,
): string {
  if (!fs.existsSync(exportDir)) {
    fs.mkdirSync(exportDir, { recursive: true, mode: 0o700 });
  }
  const filePath = path.join(exportDir, `${jobId}.dat`);
  // CONFLICT-RESOLVED: Mã hóa AES-256-GCM và giới hạn quyền tệp 0o600 cho tệp xuất `.dat` trên đĩa (HIGH-07).
  fs.writeFileSync(filePath, encryptExportArtifactBuffer(jobId, contentBuffer), { mode: 0o600 });
  return filePath;
}

/**
 * Thuật toán: Đọc tệp báo cáo đa container (ưu tiên đĩa cục bộ giam cầm `O_NOFOLLOW`, tự động tải dự phòng từ S3/R2 `exports/<jobId>.dat`), giải mã `AES-256-GCM` và xác minh `SHA-256`.
 */
export async function readVerifiedExportArtifactAsync(
  exportDir: string,
  id: string,
  filePath: string | null,
  logger: Logger,
  expectedSha256Hash?: string | null,
): Promise<Buffer | null> {
  if (!filePath) return null;
  const safeId = id.replace(/[^a-zA-Z0-9_-]/gu, '');

  if (filePath.startsWith('s3://')) {
    if (!safeId || !isValidExportS3UriForJob(filePath, safeId)) {
      logger.error(`Blocked invalid S3 export file_path read for job ${id}`);
      throw new ForbiddenException({
        errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
        message: 'Export artifact path is invalid.',
      });
    }
    const rawS3Buffer = await downloadEncryptedExportFromS3(safeId);
    return rawS3Buffer
      ? decryptAndVerifyExportArtifactBuffer(id, rawS3Buffer, expectedSha256Hash, true)
      : null;
  }

  const resolvedBase = path.resolve(exportDir);
  const resolvedTarget = path.resolve(filePath);
  const isContainedLocally =
    resolvedTarget.startsWith(`${resolvedBase}${path.sep}`) || resolvedTarget === resolvedBase;

  if (!isContainedLocally) {
    // CONFLICT-RESOLVED: Trên triển khai đa container Railway/Cloudflare R2, nếu `file_path` mang đường dẫn cục bộ của container Worker khác nhưng khớp đúng `<jobId>.dat` (không có `..`), tải từ S3 thay vì đọc đĩa cục bộ; ngược lại chặn `ForbiddenException`.
    if (resolveApiExportS3Config() !== null && isCrossContainerExportFilename(filePath, safeId)) {
      const rawS3Buffer = await downloadEncryptedExportFromS3(safeId);
      return rawS3Buffer
        ? decryptAndVerifyExportArtifactBuffer(id, rawS3Buffer, expectedSha256Hash, true)
        : null;
    }
    logger.error(`Blocked out-of-bounds export file_path read for job ${id}`);
    throw new ForbiddenException({
      errorCode: AppErrorCode.EXPORT_UNAUTHORIZED,
      message: 'Export artifact path is invalid.',
    });
  }

  const rawDiskBuffer = readContainedExportArtifactBuffer(resolvedTarget);
  if (rawDiskBuffer) {
    return decryptAndVerifyExportArtifactBuffer(id, rawDiskBuffer, expectedSha256Hash, true);
  }

  if (resolveApiExportS3Config() !== null && safeId) {
    const rawS3Buffer = await downloadEncryptedExportFromS3(safeId);
    if (rawS3Buffer) {
      return decryptAndVerifyExportArtifactBuffer(id, rawS3Buffer, expectedSha256Hash, true);
    }
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

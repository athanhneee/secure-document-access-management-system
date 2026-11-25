import type { DownloadBlob } from '@/lib/api-client';
import { formatAuditPartitionLabel, formatAuditViolationMessage } from '@/lib/ui-labels';
import type {
  AuditLogApiDto,
  AuditLogItem,
  AuditLogsPaginatedResponse,
  AuditorPaginationInfo,
  AuditTrailFilters,
  ChainVerificationReport,
  ExportFormat,
  ExportJobItem,
  PartitionVerificationResult,
  VerifyHashChainResponse,
} from './types';

const ISO_DATE_ONLY_REGEX = /^\d{4}-\d{2}-\d{2}$/;
const OPTIMISTIC_JOB_GRACE_MS = 15_000;

export const AUDIT_PARTITION_OPTIONS = [
  'ALL',
  'GLOBAL',
  'AUTH',
  'DOCUMENT',
  'ACCESS_SESSION',
  'RBAC',
  'AUDIT',
  'SECURITY',
  'SECURITY_OPERATIONS',
] as const;

/**
 * Thuật toán: Chuyển Đổi Ngày Cục Bộ `YYYY-MM-DD` Sang Mốc ISO-8601 UTC Đầu/Cuối Ngày (`toLocalDayBoundaryIso`)
 * Mục đích: Đảm bảo lọc "Từ ngày" bắt đầu từ 00:00:00.000 và "Đến ngày" bao trọn đến 23:59:59.999 theo múi giờ người dùng (UTC+7), không bao giờ mất dữ liệu ngày cuối.
 */
export function toLocalDayBoundaryIso(dateStr: string, endOfDay: boolean): string {
  const trimmed = dateStr.trim();
  if (!ISO_DATE_ONLY_REGEX.test(trimmed)) return trimmed;
  const parts = trimmed.split('-').map(Number);
  const year = parts[0] ?? 1970;
  const month = parts[1] ?? 1;
  const day = parts[2] ?? 1;
  const localDate = endOfDay
    ? new Date(year, month - 1, day, 23, 59, 59, 999)
    : new Date(year, month - 1, day, 0, 0, 0, 0);
  return Number.isNaN(localDate.getTime()) ? trimmed : localDate.toISOString();
}

/**
 * Thuật toán: Kiểm Định Hợp Lệ Khoảng Ngày Lọc (`isInvalidDateRange`)
 */
export function isInvalidDateRange(fromDate: string, toDate: string): boolean {
  return Boolean(fromDate && toDate && fromDate > toDate);
}

/**
 * Thuật toán: Truy vấn Có Lọc, Phân Trang & Chuẩn hóa Lược đồ Pháp chứng Nhật ký Kiểm toán (`buildAuditLogsQueryParams`)
 * Mục đích: Đồng bộ danh sách sự kiện kiểm toán theo bộ lọc đa chiều (`outcome`, `action`, `chainPartition`, `actorUsername`, khoảng ngày chuẩn múi giờ, thứ tự sắp xếp) và tham số phân trang (`page`, `pageSize`).
 */
export function buildAuditLogsQueryParams(
  filters: AuditTrailFilters,
  page = 1,
  pageSize = 20,
): URLSearchParams {
  const queryParams = new URLSearchParams();
  if (filters.outcomeFilter && filters.outcomeFilter !== 'ALL') {
    queryParams.set('outcome', filters.outcomeFilter);
  }
  if (filters.actionFilter.trim()) {
    queryParams.set('action', filters.actionFilter.trim());
  }
  if (filters.partitionFilter && filters.partitionFilter !== 'ALL') {
    queryParams.set('chainPartition', filters.partitionFilter);
  }
  if (filters.actorFilter.trim()) {
    queryParams.set('actorUsername', filters.actorFilter.trim());
  }
  if (filters.fromDate) {
    queryParams.set('from', toLocalDayBoundaryIso(filters.fromDate, false));
  }
  if (filters.toDate) {
    queryParams.set('to', toLocalDayBoundaryIso(filters.toDate, true));
  }
  queryParams.set('sort', 'occurred_at');
  queryParams.set('order', filters.sortOrder === 'asc' ? 'asc' : 'desc');
  queryParams.set('page', String(Math.max(1, page)));
  queryParams.set('pageSize', String(pageSize));
  return queryParams;
}

/**
 * Thuật toán: Ánh Xạ Bộ Lọc Kiểm Toán Hiện Hành Sang `filterParams` Của API Xuất Báo Cáo (`buildExportFilterParamsFromAuditFilters`)
 */
export function buildExportFilterParamsFromAuditFilters(
  filters: AuditTrailFilters,
): Record<string, unknown> {
  const params: Record<string, unknown> = {};
  if (filters.outcomeFilter && filters.outcomeFilter !== 'ALL') {
    params['outcome'] = filters.outcomeFilter;
  }
  if (filters.actionFilter.trim()) {
    params['action'] = filters.actionFilter.trim();
  }
  if (filters.partitionFilter && filters.partitionFilter !== 'ALL') {
    params['chainPartition'] = filters.partitionFilter;
  }
  if (filters.actorFilter.trim()) {
    params['actorUsername'] = filters.actorFilter.trim();
  }
  if (filters.fromDate) {
    params['from'] = toLocalDayBoundaryIso(filters.fromDate, false);
  }
  if (filters.toDate) {
    params['to'] = toLocalDayBoundaryIso(filters.toDate, true);
  }
  return params;
}

/**
 * Thuật toán: Chuẩn Hóa DTO Nhật Ký Kiểm Toán Sang Kiểu Hiển Thị An Toàn (`normalizeAuditLogDtos`)
 */
export function normalizeAuditLogDtos(dtos: AuditLogApiDto[]): AuditLogItem[] {
  return dtos.map((l, i) => ({
    id: l.id || `log-${i}`,
    occurredAt: l.occurredAt || '',
    actorUserId: l.actorUserId ?? null,
    actorUsername: l.actorUsername || 'SYSTEM',
    action: l.action || '—',
    objectType: l.objectType || '—',
    objectId: l.objectId ?? null,
    documentId: l.documentId ?? null,
    accessSessionId: l.accessSessionId ?? null,
    outcome: l.outcome || 'SUCCESS',
    reasonCode: l.reasonCode ?? null,
    ipAddress: l.ipAddress || '—',
    userAgent: l.userAgent ?? null,
    correlationId: l.correlationId || '—',
    chainPartition: l.chainPartition || 'GLOBAL',
    chainSequence: l.chainSequence,
    previousHash: l.previousHash ?? null,
    entryHash: l.entryHash || undefined,
    hmacKeyVersion: l.hmacKeyVersion,
    chainAlgorithm: l.chainAlgorithm,
    details: l.details ?? null,
  }));
}

export function extractAuditorPagination(
  res: AuditLogsPaginatedResponse,
  fallbackPage = 1,
  fallbackPageSize = 20,
): AuditorPaginationInfo {
  const raw = res.pagination ?? res.meta;
  const count = Array.isArray(res.data) ? res.data.length : 0;
  const total = typeof raw?.total === 'number' ? raw.total : count;
  const pageSize =
    typeof raw?.pageSize === 'number' && raw.pageSize > 0 ? raw.pageSize : fallbackPageSize;
  const computedTotalPages = Math.max(1, Math.ceil(total / pageSize));
  const totalPages =
    typeof raw?.totalPages === 'number' && raw.totalPages > 0 ? raw.totalPages : computedTotalPages;
  const page = typeof raw?.page === 'number' && raw.page > 0 ? raw.page : fallbackPage;
  return { page, pageSize, total, totalPages };
}

/**
 * Thuật toán: Hợp Nhất Lịch Sử Xuất Báo Cáo Có Loại Bỏ Tác Vụ Đã Bị Thu Hồi/Xóa (`mergeExportJobHistory`)
 * Mục đích: Tin cậy danh sách trả về từ máy chủ làm nguồn chân lý, chỉ giữ tạm tác vụ vừa tạo cục bộ trong cửa sổ 15 giây (PENDING/PROCESSING) để chống nhấp nháy trước khi DB đồng bộ.
 */
export function mergeExportJobHistory(
  incoming: ExportJobItem[],
  previous: ExportJobItem[],
  nowMs = Date.now(),
): ExportJobItem[] {
  const incomingIds = new Set(incoming.map((job) => job.id));
  const recentLocalPending = previous.filter((job) => {
    if (incomingIds.has(job.id)) return false;
    if (job.status !== 'PENDING' && job.status !== 'PROCESSING') return false;
    const createdMs = Date.parse(job.createdAt);
    return (
      Number.isFinite(createdMs) &&
      nowMs - createdMs >= 0 &&
      nowMs - createdMs <= OPTIMISTIC_JOB_GRACE_MS
    );
  });
  return [...recentLocalPending, ...incoming];
}

/**
 * Thuật toán: Tổng Hợp Xác Minh Toàn Vẹn Chuỗi Băm Đơn Hoặc Đa Phân Vùng Kèm Số Thứ Tự Vi Phạm (`aggregatePartitionVerifications`)
 * Mục đích: Chuẩn hóa phản hồi từ `GET /audit-logs/verify` (cả một phân vùng lẫn toàn bộ phân vùng), giữ nguyên số thứ tự `#sequence` cho từng vị trí sai lệch và tổng hợp số điểm neo đã đối soát.
 */
export function aggregatePartitionVerifications(res: VerifyHashChainResponse): {
  report: ChainVerificationReport;
  partitionCount: number;
  violationCount: number;
} {
  const maybeSingle = res as Partial<PartitionVerificationResult>;
  const structured = res as {
    partitions?: PartitionVerificationResult[];
    tamperedCount?: number;
  };

  let partitions: PartitionVerificationResult[];
  if (typeof maybeSingle?.partition === 'string' && typeof maybeSingle?.valid === 'boolean') {
    partitions = [maybeSingle as PartitionVerificationResult];
  } else if (Array.isArray(structured?.partitions)) {
    partitions = structured.partitions;
  } else {
    partitions = Object.entries((res || {}) as Record<string, unknown>)
      .filter(([, val]) => Boolean(val && typeof val === 'object' && !Array.isArray(val)))
      .map(([key, val]) => {
        const item = val as PartitionVerificationResult;
        return {
          ...item,
          partition: item.partition || key,
        };
      });
  }

  const totalChecked = partitions.reduce((acc, p) => acc + (p.totalChecked || 0), 0);
  const totalAnchorsChecked = partitions.reduce((acc, p) => acc + (p.anchorsChecked || 0), 0);
  const resumedFromAnchors = partitions.some((p) => Boolean(p.resumedFromAnchorSequence));
  const allViolations = partitions.flatMap((p) =>
    (p.violations || []).map((v) =>
      formatAuditViolationMessage(v.partition || p.partition, v.code, v.sequence),
    ),
  );
  const tamperedCount =
    typeof structured?.tamperedCount === 'number' ? structured.tamperedCount : allViolations.length;
  const isAllValid =
    tamperedCount === 0 && (partitions.length === 0 || partitions.every((p) => p.valid !== false));
  const partitionLabel =
    partitions
      .map((p) => formatAuditPartitionLabel(p.partition))
      .filter(Boolean)
      .join(', ') || 'Toàn hệ thống';

  return {
    report: {
      isChainValid: isAllValid,
      totalEntriesChecked: totalChecked,
      totalAnchorsChecked,
      resumedFromAnchors,
      partitions,
      brokenSequences: allViolations,
      verifiedAt: new Date().toISOString(),
      chainPartition: partitionLabel,
    },
    partitionCount: partitions.length,
    violationCount: Math.max(tamperedCount, allViolations.length),
  };
}

/**
 * Thuật toán: Chuẩn Hóa Siêu Dữ Liệu Tác Vụ Xuất Báo Cáo (`normalizeExportJob`)
 */
export function normalizeExportJob(
  newJob: Partial<ExportJobItem> & { id: string },
  fallbackFormat: ExportFormat = 'CSV',
): ExportJobItem {
  const expiredByTimestamp = Boolean(
    newJob.expiresAt && new Date(newJob.expiresAt).getTime() <= Date.now(),
  );
  const isExpired = Boolean(newJob.isExpired) || newJob.status === 'EXPIRED' || expiredByTimestamp;

  return {
    id: newJob.id,
    exportType: newJob.exportType || 'AUDIT_LOGS',
    format: (newJob.format as ExportFormat) || fallbackFormat,
    status: newJob.status || 'PENDING',
    createdAt: newJob.createdAt || new Date().toISOString(),
    completedAt: newJob.completedAt ?? null,
    expiresAt: newJob.expiresAt ?? null,
    isExpired,
    rowCount: newJob.rowCount ?? null,
    fileSizeBytes:
      newJob.fileSizeBytes !== undefined && newJob.fileSizeBytes !== null
        ? String(newJob.fileSizeBytes)
        : null,
    sha256Hash: newJob.sha256Hash ?? null,
    errorMessage: newJob.errorMessage ?? null,
    mimeType: newJob.mimeType ?? null,
  };
}

/**
 * Thuật toán: Định Dạng Dung Lượng Tệp Thân Thiện Tiếng Việt (`formatByteSizeVi`)
 */
export function formatByteSizeVi(rawBytes: string | number | null | undefined): string {
  if (rawBytes === null || rawBytes === undefined || rawBytes === '') return '—';
  const bytes = Number(rawBytes);
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Thuật toán: Kích Hoạt Tải Tệp Nhị Phân Tạm Thời An Toàn Với Độ Trễ Thu Hồi URL (`triggerEphemeralBlobDownload`)
 * Mục đích: Ưu tiên tên tệp từ tiêu đề `Content-Disposition` của máy chủ và trì hoãn `URL.revokeObjectURL` 1 giây để không cắt ngang tải tệp trên Safari/Firefox.
 */
export function triggerEphemeralBlobDownload(blob: DownloadBlob, job: ExportJobItem): void {
  const ext = job.format.toLowerCase() === 'excel' ? 'xlsx' : job.format.toLowerCase();
  const fallbackName = `${job.exportType.toLowerCase()}_${job.id.slice(0, 8)}.${ext}`;
  const filename = blob.filename?.trim() || fallbackName;
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

/**
 * Thuật toán: Kết Xuất Biên Bản Xác Minh Toàn Vẹn Chuỗi Băm Sang Tệp JSON (`downloadVerificationReportJson`)
 */
export function downloadVerificationReportJson(report: ChainVerificationReport): void {
  const payload = JSON.stringify(
    {
      certificateType: 'AUDIT_HASH_CHAIN_VERIFICATION_REPORT',
      verifiedAt: report.verifiedAt,
      isChainValid: report.isChainValid,
      chainPartition: report.chainPartition,
      totalEntriesChecked: report.totalEntriesChecked,
      totalAnchorsChecked: report.totalAnchorsChecked,
      verificationScope: report.resumedFromAnchors
        ? 'CHECKPOINT_RESUMED_WITH_PRIOR_ANCHOR_AND_COUNT_CHECK'
        : 'FULL_GENESIS_SCAN',
      violations: report.brokenSequences,
      partitions: report.partitions,
    },
    null,
    2,
  );
  const blob = new Blob([payload], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const stamp = report.verifiedAt.replace(/[:.]/g, '-').slice(0, 19);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', `audit_integrity_report_${stamp}.json`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

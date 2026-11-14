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

/**
 * Thuật toán: Truy vấn Có Lọc, Phân Trang & Chuẩn hóa Lược đồ Pháp chứng Nhật ký Kiểm toán (`buildAuditLogsQueryParams`)
 * Mục đích: Đồng bộ danh sách sự kiện kiểm toán theo bộ lọc đa chiều (`outcome`, `action`, khoảng ngày), tham số phân trang (`page`, `pageSize`) và ánh xạ đầy đủ siêu dữ liệu chuỗi băm (`chainPartition`, `chainSequence`, `previousHash`, `entryHash`, `reasonCode`, `details`).
 */
export function buildAuditLogsQueryParams(
  filters: AuditTrailFilters,
  page = 1,
  pageSize = 20,
): URLSearchParams {
  const queryParams = new URLSearchParams();
  if (filters.outcomeFilter !== 'ALL') queryParams.set('outcome', filters.outcomeFilter);
  if (filters.actionFilter.trim()) queryParams.set('action', filters.actionFilter.trim());
  if (filters.fromDate) queryParams.set('from', filters.fromDate);
  if (filters.toDate) queryParams.set('to', filters.toDate);
  queryParams.set('page', String(Math.max(1, page)));
  queryParams.set('pageSize', String(pageSize));
  return queryParams;
}

export function normalizeAuditLogDtos(dtos: AuditLogApiDto[]): AuditLogItem[] {
  return dtos.map((l, i) => ({
    id: l.id || `log-${i}`,
    occurredAt: l.occurredAt || l.occurred_at || '',
    actorUserId: l.actorUserId ?? l.actor_user_id ?? null,
    actorUsername: l.actorUsername || l.actor_username || 'SYSTEM',
    action: l.action || '—',
    objectType: l.objectType || l.object_type || '—',
    objectId: l.objectId ?? l.object_id ?? null,
    documentId: l.documentId ?? l.document_id ?? null,
    accessSessionId: l.accessSessionId ?? l.access_session_id ?? null,
    outcome: l.outcome || 'SUCCESS',
    reasonCode: l.reasonCode ?? l.reason_code ?? null,
    ipAddress: l.ipAddress || l.ip_address || '—',
    userAgent: l.userAgent ?? l.user_agent ?? null,
    correlationId: l.correlationId || l.correlation_id || '—',
    chainPartition: l.chainPartition || l.chain_partition || 'GLOBAL',
    chainSequence: l.chainSequence ?? l.chain_sequence,
    previousHash: l.previousHash ?? l.previous_hash ?? null,
    entryHash: l.entryHash || l.entry_hash || undefined,
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
 * Thuật toán: Tổng hợp Xác minh Toàn vẹn Chuỗi Băm Đa phân vùng (`aggregatePartitionVerifications`)
 * Mục đích: Kiểm chứng không có bất kỳ bản ghi nhật ký nào bị sửa đổi, xóa bỏ hoặc chèn trái phép trên các phân vùng chuỗi kiểm toán thực tế.
 */
export function aggregatePartitionVerifications(res: VerifyHashChainResponse): {
  report: ChainVerificationReport;
  partitionCount: number;
  violationCount: number;
} {
  const structured = res as {
    partitions?: PartitionVerificationResult[];
    tamperedCount?: number;
  };

  const partitions: PartitionVerificationResult[] = Array.isArray(structured?.partitions)
    ? structured.partitions
    : Object.entries(res || {})
        .filter(([, val]) => Boolean(val && typeof val === 'object' && !Array.isArray(val)))
        .map(([key, val]) => {
          const item = val as PartitionVerificationResult;
          return {
            ...item,
            partition: item.partition || key,
          };
        });

  const totalChecked = partitions.reduce((acc, p) => acc + (p.totalChecked || 0), 0);
  const allViolations = partitions.flatMap((p) =>
    (p.violations || []).map((v) => `${p.partition || 'GLOBAL'}: ${v.message || v.code}`),
  );
  const tamperedCount =
    typeof structured?.tamperedCount === 'number' ? structured.tamperedCount : allViolations.length;
  const isAllValid =
    tamperedCount === 0 && (partitions.length === 0 || partitions.every((p) => p.valid !== false));
  const partitionLabel =
    partitions
      .map((p) => p.partition)
      .filter(Boolean)
      .join(', ') || 'GLOBAL';

  return {
    report: {
      isChainValid: isAllValid,
      totalEntriesChecked: totalChecked,
      tamperingDetected: !isAllValid,
      brokenSequences: allViolations,
      verifiedAt: new Date().toISOString(),
      chainPartition: partitionLabel,
    },
    partitionCount: partitions.length,
    violationCount: Math.max(tamperedCount, allViolations.length),
  };
}

/**
 * Thuật toán: Xuất Báo cáo Bất đồng bộ Chống Formula Injection & Tải Luồng Nhị phân (`normalizeExportJob`)
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
  };
}

export function triggerEphemeralBlobDownload(blob: Blob, job: ExportJobItem): void {
  const ext = job.format.toLowerCase() === 'excel' ? 'xlsx' : job.format.toLowerCase();
  const filename = `audit_export_${job.id.slice(0, 8)}.${ext}`;
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

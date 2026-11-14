import type {
  AuditLogApiDto,
  AuditLogItem,
  AuditTrailFilters,
  ChainVerificationReport,
  ExportFormat,
  ExportJobItem,
  PartitionVerificationResult,
  VerifyHashChainResponse,
} from './types';

/**
 * Thuật toán: Truy vấn Có Lọc & Chuẩn hóa Lược đồ Nhật ký Kiểm toán (`buildAuditLogsQueryParams`)
 * Mục đích: Đồng bộ danh sách sự kiện kiểm toán theo bộ lọc đa chiều (`outcome`, `action`, khoảng ngày) và ánh xạ thống nhất giữa định dạng `camelCase` và `snake_case`.
 */
export function buildAuditLogsQueryParams(filters: AuditTrailFilters): URLSearchParams {
  const queryParams = new URLSearchParams();
  if (filters.outcomeFilter !== 'ALL') queryParams.set('outcome', filters.outcomeFilter);
  if (filters.actionFilter.trim()) queryParams.set('action', filters.actionFilter.trim());
  if (filters.fromDate) queryParams.set('from', filters.fromDate);
  if (filters.toDate) queryParams.set('to', filters.toDate);
  queryParams.set('pageSize', '50');
  return queryParams;
}

export function normalizeAuditLogDtos(dtos: AuditLogApiDto[]): AuditLogItem[] {
  return dtos.map((l, i) => ({
    id: l.id || `log-${i}`,
    occurredAt: l.occurredAt || l.occurred_at || '',
    actorUsername: l.actorUsername || l.actor_username || 'SYSTEM',
    action: l.action || '—',
    objectType: l.objectType || l.object_type || '—',
    objectId: l.objectId || l.object_id,
    outcome: l.outcome || 'SUCCESS',
    ipAddress: l.ipAddress || l.ip_address || '—',
    correlationId: l.correlationId || l.correlation_id || '—',
    chainSequence: l.chainSequence ?? l.chain_sequence,
    entryHash: l.entryHash || l.entry_hash || undefined,
  }));
}

/**
 * Thuật toán: Tổng hợp Xác minh Toàn vẹn Chuỗi Băm Đa phân vùng (`aggregatePartitionVerifications`)
 * Mục đích: Kiểm chứng không có bất kỳ bản ghi nhật ký nào bị sửa đổi, xóa bỏ hoặc chèn trái phép trên các phân vùng chuỗi kiểm toán thực tế.
 * Cơ chế hoạt động:
 *   - Trích xuất danh sách phân vùng thực từ phản hồi `/audit-logs/verify` (mặc định nhãn `GLOBAL` thay vì hằng số giả `GLOBAL_CHAIN`).
 *   - Khi `partitions.length === 0` và `tamperedCount === 0`, đánh giá `isChainValid: true` (`CHƯA CÓ BẢN GHI / HỢP LỆ`) thay vì phát cảnh báo giả mạo sai lệch.
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
 * Mục đích: Chuẩn hóa trạng thái tác vụ xuất (`CSV`, `JSON`, `PDF`, `EXCEL`) với TTL 24 giờ và tải tệp `Blob` qua Object URL tự thu hồi.
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

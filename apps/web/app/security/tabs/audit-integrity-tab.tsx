'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  Anchor,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  formatAuditActionLabel,
  formatAuditObjectTypeLabel,
  formatAuditOutcomeLabel,
  formatAuditPartitionLabel,
  formatAuditViolationMessage,
  formatSafeDateVi,
} from '@/lib/ui-labels';

interface AuditAnchorRow {
  id: string;
  chainPartition: string;
  anchorSequence: string;
  entryHash: string;
  signature: string;
  signerKeyId?: string | undefined;
  status?: string | undefined;
  anchoredAt: string;
}

interface AuditVerificationEntry {
  partition: string;
  valid: boolean;
  totalChecked: number;
  anchorsChecked: number;
  violations: Array<{ code: string; partition: string; sequence: string; message: string }>;
}

interface AuditLogRow {
  id: string;
  chainPartition?: string;
  action: string;
  actorUsername?: string | null;
  objectType?: string | null;
  outcome: string;
  ipAddress?: string | null;
  occurredAt: string;
}

interface AuditIntegrityTabProps {
  canCreateAnchor: boolean;
  onMessage: (message: string) => void;
  onError: (errorMessage: string) => void;
}

const AUDIT_PARTITIONS = [
  'AUTH',
  'ACCESS_SESSION',
  'DOCUMENT',
  'RBAC',
  'SECURITY',
  'SECURITY_OPERATIONS',
  'GLOBAL',
] as const;

/**
 * Thuật toán: Kiểm Chứng Chuỗi Băm Kiểm Toán, Khởi Tạo Điểm Neo Chữ Ký HMAC (UC32) & Tra Cứu Nhật Ký SOC (`AuditIntegrityTab`)
 * Mục đích: Đưa đầy đủ tính năng `AUDIT_ANCHOR:CREATE` (#04) và `AUDIT_LOG:VIEW`/`VERIFY` (#28) vào cổng `/security` mà vẫn tuân thủ Phân tách nhiệm vụ SoD.
 */
export function AuditIntegrityTab({ canCreateAnchor, onMessage, onError }: AuditIntegrityTabProps) {
  const [selectedPartition, setSelectedPartition] = useState<string>('AUTH');
  const [anchors, setAnchors] = useState<AuditAnchorRow[]>([]);
  const [logs, setLogs] = useState<AuditLogRow[]>([]);
  const [logsPage, setLogsPage] = useState(1);
  const [logsTotalPages, setLogsTotalPages] = useState(1);
  const [logsTotal, setLogsTotal] = useState(0);
  const [verifyReport, setVerifyReport] = useState<AuditVerificationEntry[] | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isCreatingAnchor, setIsCreatingAnchor] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  const loadAuditData = useCallback(async () => {
    setIsLoading(true);
    setLocalError(null);
    const [anchorsRes, logsRes] = await Promise.allSettled([
      apiClient<{ data: AuditAnchorRow[] }>('/audit-logs/anchors'),
      apiClient<{
        data: AuditLogRow[];
        pagination?: { page: number; totalPages: number; total: number };
      }>(`/audit-logs?page=${logsPage}&pageSize=15`),
    ]);

    if (anchorsRes.status === 'fulfilled') {
      setAnchors(anchorsRes.value.data || []);
    } else {
      setLocalError(
        anchorsRes.reason instanceof ApiError
          ? anchorsRes.reason.message
          : 'Không thể tải danh sách điểm neo kiểm toán.',
      );
    }

    if (logsRes.status === 'fulfilled') {
      setLogs(logsRes.value.data || []);
      setLogsTotal(logsRes.value.pagination?.total ?? logsRes.value.data?.length ?? 0);
      setLogsTotalPages(Math.max(1, logsRes.value.pagination?.totalPages ?? 1));
    } else {
      setLocalError(
        logsRes.reason instanceof ApiError
          ? logsRes.reason.message
          : 'Không thể tải danh sách nhật ký kiểm toán.',
      );
    }
    setIsLoading(false);
  }, [logsPage]);

  useEffect(() => {
    let ignore = false;
    void Promise.resolve().then(() => {
      if (!ignore) void loadAuditData();
    });
    return () => {
      ignore = true;
    };
  }, [loadAuditData]);

  async function handleCreateAnchor() {
    setIsCreatingAnchor(true);
    setLocalError(null);
    try {
      const created = await apiClient<AuditAnchorRow>('/audit-logs/anchors', {
        method: 'POST',
        body: JSON.stringify({ chainPartition: selectedPartition }),
      });
      onMessage(
        `Đã khởi tạo điểm neo kiểm toán HMAC cho phân vùng ${created.chainPartition} tại bản ghi #${created.anchorSequence}.`,
      );
      await loadAuditData();
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? err.message || 'Không thể khởi tạo điểm neo kiểm toán.'
          : 'Không thể khởi tạo điểm neo kiểm toán.';
      setLocalError(msg);
      onError(msg);
    } finally {
      setIsCreatingAnchor(false);
    }
  }

  async function handleVerifyChain() {
    setIsVerifying(true);
    setLocalError(null);
    try {
      const res = await apiClient<AuditVerificationEntry | Record<string, AuditVerificationEntry>>(
        '/audit-logs/verify',
      );
      const entries =
        'partition' in res && typeof res.partition === 'string'
          ? [res as AuditVerificationEntry]
          : Object.values(res as Record<string, AuditVerificationEntry>);
      setVerifyReport(entries);
      const brokenCount = entries.filter((e) => !e.valid).length;
      if (brokenCount === 0) {
        onMessage(
          `Đã xác minh toàn vẹn ${entries.length} phân vùng chuỗi kiểm toán — không phát hiện sai lệch.`,
        );
      } else {
        onError(
          `Phát hiện ${brokenCount} phân vùng có dấu hiệu bất thường toàn vẹn chuỗi kiểm toán!`,
        );
      }
    } catch (err) {
      const msg =
        err instanceof ApiError ? err.message : 'Không thể kiểm tra toàn vẹn chuỗi kiểm toán.';
      setLocalError(msg);
      onError(msg);
    } finally {
      setIsVerifying(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3 space-y-3">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
            <CardTitle className="text-sm sm:text-base text-[#222222] flex items-center gap-2">
              <Anchor size={16} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
              <span>Toàn vẹn chuỗi băm &amp; Điểm neo kiểm toán ({anchors.length})</span>
            </CardTitle>

            <div className="flex flex-wrap items-center gap-2">
              {canCreateAnchor && (
                <>
                  <label htmlFor="soc-anchor-partition" className="sr-only">
                    Chọn phân vùng chuỗi kiểm toán
                  </label>
                  <select
                    id="soc-anchor-partition"
                    value={selectedPartition}
                    onChange={(e) => setSelectedPartition(e.target.value)}
                    className="min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs text-[#222222] cursor-pointer"
                  >
                    {AUDIT_PARTITIONS.map((p) => (
                      <option key={p} value={p}>
                        Phân vùng: {formatAuditPartitionLabel(p)}
                      </option>
                    ))}
                  </select>
                  <InteractiveHoverButton
                    type="button"
                    size="sm"
                    variant="primary"
                    text="Tạo điểm neo HMAC"
                    icon={<Anchor size={16} strokeWidth={1.75} aria-hidden="true" />}
                    isLoading={isCreatingAnchor}
                    disabled={isCreatingAnchor}
                    onClick={() => void handleCreateAnchor()}
                  />
                </>
              )}

              <InteractiveHoverButton
                type="button"
                size="sm"
                variant="secondary"
                text="Kiểm chứng toàn chuỗi"
                icon={<ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
                isLoading={isVerifying}
                disabled={isVerifying}
                onClick={() => void handleVerifyChain()}
              />
            </div>
          </div>

          {localError && (
            <Alert variant="destructive" className="text-xs">
              <AlertTriangle
                size={16}
                strokeWidth={1.75}
                className="shrink-0 text-[#C13515]"
                aria-hidden="true"
              />
              <AlertDescription className="ml-2">{localError}</AlertDescription>
            </Alert>
          )}
        </CardHeader>

        <CardContent className="space-y-4">
          {verifyReport && (
            <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-2 text-xs">
              <div className="font-semibold text-[#222222] flex items-center gap-1.5">
                <CheckCircle2
                  size={16}
                  strokeWidth={1.75}
                  className="text-[#008A05]"
                  aria-hidden="true"
                />
                <span>
                  Kết quả xác minh mật mã chuỗi kiểm toán ({verifyReport.length} phân vùng)
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {verifyReport.map((entry) => (
                  <div
                    key={entry.partition}
                    className="rounded-[12px] border border-[#ebebeb] bg-[#ffffff] p-2.5 space-y-1"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono font-semibold text-[#222222]">
                        {formatAuditPartitionLabel(entry.partition)}
                      </span>
                      <Badge variant={entry.valid ? 'success' : 'destructive'}>
                        {entry.valid ? 'Toàn vẹn' : `${entry.violations.length} lỗi`}
                      </Badge>
                    </div>
                    <div className="text-[#717171]">
                      Đã kiểm tra: {entry.totalChecked} bản ghi · {entry.anchorsChecked} điểm neo
                    </div>
                    {entry.violations.slice(0, 2).map((v, idx) => (
                      <div key={idx} className="text-[#C13515]">
                        {formatAuditViolationMessage(v.partition, v.code, v.sequence)}
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="rounded-[16px] border border-[#ebebeb] overflow-hidden">
            <Table>
              <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                <TableRow>
                  <TableHead className="text-xs text-[#717171]">Phân vùng</TableHead>
                  <TableHead className="text-xs text-[#717171]">Số thứ tự neo</TableHead>
                  <TableHead className="text-xs text-[#717171]">Mã băm bản ghi</TableHead>
                  <TableHead className="text-xs text-[#717171]">Khóa ký</TableHead>
                  <TableHead className="text-xs text-[#717171]">Thời điểm neo</TableHead>
                  <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {anchors.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-6 text-xs text-[#717171]">
                      Chưa có điểm neo chữ ký nào. Chọn phân vùng và bấm &quot;Tạo điểm neo
                      HMAC&quot; để đóng dấu toàn vẹn.
                    </TableCell>
                  </TableRow>
                ) : (
                  anchors.map((a) => (
                    <TableRow key={a.id} className="border-b border-[#ebebeb]">
                      <TableCell className="font-mono font-semibold text-xs text-[#222222]">
                        {formatAuditPartitionLabel(a.chainPartition)}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-[#222222]">
                        #{a.anchorSequence}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-[#717171]">
                        {a.entryHash.slice(0, 16)}…
                      </TableCell>
                      <TableCell className="font-mono text-xs text-[#717171]">
                        {a.signerKeyId || 'v1'}
                      </TableCell>
                      <TableCell className="text-xs text-[#717171] whitespace-nowrap">
                        {formatSafeDateVi(a.anchoredAt, { includeTime: true })}
                      </TableCell>
                      <TableCell>
                        <Badge variant={a.status === 'INVALID' ? 'destructive' : 'success'}>
                          {a.status === 'INVALID' ? 'Sai lệch' : 'Hợp lệ'}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3 flex flex-row items-center justify-between gap-2">
          <CardTitle className="text-sm sm:text-base text-[#222222]">
            Nhật ký kiểm toán toàn hệ thống ({logsTotal})
          </CardTitle>
          <InteractiveHoverButton
            type="button"
            size="sm"
            variant="secondary"
            text="Tải lại"
            icon={
              <RefreshCw
                size={16}
                strokeWidth={1.75}
                className={isLoading ? 'animate-spin' : ''}
                aria-hidden="true"
              />
            }
            disabled={isLoading}
            onClick={() => void loadAuditData()}
          />
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Thời gian</TableHead>
                <TableHead className="text-xs text-[#717171]">Tác nhân</TableHead>
                <TableHead className="text-xs text-[#717171]">Hành động</TableHead>
                <TableHead className="text-xs text-[#717171]">Đối tượng</TableHead>
                <TableHead className="text-xs text-[#717171]">Địa chỉ IP</TableHead>
                <TableHead className="text-xs text-[#717171]">Kết quả</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {logs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-6 text-xs text-[#717171]">
                    {isLoading
                      ? 'Đang tải nhật ký kiểm toán…'
                      : 'Chưa có bản ghi nhật ký kiểm toán.'}
                  </TableCell>
                </TableRow>
              ) : (
                logs.map((log) => (
                  <TableRow key={log.id} className="border-b border-[#ebebeb]">
                    <TableCell className="text-xs text-[#717171] whitespace-nowrap">
                      {formatSafeDateVi(log.occurredAt, { includeTime: true })}
                    </TableCell>
                    <TableCell className="text-xs font-medium text-[#222222]">
                      {log.actorUsername || 'Hệ thống'}
                    </TableCell>
                    <TableCell className="text-xs text-[#222222]">
                      {formatAuditActionLabel(log.action)}
                    </TableCell>
                    <TableCell className="text-xs text-[#717171]">
                      {formatAuditObjectTypeLabel(log.objectType)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-[#717171]">
                      {log.ipAddress || '—'}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          log.outcome === 'SUCCESS'
                            ? 'success'
                            : log.outcome === 'DENIED'
                              ? 'destructive'
                              : 'warning'
                        }
                      >
                        {formatAuditOutcomeLabel(log.outcome)}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>

          {logsTotalPages > 1 && (
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#ebebeb] px-4 py-3 text-xs text-[#717171]">
              <span>
                Trang {logsPage} / {logsTotalPages}
              </span>
              <div className="flex items-center gap-2">
                <InteractiveHoverButton
                  type="button"
                  size="sm"
                  variant="secondary"
                  text="Trang trước"
                  icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
                  disabled={logsPage <= 1}
                  onClick={() => setLogsPage((p) => Math.max(1, p - 1))}
                />
                <InteractiveHoverButton
                  type="button"
                  size="sm"
                  variant="secondary"
                  text="Trang sau"
                  icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
                  disabled={logsPage >= logsTotalPages}
                  onClick={() => setLogsPage((p) => Math.min(logsTotalPages, p + 1))}
                />
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

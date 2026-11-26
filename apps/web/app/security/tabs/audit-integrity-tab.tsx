'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { AlertTriangle, Anchor, CheckCircle2, RefreshCw, ShieldCheck } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Select } from '@/components/ui/select';
import { formatAuditPartitionLabel, formatAuditViolationMessage } from '@/lib/ui-labels';
import { AUDIT_PARTITIONS } from '../helpers';
import {
  AuditAnchorsSection,
  AuditSystemLogsSection,
  type AuditAnchorRow,
  type AuditLogRow,
} from './audit-integrity-tables';

interface AuditVerificationEntry {
  partition: string;
  valid: boolean;
  totalChecked: number;
  anchorsChecked: number;
  violations: Array<{ code: string; partition: string; sequence: string; message: string }>;
}

interface AuditIntegrityTabProps {
  canCreateAnchor: boolean;
  refreshSignal?: number | undefined;
  onMessage: (message: string) => void;
  onError: (errorMessage: string) => void;
}

/**
 * Thuật toán: Kiểm Chứng Chuỗi Băm Kiểm Toán, Khởi Tạo Điểm Neo Chữ Ký HMAC (UC32) & Tra Cứu Nhật Ký SOC (`AuditIntegrityTab`)
 * Mục đích:
 *   - Dùng chung `AUDIT_PARTITIONS` có đủ `'AUDIT'`, giữ `<Select>` `w-full` trên di động `375px`.
 *   - Hiển thị biểu tượng `<AlertTriangle>` chữ `#C13515` phẳng theo mẫu `staff-001` khi phát hiện sai lệch, đếm số vi phạm ẩn `+(violations.length - 2)` và nạp lại nhật ký im lặng (`{ silent: true }`) sau khi xác minh chuỗi.
 */
export function AuditIntegrityTab({
  canCreateAnchor,
  refreshSignal = 0,
  onMessage,
  onError,
}: AuditIntegrityTabProps) {
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

  const anchorsAbortRef = useRef<AbortController | null>(null);
  const logsAbortRef = useRef<AbortController | null>(null);

  const loadAnchors = useCallback(async (options?: { silent?: boolean }) => {
    anchorsAbortRef.current?.abort();
    const ctrl = new AbortController();
    anchorsAbortRef.current = ctrl;
    try {
      const res = await apiClient<{ data: AuditAnchorRow[] }>('/audit-logs/anchors', {
        signal: ctrl.signal,
      });
      if (ctrl.signal.aborted) return;
      setAnchors(res.data || []);
    } catch (err) {
      if (ctrl.signal.aborted) return;
      if (!options?.silent) {
        setLocalError(
          err instanceof ApiError ? err.message : 'Không thể tải danh sách điểm neo kiểm toán.',
        );
      }
    }
  }, []);

  const loadLogs = useCallback(
    async (options?: { silent?: boolean }) => {
      logsAbortRef.current?.abort();
      const ctrl = new AbortController();
      logsAbortRef.current = ctrl;
      if (!options?.silent) {
        setIsLoading(true);
        setLocalError(null);
      }
      try {
        const res = await apiClient<{
          data: AuditLogRow[];
          pagination?: { page: number; totalPages: number; total: number };
        }>(`/audit-logs?page=${logsPage}&pageSize=15`, { signal: ctrl.signal });
        if (ctrl.signal.aborted) return;
        setLogs(res.data || []);
        setLogsTotal(res.pagination?.total ?? res.data?.length ?? 0);
        setLogsTotalPages(Math.max(1, res.pagination?.totalPages ?? 1));
      } catch (err) {
        if (ctrl.signal.aborted) return;
        if (!options?.silent) {
          setLocalError(
            err instanceof ApiError ? err.message : 'Không thể tải danh sách nhật ký kiểm toán.',
          );
        }
      } finally {
        if (!ctrl.signal.aborted && !options?.silent) {
          setIsLoading(false);
        }
      }
    },
    [logsPage],
  );

  const loadAuditData = useCallback(
    async (options?: { silent?: boolean }) => {
      await Promise.allSettled([loadAnchors(options), loadLogs(options)]);
    },
    [loadAnchors, loadLogs],
  );

  useEffect(() => {
    let ignore = false;
    void Promise.resolve().then(() => {
      if (!ignore) void loadAnchors();
    });
    return () => {
      ignore = true;
      anchorsAbortRef.current?.abort();
    };
  }, [loadAnchors]);

  useEffect(() => {
    let ignore = false;
    void Promise.resolve().then(() => {
      if (!ignore) void loadLogs();
    });
    return () => {
      ignore = true;
      logsAbortRef.current?.abort();
    };
  }, [loadLogs]);

  const prevRefreshSignalRef = useRef(refreshSignal);
  useEffect(() => {
    if (prevRefreshSignalRef.current !== refreshSignal) {
      prevRefreshSignalRef.current = refreshSignal;
      void loadAuditData();
    }
  }, [refreshSignal, loadAuditData]);

  async function handleCreateAnchor() {
    setIsCreatingAnchor(true);
    setLocalError(null);
    try {
      const created = await apiClient<AuditAnchorRow>('/audit-logs/anchors', {
        method: 'POST',
        body: JSON.stringify({ chainPartition: selectedPartition }),
      });
      onMessage(
        `Đã khởi tạo điểm neo kiểm toán HMAC cho phân vùng ${formatAuditPartitionLabel(created.chainPartition)} tại bản ghi #${created.anchorSequence}.`,
      );
      await loadAuditData({ silent: true });
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? err.message || 'Không thể khởi tạo điểm neo kiểm toán.'
          : 'Không thể khởi tạo điểm neo kiểm toán.';
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
      await loadAuditData({ silent: true });
    } catch (err) {
      const msg =
        err instanceof ApiError ? err.message : 'Không thể kiểm tra toàn vẹn chuỗi kiểm toán.';
      onError(msg);
    } finally {
      setIsVerifying(false);
    }
  }

  const hasBrokenPartitions = Boolean(verifyReport && verifyReport.some((e) => !e.valid));

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3 space-y-3">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
            <CardTitle className="text-sm sm:text-base text-[#222222] flex items-center gap-2">
              <Anchor size={16} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
              <span>Toàn vẹn chuỗi băm &amp; Điểm neo kiểm toán ({anchors.length})</span>
            </CardTitle>

            <div className="flex flex-col sm:flex-row sm:flex-wrap items-stretch sm:items-center gap-2 w-full lg:w-auto">
              {canCreateAnchor && (
                <>
                  <label htmlFor="soc-anchor-partition" className="sr-only">
                    Chọn phân vùng chuỗi kiểm toán
                  </label>
                  <Select
                    id="soc-anchor-partition"
                    value={selectedPartition}
                    onChange={(e) => setSelectedPartition(e.target.value)}
                    wrapperClassName="w-full sm:w-60"
                  >
                    {AUDIT_PARTITIONS.map((p) => (
                      <option key={p} value={p}>
                        Phân vùng: {formatAuditPartitionLabel(p)}
                      </option>
                    ))}
                  </Select>
                  <InteractiveHoverButton
                    type="button"
                    size="sm"
                    variant="primary"
                    text="Tạo điểm neo HMAC"
                    icon={<Anchor size={16} strokeWidth={1.75} aria-hidden="true" />}
                    isLoading={isCreatingAnchor}
                    disabled={isCreatingAnchor}
                    onClick={() => handleCreateAnchor()}
                    className="w-full sm:w-auto"
                  />
                </>
              )}

              <InteractiveHoverButton
                type="button"
                size="sm"
                variant="secondary"
                text="Kiểm chứng chuỗi"
                icon={<ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
                isLoading={isVerifying}
                disabled={isVerifying}
                onClick={() => handleVerifyChain()}
                className="w-full sm:w-auto"
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
            <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-2.5 text-xs">
              <div
                className={`font-semibold flex items-center gap-1.5 ${
                  hasBrokenPartitions ? 'text-[#C13515]' : 'text-[#222222]'
                }`}
              >
                {hasBrokenPartitions ? (
                  <AlertTriangle
                    size={16}
                    strokeWidth={1.75}
                    className="text-[#C13515] shrink-0"
                    aria-hidden="true"
                  />
                ) : (
                  <CheckCircle2
                    size={16}
                    strokeWidth={1.75}
                    className="text-[#008A05] shrink-0"
                    aria-hidden="true"
                  />
                )}
                <span>
                  {hasBrokenPartitions
                    ? `Phát hiện sai lệch mật mã chuỗi kiểm toán (${verifyReport.length} phân vùng đã kiểm tra)`
                    : `Kết quả xác minh mật mã chuỗi kiểm toán (${verifyReport.length} phân vùng toàn vẹn)`}
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {verifyReport.map((entry) => {
                  const hiddenViolationsCount = Math.max(0, entry.violations.length - 2);
                  return (
                    <div
                      key={entry.partition}
                      className="rounded-[12px] border border-[#ebebeb] bg-[#ffffff] p-2.5 space-y-1"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-[#222222]">
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
                        <div key={idx} className="text-[#C13515] break-words">
                          {formatAuditViolationMessage(v.partition, v.code, v.sequence)}
                        </div>
                      ))}
                      {hiddenViolationsCount > 0 && (
                        <div className="font-semibold text-[#C13515]">
                          +{hiddenViolationsCount} vi phạm khác chưa hiển thị
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <AuditAnchorsSection anchors={anchors} />
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
            onClick={() => loadAuditData()}
          />
        </CardHeader>
        <CardContent className="p-0">
          <AuditSystemLogsSection
            logs={logs}
            isLoading={isLoading}
            logsPage={logsPage}
            logsTotalPages={logsTotalPages}
            onPageChange={setLogsPage}
          />
        </CardContent>
      </Card>
    </div>
  );
}

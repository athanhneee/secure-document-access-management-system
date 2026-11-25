'use client';

import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, ChevronLeft, ChevronRight, RotateCcw, Search } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
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
  formatAlertSeverityLabel,
  formatAlertStatusLabel,
  formatDetectionRuleLabel,
  formatSafeDateVi,
} from '@/lib/ui-labels';
import { mapAuditorAlertDto } from '../forensics-helpers';
import { isAbortError } from '../hooks/use-export-polling';
import type { AuditorAlertItem, AuditorAlertPaginatedResponse } from '../types';

interface AuditorAlertsTabProps {
  onSelectAlert: (alert: AuditorAlertItem) => void;
}

const PAGE_SIZE = 20;

/**
 * Thuật toán: Hàng Đợi Cảnh Báo An Ninh Chế Độ Chỉ Đọc Cho Kiểm Toán Viên (`AuditorAlertsTab`, UC36)
 * Mục đích: Mở quyền tra cứu `SECURITY_ALERT:VIEW` đã cấp cho `AUDITOR` trên giao diện tối ưu Mobile 375px + Desktop mà tuyệt đối không cho phép thay đổi trạng thái cảnh báo.
 */
export function AuditorAlertsTab({ onSelectAlert }: AuditorAlertsTabProps) {
  const [alerts, setAlerts] = useState<AuditorAlertItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [localError, setLocalError] = useState<string | null>(null);

  const loadAlerts = useCallback(
    async (signal?: AbortSignal) => {
      const params = new URLSearchParams({ page: String(page), pageSize: String(PAGE_SIZE) });
      if (severityFilter !== 'ALL') params.set('severity', severityFilter);
      if (statusFilter !== 'ALL') params.set('status', statusFilter);
      if (searchQuery.trim()) params.set('search', searchQuery.trim());

      const res = await apiClient<AuditorAlertPaginatedResponse>(
        `/security-alerts?${params.toString()}`,
        signal ? { signal } : undefined,
      );
      const list = Array.isArray(res?.data) ? res.data.map(mapAuditorAlertDto) : [];
      const resolvedTotal = res?.meta?.total ?? res?.total ?? list.length;
      return { list, resolvedTotal };
    },
    [page, searchQuery, severityFilter, statusFilter],
  );

  useEffect(() => {
    let ignore = false;
    const controller = new AbortController();
    const timer = setTimeout(
      () => {
        void (async () => {
          setIsLoading(true);
          setLocalError(null);
          try {
            const { list, resolvedTotal } = await loadAlerts(controller.signal);
            if (ignore) return;
            setAlerts(list);
            setTotal(resolvedTotal);
          } catch (err) {
            if (ignore || isAbortError(err, controller.signal)) return;
            setLocalError(
              err instanceof ApiError ? err.message : 'Không thể tải danh sách cảnh báo an ninh.',
            );
          } finally {
            if (!ignore && !controller.signal.aborted) setIsLoading(false);
          }
        })();
      },
      searchQuery.trim() ? 250 : 0,
    );

    return () => {
      ignore = true;
      clearTimeout(timer);
      controller.abort();
    };
  }, [loadAlerts, searchQuery]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const hasFilters =
    severityFilter !== 'ALL' || statusFilter !== 'ALL' || searchQuery.trim() !== '';

  function resetFilters() {
    setSeverityFilter('ALL');
    setStatusFilter('ALL');
    setSearchQuery('');
    setPage(1);
  }

  return (
    <Card>
      <CardHeader className="pb-3 space-y-3">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          <CardTitle className="text-sm sm:text-base text-[#222222]">
            Cảnh báo an ninh (Chỉ đọc · {total})
          </CardTitle>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 w-full lg:w-auto min-w-0">
            <div>
              <label htmlFor="auditor-alert-search" className="sr-only">
                Tìm kiếm cảnh báo an ninh
              </label>
              <Input
                id="auditor-alert-search"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setPage(1);
                }}
                placeholder="Tìm tiêu đề, người dùng…"
                className="min-h-11 sm:h-9 w-full rounded-full border-[#dddddd] bg-[#ffffff] text-xs placeholder:text-[#717171]"
              />
            </div>

            <div>
              <label htmlFor="auditor-alert-severity" className="sr-only">
                Lọc theo mức độ nghiêm trọng
              </label>
              <select
                id="auditor-alert-severity"
                value={severityFilter}
                onChange={(e) => {
                  setSeverityFilter(e.target.value);
                  setPage(1);
                }}
                className="min-h-11 sm:h-9 w-full rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
              >
                <option value="ALL">Mọi mức độ</option>
                <option value="CRITICAL">Nghiêm trọng</option>
                <option value="HIGH">Cao</option>
                <option value="MEDIUM">Trung bình</option>
                <option value="LOW">Thấp</option>
              </select>
            </div>

            <div>
              <label htmlFor="auditor-alert-status" className="sr-only">
                Lọc theo trạng thái cảnh báo
              </label>
              <select
                id="auditor-alert-status"
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value);
                  setPage(1);
                }}
                className="min-h-11 sm:h-9 w-full rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
              >
                <option value="ALL">Mọi trạng thái</option>
                <option value="OPEN">Chờ xử lý</option>
                <option value="INVESTIGATING">Đang điều tra</option>
                <option value="RESOLVED">Đã xử lý</option>
                <option value="FALSE_POSITIVE">Báo động giả</option>
              </select>
            </div>
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

      <CardContent className="p-0">
        {isLoading && alerts.length === 0 ? (
          <div className="p-4 space-y-2.5" aria-busy="true">
            {[0, 1, 2, 3].map((idx) => (
              <div
                key={idx}
                className="h-12 w-full rounded-[14px] bg-[#f7f7f7] border border-[#ebebeb] animate-pulse"
              />
            ))}
          </div>
        ) : (
          <>
            <div className="md:hidden divide-y divide-[#ebebeb]">
              {alerts.length === 0 ? (
                <div className="px-4 py-8 text-center text-xs text-[#717171] space-y-2.5">
                  <p>Không có cảnh báo an ninh nào khớp với bộ lọc hiện tại.</p>
                  {hasFilters && (
                    <InteractiveHoverButton
                      type="button"
                      size="sm"
                      variant="secondary"
                      text="Xóa bộ lọc"
                      icon={<RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />}
                      onClick={resetFilters}
                    />
                  )}
                </div>
              ) : (
                alerts.map((alert) => (
                  <article key={alert.id} className="p-3.5 space-y-2 text-xs">
                    <div className="flex items-start justify-between gap-2">
                      <Badge
                        variant={
                          alert.severity === 'CRITICAL'
                            ? 'destructive'
                            : alert.severity === 'HIGH'
                              ? 'warning'
                              : 'info'
                        }
                      >
                        {formatAlertSeverityLabel(alert.severity)}
                      </Badge>
                      <Badge
                        variant={
                          alert.status === 'OPEN'
                            ? 'destructive'
                            : alert.status === 'INVESTIGATING' || alert.status === 'ESCALATED'
                              ? 'warning'
                              : 'success'
                        }
                      >
                        {formatAlertStatusLabel(alert.status)}
                      </Badge>
                    </div>
                    <div className="font-semibold text-[#222222] break-words">{alert.title}</div>
                    <div className="text-[#717171]">
                      {formatDetectionRuleLabel(alert.ruleCode)} ·{' '}
                      {alert.detectedUserName || 'Chưa định danh'} · {alert.ipAddress}
                    </div>
                    <div className="text-[#717171] tabular-nums">
                      {formatSafeDateVi(alert.detectedAt, { includeTime: true })}
                    </div>
                    <InteractiveHoverButton
                      size="sm"
                      variant="secondary"
                      text="Xem bằng chứng"
                      icon={<Search size={16} strokeWidth={1.75} aria-hidden="true" />}
                      onClick={() => onSelectAlert(alert)}
                      className="w-full"
                    />
                  </article>
                ))
              )}
            </div>

            <div className="hidden md:block">
              <Table>
                <caption className="sr-only">
                  Danh sách cảnh báo an ninh ở chế độ chỉ đọc cho kiểm toán viên
                </caption>
                <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                  <TableRow>
                    <TableHead className="text-xs text-[#717171]">Mức độ</TableHead>
                    <TableHead className="text-xs text-[#717171]">Loại / Tiêu đề</TableHead>
                    <TableHead className="text-xs text-[#717171]">Đối tượng</TableHead>
                    <TableHead className="text-xs text-[#717171]">Địa chỉ IP</TableHead>
                    <TableHead className="text-xs text-[#717171]">Thời điểm</TableHead>
                    <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                    <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {alerts.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="py-8 text-center text-xs text-[#717171]">
                        Không có cảnh báo an ninh nào khớp với bộ lọc hiện tại.
                      </TableCell>
                    </TableRow>
                  ) : (
                    alerts.map((alert) => (
                      <TableRow
                        key={alert.id}
                        className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                      >
                        <TableCell>
                          <Badge
                            variant={
                              alert.severity === 'CRITICAL'
                                ? 'destructive'
                                : alert.severity === 'HIGH'
                                  ? 'warning'
                                  : 'info'
                            }
                          >
                            {formatAlertSeverityLabel(alert.severity)}
                          </Badge>
                        </TableCell>
                        <TableCell className="max-w-xs">
                          <div className="font-semibold text-xs text-[#222222] break-words">
                            {alert.title}
                          </div>
                          <div className="text-[11px] text-[#717171]">
                            {formatDetectionRuleLabel(alert.ruleCode)}
                          </div>
                        </TableCell>
                        <TableCell className="text-xs text-[#222222]">
                          {alert.detectedUserName || 'Chưa định danh'}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-[#717171] tabular-nums">
                          {alert.ipAddress}
                        </TableCell>
                        <TableCell className="text-xs text-[#717171] whitespace-nowrap tabular-nums">
                          {formatSafeDateVi(alert.detectedAt, { includeTime: true })}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              alert.status === 'OPEN'
                                ? 'destructive'
                                : alert.status === 'INVESTIGATING' || alert.status === 'ESCALATED'
                                  ? 'warning'
                                  : 'success'
                            }
                          >
                            {formatAlertStatusLabel(alert.status)}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right whitespace-nowrap">
                          <InteractiveHoverButton
                            size="sm"
                            variant="secondary"
                            text="Chi tiết"
                            icon={<Search size={16} strokeWidth={1.75} aria-hidden="true" />}
                            onClick={() => onSelectAlert(alert)}
                          />
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </>
        )}

        {totalPages > 1 && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#ebebeb] px-4 py-3 text-xs text-[#717171]">
            <span className="tabular-nums">
              Trang {page} / {totalPages} · Tổng {total} cảnh báo
            </span>
            <div className="flex items-center gap-2">
              <InteractiveHoverButton
                type="button"
                size="sm"
                variant="secondary"
                text="Trang trước"
                icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
                disabled={isLoading || page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              />
              <InteractiveHoverButton
                type="button"
                size="sm"
                variant="secondary"
                text="Trang sau"
                icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
                disabled={isLoading || page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              />
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

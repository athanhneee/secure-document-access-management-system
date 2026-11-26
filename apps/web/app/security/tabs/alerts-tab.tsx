'use client';

import { AlertTriangle, ChevronLeft, ChevronRight, RotateCcw, Search, X } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
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
import type { SecurityAlertItem } from '../types';

interface AlertsTabProps {
  alerts: SecurityAlertItem[];
  total: number;
  page: number;
  severityFilter: string;
  statusFilter: string;
  searchQuery: string;
  tabError?: string | null | undefined;
  onSeverityChange: (value: string) => void;
  onStatusChange: (value: string) => void;
  onSearchChange: (value: string) => void;
  onPageChange: (page: number) => void;
  onSelectAlert: (alert: SecurityAlertItem) => void;
}

const PAGE_SIZE = 20;

/**
 * Thuật toán: Hàng Đợi Cảnh Báo SOC Lọc & Phân Trang Phía Máy Chủ Kèm Cô Lập Lỗi Tab & Thẻ Di Động `375px` (`AlertsTab`)
 * Mục đích: Khắc phục giới hạn 50 dòng tĩnh, hiển thị tổng `meta.total`, lọc server-side và hiển thị địa chỉ IP nguồn thực tế (#03, #13, #29, #33).
 */
export function AlertsTab({
  alerts,
  total,
  page,
  severityFilter,
  statusFilter,
  searchQuery,
  tabError,
  onSeverityChange,
  onStatusChange,
  onSearchChange,
  onPageChange,
  onSelectAlert,
}: AlertsTabProps) {
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const hasFilters =
    severityFilter !== 'ALL' || statusFilter !== 'ALL' || searchQuery.trim() !== '';

  function getSeverityVariant(severity: SecurityAlertItem['severity']) {
    if (severity === 'CRITICAL') return 'destructive' as const;
    if (severity === 'HIGH') return 'warning' as const;
    return 'info' as const;
  }

  function getStatusVariant(status: SecurityAlertItem['status']) {
    if (status === 'OPEN') return 'destructive' as const;
    if (status === 'INVESTIGATING') return 'warning' as const;
    return 'success' as const;
  }

  return (
    <Card>
      <CardHeader className="p-4 sm:p-5 pb-3.5 border-b border-[#ebebeb] space-y-3">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          <CardTitle className="text-sm sm:text-base text-[#222222] shrink-0">
            Hàng đợi cảnh báo bảo mật ({total})
          </CardTitle>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 w-full lg:w-auto min-w-0">
            <div className="relative">
              <label htmlFor="soc-alert-search" className="sr-only">
                Tìm kiếm cảnh báo
              </label>
              <Search
                size={16}
                strokeWidth={1.75}
                className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-[#717171]"
                aria-hidden="true"
              />
              <Input
                id="soc-alert-search"
                maxLength={120}
                value={searchQuery}
                onChange={(e) => onSearchChange(e.target.value)}
                placeholder="Tìm tiêu đề, người dùng…"
                className={`pl-10 ${searchQuery ? 'pr-11 sm:pr-10' : ''} h-11 sm:h-9 w-full rounded-[12px] sm:rounded-full border-[#dddddd] bg-[#ffffff] placeholder:text-[#717171]`}
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => onSearchChange('')}
                  aria-label="Xóa từ khóa tìm kiếm"
                  className="absolute right-0.5 sm:right-1.5 top-1/2 -translate-y-1/2 flex h-11 w-11 sm:h-7 sm:w-7 items-center justify-center rounded-full text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] cursor-pointer"
                >
                  <X size={16} strokeWidth={2} aria-hidden="true" />
                </button>
              )}
            </div>

            <div>
              <label htmlFor="soc-alert-severity-filter" className="sr-only">
                Lọc theo mức độ nghiêm trọng
              </label>
              <Select
                id="soc-alert-severity-filter"
                value={severityFilter}
                onChange={(e) => onSeverityChange(e.target.value)}
              >
                <option value="ALL">Mọi mức độ nghiêm trọng</option>
                <option value="CRITICAL">Nghiêm trọng</option>
                <option value="HIGH">Cao</option>
                <option value="MEDIUM">Trung bình</option>
                <option value="LOW">Thấp</option>
              </Select>
            </div>

            <div>
              <label htmlFor="soc-alert-status-filter" className="sr-only">
                Lọc theo trạng thái xử lý
              </label>
              <Select
                id="soc-alert-status-filter"
                value={statusFilter}
                onChange={(e) => onStatusChange(e.target.value)}
              >
                <option value="ALL">Mọi trạng thái xử lý</option>
                <option value="OPEN">Chờ xử lý</option>
                <option value="INVESTIGATING">Đang điều tra</option>
                <option value="RESOLVED">Đã xử lý</option>
                <option value="FALSE_POSITIVE">Báo động giả</option>
              </Select>
            </div>
          </div>
        </div>

        {tabError && (
          <Alert variant="destructive" className="text-xs">
            <AlertTriangle
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#C13515]"
              aria-hidden="true"
            />
            <AlertDescription className="ml-2">{tabError}</AlertDescription>
          </Alert>
        )}
      </CardHeader>

      <CardContent className="p-0">
        {alerts.length === 0 ? (
          <div className="py-10 px-4 text-center text-xs text-[#717171]">
            <div className="flex flex-col items-center gap-2.5">
              <span>Không có cảnh báo bảo mật nào khớp với bộ lọc hiện tại.</span>
              {hasFilters && (
                <InteractiveHoverButton
                  type="button"
                  size="sm"
                  variant="secondary"
                  text="Xóa bộ lọc"
                  icon={<RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />}
                  onClick={() => {
                    onSeverityChange('ALL');
                    onStatusChange('ALL');
                    onSearchChange('');
                  }}
                />
              )}
            </div>
          </div>
        ) : (
          <>
            <div className="md:hidden divide-y divide-[#ebebeb]">
              {alerts.map((alert) => (
                <article key={alert.id} className="px-4 py-4 space-y-3 bg-[#ffffff]">
                  <div className="flex items-center justify-between gap-2">
                    <Badge variant={getSeverityVariant(alert.severity)}>
                      {formatAlertSeverityLabel(alert.severity)}
                    </Badge>
                    <Badge variant={getStatusVariant(alert.status)}>
                      {formatAlertStatusLabel(alert.status)}
                    </Badge>
                  </div>

                  <div className="space-y-0.5 min-w-0">
                    <h3 className="text-sm font-semibold text-[#222222] leading-snug break-words">
                      {alert.title}
                    </h3>
                    <p className="text-xs text-[#717171]">
                      {formatDetectionRuleLabel(alert.ruleCode)}
                      {alert.notes && alert.notes.length > 0
                        ? ` · ${alert.notes.length} ghi chú`
                        : ''}
                    </p>
                  </div>

                  <div className="rounded-[12px] bg-[#f7f7f7] px-3 py-2 space-y-1.5 text-xs">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-[#717171] shrink-0">Đối tượng</span>
                      <span className="font-medium text-[#222222] text-right truncate">
                        {alert.detectedUserName || 'Chưa định danh'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-[#717171] shrink-0">Địa chỉ IP</span>
                      <span className="font-mono text-[#222222] tabular-nums">
                        {alert.ipAddress}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-[#717171] shrink-0">Thời điểm</span>
                      <span className="text-[#717171] tabular-nums">
                        {formatSafeDateVi(alert.detectedAt, { includeTime: true })}
                      </span>
                    </div>
                  </div>

                  <div className="pt-0.5">
                    <InteractiveHoverButton
                      size="sm"
                      variant="secondary"
                      text="Chi tiết"
                      icon={<Search size={16} strokeWidth={1.75} aria-hidden="true" />}
                      onClick={() => onSelectAlert(alert)}
                      className="w-full"
                    />
                  </div>
                </article>
              ))}
            </div>

            <div className="hidden md:block">
              <Table>
                <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                  <TableRow>
                    <TableHead className="text-xs text-[#717171]">Mức độ</TableHead>
                    <TableHead className="text-xs text-[#717171]">
                      Loại cảnh báo / Tiêu đề
                    </TableHead>
                    <TableHead className="text-xs text-[#717171]">Đối tượng phát hiện</TableHead>
                    <TableHead className="text-xs text-[#717171]">Địa chỉ IP</TableHead>
                    <TableHead className="text-xs text-[#717171]">Thời điểm</TableHead>
                    <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                    <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {alerts.map((alert) => (
                    <TableRow
                      key={alert.id}
                      className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                    >
                      <TableCell>
                        <Badge variant={getSeverityVariant(alert.severity)}>
                          {formatAlertSeverityLabel(alert.severity)}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-xs">
                        <div className="font-semibold text-xs text-[#222222] break-words">
                          {alert.title}
                        </div>
                        <div className="text-xs text-[#717171]">
                          {formatDetectionRuleLabel(alert.ruleCode)}
                          {alert.notes && alert.notes.length > 0
                            ? ` · ${alert.notes.length} ghi chú`
                            : ''}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-[#222222]">
                        {alert.detectedUserName || 'Chưa định danh'}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-[#717171]">
                        {alert.ipAddress}
                      </TableCell>
                      <TableCell className="text-xs text-[#717171] whitespace-nowrap">
                        {formatSafeDateVi(alert.detectedAt, { includeTime: true })}
                      </TableCell>
                      <TableCell>
                        <Badge variant={getStatusVariant(alert.status)}>
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
                  ))}
                </TableBody>
              </Table>
            </div>
          </>
        )}

        {totalPages > 1 && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#ebebeb] px-4 py-3 text-xs text-[#717171]">
            <span>
              Trang {page} / {totalPages} · Tổng {total} cảnh báo
            </span>
            <div className="flex items-center gap-2">
              <InteractiveHoverButton
                type="button"
                size="sm"
                variant="secondary"
                text="Trang trước"
                icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
                disabled={page <= 1}
                onClick={() => onPageChange(Math.max(1, page - 1))}
              />
              <InteractiveHoverButton
                type="button"
                size="sm"
                variant="secondary"
                text="Trang sau"
                icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
                disabled={page >= totalPages}
                onClick={() => onPageChange(Math.min(totalPages, page + 1))}
              />
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

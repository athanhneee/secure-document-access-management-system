'use client';

import { Calendar, ChevronLeft, ChevronRight, Eye, Search } from 'lucide-react';
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
import type { AuditLogItem } from '../types';

interface AuditTrailTabProps {
  logs: AuditLogItem[];
  page: number;
  totalPages: number;
  totalLogs: number;
  isLoading: boolean;
  outcomeFilter: string;
  actionFilter: string;
  fromDate: string;
  toDate: string;
  onPageChange: (nextPage: number) => void;
  onOutcomeFilterChange: (value: string) => void;
  onActionFilterChange: (value: string) => void;
  onFromDateChange: (value: string) => void;
  onToDateChange: (value: string) => void;
  onSelectLog: (log: AuditLogItem) => void;
}

/**
 * Thuật toán: Bảng Tra Cứu Nhật Ký Kiểm Toán Phân Trang & Xem Siêu Dữ Liệu Pháp Chứng (`AuditTrailTab`)
 * Mục đích: Kết hợp bộ lọc đa chiều, điều hướng phân trang máy chủ (`Trang trước`, `Trang X / Y`, `Trang sau`) và mở `<dialog>` chi tiết pháp chứng Read-Only trên từng bản ghi.
 */
export function AuditTrailTab({
  logs,
  page,
  totalPages,
  totalLogs,
  isLoading,
  outcomeFilter,
  actionFilter,
  fromDate,
  toDate,
  onPageChange,
  onOutcomeFilterChange,
  onActionFilterChange,
  onFromDateChange,
  onToDateChange,
  onSelectLog,
}: AuditTrailTabProps) {
  const safeTotalPages = Math.max(1, totalPages);

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-3">
          <CardTitle className="text-sm sm:text-base text-[#222222] shrink-0">
            Nhật ký kiểm toán ({totalLogs})
          </CardTitle>

          <div className="flex flex-col sm:flex-row sm:flex-wrap items-stretch sm:items-center gap-2 w-full xl:w-auto min-w-0">
            <div>
              <label htmlFor="auditor-outcome-filter" className="sr-only">
                Lọc theo kết quả kiểm toán
              </label>
              <select
                id="auditor-outcome-filter"
                value={outcomeFilter}
                onChange={(e) => onOutcomeFilterChange(e.target.value)}
                className="min-h-11 sm:h-9 w-full sm:w-auto rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
              >
                <option value="ALL">Mọi kết quả</option>
                <option value="SUCCESS">SUCCESS (Thành công)</option>
                <option value="DENIED">DENIED (Từ chối)</option>
                <option value="FAILED">FAILED (Thất bại)</option>
              </select>
            </div>

            <div className="relative w-full sm:w-44 min-w-0">
              <label htmlFor="auditor-action-filter" className="sr-only">
                Lọc theo mã hành động
              </label>
              <Search
                size={16}
                strokeWidth={1.75}
                className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-[#717171]"
                aria-hidden="true"
              />
              <Input
                id="auditor-action-filter"
                type="text"
                placeholder="Lọc hành động..."
                value={actionFilter}
                onChange={(e) => onActionFilterChange(e.target.value)}
                className="pl-9 min-h-11 sm:h-9 w-full text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20"
              />
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center gap-1.5 w-full sm:w-auto shrink-0 text-xs text-[#717171]">
              <div className="flex items-center gap-1.5 w-full sm:w-auto shrink-0">
                <Calendar
                  size={16}
                  strokeWidth={1.75}
                  className="shrink-0 text-[#717171]"
                  aria-hidden="true"
                />
                <label htmlFor="auditor-from-date" className="sr-only">
                  Từ ngày
                </label>
                <div className="w-full sm:w-36 shrink-0">
                  <Input
                    id="auditor-from-date"
                    type="date"
                    value={fromDate}
                    onChange={(e) => onFromDateChange(e.target.value)}
                    className="min-h-11 sm:h-9 w-full text-xs rounded-full bg-[#ffffff] border-[#dddddd] px-3 text-[#222222] focus:border-[#FF385C]"
                  />
                </div>
              </div>
              <span className="hidden sm:inline shrink-0 text-[#717171]" aria-hidden="true">
                –
              </span>
              <label htmlFor="auditor-to-date" className="sr-only">
                Đến ngày
              </label>
              <div className="w-full sm:w-36 shrink-0">
                <Input
                  id="auditor-to-date"
                  type="date"
                  value={toDate}
                  onChange={(e) => onToDateChange(e.target.value)}
                  className="min-h-11 sm:h-9 w-full text-xs rounded-full bg-[#ffffff] border-[#dddddd] px-3 text-[#222222] focus:border-[#FF385C]"
                />
              </div>
            </div>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
            <TableRow>
              <TableHead className="text-xs text-[#717171]">Thời gian (UTC)</TableHead>
              <TableHead className="text-xs text-[#717171]">Người thực hiện</TableHead>
              <TableHead className="text-xs text-[#717171]">Hành động</TableHead>
              <TableHead className="text-xs text-[#717171]">Kết quả</TableHead>
              <TableHead className="text-xs text-[#717171]">Địa chỉ IP</TableHead>
              <TableHead className="text-xs text-[#717171]">Correlation ID / Hash</TableHead>
              <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {logs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="py-8 text-center text-xs text-[#717171]">
                  Không có bản ghi nhật ký kiểm toán phù hợp bộ lọc hiện tại
                </TableCell>
              </TableRow>
            ) : (
              logs.map((log) => (
                <TableRow key={log.id} className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60">
                  <TableCell className="font-bold text-xs text-[#717171] whitespace-nowrap">
                    {log.occurredAt
                      ? new Date(log.occurredAt).toISOString().replace('T', ' ').slice(0, 19)
                      : '—'}
                  </TableCell>
                  <TableCell className="font-semibold text-xs text-[#222222]">
                    {log.actorUsername}
                  </TableCell>
                  <TableCell className="font-bold text-xs text-[#008489]">{log.action}</TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        log.outcome === 'SUCCESS'
                          ? 'success'
                          : log.outcome === 'DENIED'
                            ? 'warning'
                            : 'destructive'
                      }
                    >
                      {log.outcome}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-bold text-xs text-[#717171]">
                    {log.ipAddress || '—'}
                  </TableCell>
                  <TableCell className="font-bold text-xs text-[#717171] max-w-xs truncate">
                    {log.correlationId}
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap">
                    <InteractiveHoverButton
                      size="sm"
                      variant="secondary"
                      text="Xem"
                      icon={<Eye size={16} strokeWidth={1.75} aria-hidden="true" />}
                      onClick={() => onSelectLog(log)}
                    />
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>

        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-t border-[#ebebeb] bg-[#f7f7f7]/50 px-4 py-2.5 text-xs text-[#717171]">
          <div>
            Tổng cộng <strong className="text-[#222222]">{totalLogs}</strong> bản ghi · Hiển thị{' '}
            <strong className="text-[#222222]">{logs.length}</strong> dòng
          </div>
          <div className="flex items-center justify-between sm:justify-end gap-2">
            <InteractiveHoverButton
              type="button"
              size="sm"
              variant="secondary"
              text="Trang trước"
              icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
              disabled={isLoading || page <= 1}
              onClick={() => onPageChange(Math.max(1, page - 1))}
            />
            <span className="px-2 font-semibold text-[#222222] whitespace-nowrap">
              Trang {page} / {safeTotalPages}
            </span>
            <InteractiveHoverButton
              type="button"
              size="sm"
              variant="secondary"
              text="Trang sau"
              icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
              disabled={isLoading || page >= safeTotalPages}
              onClick={() => onPageChange(Math.min(safeTotalPages, page + 1))}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

'use client';

import { useEffect, useRef } from 'react';
import { ChevronLeft, ChevronRight, Eye, RotateCcw } from 'lucide-react';
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
  formatAuditOutcomeLabel,
  formatAuditPartitionLabel,
  formatSafeDateVi,
} from '@/lib/ui-labels';
import type { AuditLogItem } from '../types';
import { AuditTrailFiltersBar } from './audit-trail-filters';

interface AuditTrailTabProps {
  logs: AuditLogItem[];
  page: number;
  pageSize: number;
  totalPages: number;
  totalLogs: number;
  isLoading: boolean;
  outcomeFilter: string;
  actionFilter: string;
  partitionFilter: string;
  actorFilter: string;
  fromDate: string;
  toDate: string;
  sortOrder: 'desc' | 'asc';
  dateRangeError: string | null;
  onPageChange: (nextPage: number) => void;
  onPageSizeChange: (nextPageSize: number) => void;
  onOutcomeFilterChange: (value: string) => void;
  onActionFilterChange: (value: string) => void;
  onPartitionFilterChange: (value: string) => void;
  onActorFilterChange: (value: string) => void;
  onFromDateChange: (value: string) => void;
  onToDateChange: (value: string) => void;
  onSortOrderChange: (value: 'desc' | 'asc') => void;
  onResetFilters: () => void;
  onSelectLog: (log: AuditLogItem) => void;
}

function getOutcomeBadgeVariant(outcome: AuditLogItem['outcome']) {
  if (outcome === 'SUCCESS') return 'success';
  if (outcome === 'DENIED') return 'warning';
  return 'destructive';
}

/**
 * Thuật toán: Giao Diện Tra Cứu Nhật Ký Kiểm Toán Thích Ứng Mobile 375px (Thẻ Dọc) & Desktop (Bảng Ghim Đầu) (`AuditTrailTab`)
 * Mục đích:
 *   - Loại bỏ tình trạng chớp nháy rỗng khi đang tải bằng khung xương Skeleton, đồng thời loại bỏ cuộn ngang 880px trên màn hình mobile 375px bằng danh sách thẻ gọn gàng.
 *   - Đảm bảo mọi nút chọn (bao gồm `#auditor-page-size`) đạt ngưỡng chạm tối thiểu 44px trên di động và phân cấp rõ nét giữa thông tin chính/phụ.
 */
export function AuditTrailTab({
  logs,
  page,
  pageSize,
  totalPages,
  totalLogs,
  isLoading,
  outcomeFilter,
  actionFilter,
  partitionFilter,
  actorFilter,
  fromDate,
  toDate,
  sortOrder,
  dateRangeError,
  onPageChange,
  onPageSizeChange,
  onOutcomeFilterChange,
  onActionFilterChange,
  onPartitionFilterChange,
  onActorFilterChange,
  onFromDateChange,
  onToDateChange,
  onSortOrderChange,
  onResetFilters,
  onSelectLog,
}: AuditTrailTabProps) {
  const safeTotalPages = Math.max(1, totalPages);
  const tableScrollRef = useRef<HTMLDivElement | null>(null);
  const hasFilters =
    outcomeFilter !== 'ALL' ||
    partitionFilter !== 'ALL' ||
    actionFilter.trim() !== '' ||
    actorFilter.trim() !== '' ||
    fromDate !== '' ||
    toDate !== '';

  useEffect(() => {
    tableScrollRef.current?.scrollTo({ top: 0 });
  }, [
    page,
    pageSize,
    outcomeFilter,
    partitionFilter,
    actionFilter,
    actorFilter,
    fromDate,
    toDate,
    sortOrder,
  ]);

  return (
    <Card>
      <CardHeader className="pb-3 space-y-3">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-sm sm:text-base text-[#222222] shrink-0">
            Nhật ký kiểm toán ({totalLogs})
          </CardTitle>
        </div>

        <AuditTrailFiltersBar
          outcomeFilter={outcomeFilter}
          actionFilter={actionFilter}
          partitionFilter={partitionFilter}
          actorFilter={actorFilter}
          fromDate={fromDate}
          toDate={toDate}
          sortOrder={sortOrder}
          dateRangeError={dateRangeError}
          onOutcomeFilterChange={onOutcomeFilterChange}
          onActionFilterChange={onActionFilterChange}
          onPartitionFilterChange={onPartitionFilterChange}
          onActorFilterChange={onActorFilterChange}
          onFromDateChange={onFromDateChange}
          onToDateChange={onToDateChange}
          onSortOrderChange={onSortOrderChange}
          onResetFilters={onResetFilters}
        />
      </CardHeader>

      <CardContent className="p-0">
        {isLoading && logs.length === 0 ? (
          <div className="p-4 space-y-2.5" aria-busy="true" aria-live="polite">
            {[0, 1, 2, 3, 4].map((idx) => (
              <div
                key={idx}
                className="h-12 w-full rounded-[14px] bg-[#f7f7f7] border border-[#ebebeb] animate-pulse"
              />
            ))}
          </div>
        ) : (
          <>
            {/* Mobile 375px card view — zero horizontal overflow */}
            <div className="md:hidden divide-y divide-[#ebebeb]">
              {logs.length === 0 ? (
                <div className="px-4 py-8 text-center text-xs text-[#717171] space-y-3">
                  <p>Không có bản ghi nhật ký kiểm toán nào phù hợp với bộ lọc hiện tại.</p>
                  {hasFilters && (
                    <InteractiveHoverButton
                      type="button"
                      size="sm"
                      variant="secondary"
                      text="Xóa bộ lọc"
                      icon={<RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />}
                      onClick={onResetFilters}
                    />
                  )}
                </div>
              ) : (
                logs.map((log) => {
                  const formattedTime = formatSafeDateVi(log.occurredAt, { includeTime: true });
                  const actionLabel = formatAuditActionLabel(log.action);
                  const actorLabel =
                    log.actorUsername === 'SYSTEM' ? 'Hệ thống' : log.actorUsername;
                  return (
                    <article key={log.id} className="p-3.5 space-y-2 text-xs">
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <div className="font-semibold text-[#008489] break-words">
                            {actionLabel}
                          </div>
                          <div className="text-[#717171] tabular-nums">{formattedTime}</div>
                        </div>
                        <Badge variant={getOutcomeBadgeVariant(log.outcome)}>
                          {formatAuditOutcomeLabel(log.outcome)}
                        </Badge>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[#717171]">
                        <div className="min-w-0 truncate">
                          Tác nhân:{' '}
                          <span className="font-semibold text-[#222222]">{actorLabel}</span>
                        </div>
                        <div className="min-w-0 truncate">
                          Phân vùng:{' '}
                          <span className="text-[#222222]">
                            {formatAuditPartitionLabel(log.chainPartition)}
                          </span>
                        </div>
                        <div className="min-w-0 truncate tabular-nums">
                          IP:{' '}
                          <span className="font-mono text-[#222222]">{log.ipAddress || '—'}</span>
                        </div>
                        <div className="min-w-0 truncate">
                          Mã: <span className="font-mono text-[#222222]">{log.correlationId}</span>
                        </div>
                      </div>
                      <div className="pt-1">
                        <InteractiveHoverButton
                          size="sm"
                          variant="secondary"
                          text="Xem chi tiết"
                          icon={<Eye size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => onSelectLog(log)}
                          className="w-full"
                        />
                      </div>
                    </article>
                  );
                })
              )}
            </div>

            {/* Desktop table view */}
            <div className="hidden md:block">
              <Table containerRef={tableScrollRef} className="min-w-[880px] table-fixed">
                <caption className="sr-only">
                  Danh sách bản ghi nhật ký kiểm toán hệ thống theo bộ lọc hiện hành
                </caption>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[168px] text-xs text-[#717171]">Thời gian</TableHead>
                    <TableHead className="w-[138px] text-xs text-[#717171]">
                      Người thực hiện
                    </TableHead>
                    <TableHead className="w-[215px] text-xs text-[#717171]">Hành động</TableHead>
                    <TableHead className="w-[105px] text-xs text-[#717171]">Kết quả</TableHead>
                    <TableHead className="w-[115px] text-xs text-[#717171]">Địa chỉ IP</TableHead>
                    <TableHead className="text-xs text-[#717171]">Mã truy vết</TableHead>
                    <TableHead className="w-[96px] text-xs text-[#717171] text-right">
                      Thao tác
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {logs.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="py-8 text-center text-xs text-[#717171]">
                        <div className="flex flex-col items-center gap-2.5">
                          <span>
                            Không có bản ghi nhật ký kiểm toán nào phù hợp với bộ lọc hiện tại.
                          </span>
                          {hasFilters && (
                            <InteractiveHoverButton
                              type="button"
                              size="sm"
                              variant="secondary"
                              text="Xóa bộ lọc"
                              icon={<RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />}
                              onClick={onResetFilters}
                            />
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    logs.map((log) => {
                      const formattedTime = formatSafeDateVi(log.occurredAt, { includeTime: true });
                      const actionLabel = formatAuditActionLabel(log.action);
                      const actorLabel =
                        log.actorUsername === 'SYSTEM' ? 'Hệ thống' : log.actorUsername;
                      const partitionLabel = formatAuditPartitionLabel(log.chainPartition);
                      return (
                        <TableRow
                          key={log.id}
                          className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                        >
                          <TableCell
                            title={formattedTime}
                            className="font-normal text-xs text-[#717171] whitespace-nowrap tabular-nums truncate"
                          >
                            {formattedTime}
                          </TableCell>
                          <TableCell
                            title={actorLabel}
                            className="font-semibold text-xs text-[#222222] truncate"
                          >
                            {actorLabel}
                          </TableCell>
                          <TableCell title={`${actionLabel} (${log.action}) · ${partitionLabel}`}>
                            <div className="font-semibold text-xs text-[#008489] truncate">
                              {actionLabel}
                            </div>
                            <div className="text-[11px] text-[#717171] truncate">
                              {partitionLabel}
                            </div>
                          </TableCell>
                          <TableCell className="whitespace-nowrap">
                            <Badge variant={getOutcomeBadgeVariant(log.outcome)}>
                              {formatAuditOutcomeLabel(log.outcome)}
                            </Badge>
                          </TableCell>
                          <TableCell
                            title={log.ipAddress || '—'}
                            className="font-mono font-normal text-xs text-[#717171] whitespace-nowrap tabular-nums truncate"
                          >
                            {log.ipAddress || '—'}
                          </TableCell>
                          <TableCell
                            title={log.correlationId}
                            className="font-mono font-normal text-xs text-[#717171] truncate"
                          >
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
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </div>
          </>
        )}

        <div
          aria-live="polite"
          className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 border-t border-[#ebebeb] bg-[#f7f7f7]/60 px-4 py-2.5 text-xs text-[#717171]"
        >
          <div className="flex flex-wrap items-center gap-2.5">
            <span>
              Tổng cộng <strong className="text-[#222222]">{totalLogs}</strong> bản ghi · Đang hiển
              thị <strong className="text-[#222222]">{logs.length}</strong> bản ghi
            </span>
            <div className="inline-flex items-center gap-1.5">
              <label htmlFor="auditor-page-size" className="sr-only">
                Số bản ghi mỗi trang nhật ký
              </label>
              <select
                id="auditor-page-size"
                value={pageSize}
                onChange={(e) => onPageSizeChange(Number(e.target.value))}
                className="min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs font-medium text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
              >
                <option value={10}>10 bản ghi / trang</option>
                <option value={20}>20 bản ghi / trang</option>
                <option value={50}>50 bản ghi / trang</option>
              </select>
            </div>
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
            <span className="px-2 font-semibold text-[#222222] whitespace-nowrap tabular-nums">
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

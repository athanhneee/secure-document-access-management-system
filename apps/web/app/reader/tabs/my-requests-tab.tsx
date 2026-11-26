'use client';

import { useState } from 'react';
import { ChevronLeft, ChevronRight, Loader2, Search, X } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import {
  formatPermissionActionLabel,
  formatRequestStatusLabel,
  formatSafeDateVi,
} from '@/lib/ui-labels';
import { formatRequestDurationLabel } from '../helpers';
import type { MyRequestItem } from '../types';

interface MyRequestsTabProps {
  myRequests: MyRequestItem[];
  totalCount?: number | undefined;
  isLoading?: boolean | undefined;
  page?: number | undefined;
  hasMore?: boolean | undefined;
  onPageChange?: ((page: number) => void) | undefined;
  statusFilter?: string | undefined;
  onStatusFilterChange?: ((status: string) => void) | undefined;
  cancellingRequestId: string | null;
  canCancelRequest?: boolean;
  onCancelRequest: (requestId: string) => void;
}

/**
 * Thuật toán: Định Dạng Tiền Tố Mốc Thời Gian Quyết Định Theo Trạng Thái Yêu Cầu (`formatDecisionTimestampPrefix`, BUG-119)
 */
function formatDecisionTimestampPrefix(status: MyRequestItem['status']): string {
  if (status === 'APPROVED') return 'Duyệt:';
  if (status === 'REJECTED') return 'Từ chối:';
  if (status === 'CANCELLED') return 'Hủy:';
  if (status === 'EXPIRED') return 'Hết hạn:';
  return 'Xử lý:';
}

/**
 * Thuật toán: Định Dạng Nhãn Ghi Chú Quyết Định Theo Trạng Thái Yêu Cầu (`formatDecisionNoteHeading`, BUG-119)
 */
function formatDecisionNoteHeading(status: MyRequestItem['status']): string {
  if (status === 'REJECTED') return 'Lý do từ chối:';
  if (status === 'CANCELLED') return 'Ghi chú hủy:';
  return 'Phản hồi phê duyệt:';
}

/**
 * Thuật toán: Lịch Sử Yêu Cầu Truy Cập Kèm Lý Do Duyệt/Từ Chối (`decisionNote`), Lọc Trạng Thái, Phân Trang & Thẻ Di Động (`MyRequestsTab`)
 * Mục đích: Hiển thị đầy đủ `documentCode`, `justification`, `decidedAt`, `decisionNote` (`V-35`, `V-53`), loại bỏ chuỗi rác `"7 ngày (mặc định)"` và `NaN` (`V-32`, `V-46`), tối ưu `375px` (`V-58`) và cỡ chữ chuẩn `text-xs` (`V-61`).
 */
export function MyRequestsTab({
  myRequests,
  totalCount,
  isLoading = false,
  page = 1,
  hasMore = false,
  onPageChange,
  statusFilter = 'ALL',
  onStatusFilterChange,
  cancellingRequestId,
  canCancelRequest = true,
  onCancelRequest,
}: MyRequestsTabProps) {
  const [localQuery, setLocalQuery] = useState('');
  const q = localQuery.trim().toLowerCase();
  const visibleRequests = q
    ? myRequests.filter(
        (req) =>
          req.documentTitle.toLowerCase().includes(q) ||
          Boolean(req.documentCode && req.documentCode.toLowerCase().includes(q)) ||
          Boolean(req.justification && req.justification.toLowerCase().includes(q)) ||
          Boolean(req.decisionNote && req.decisionNote.toLowerCase().includes(q)),
      )
    : myRequests;

  const badgeVariantFor = (status: MyRequestItem['status']) =>
    status === 'PENDING'
      ? 'warning'
      : status === 'APPROVED'
        ? 'success'
        : status === 'CANCELLED' || status === 'EXPIRED'
          ? 'neutral'
          : 'destructive';

  return (
    <Card>
      <CardHeader className="p-4 sm:p-5 pb-3.5 border-b border-[#ebebeb] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <CardTitle className="text-sm sm:text-base text-[#222222] shrink-0">
          Yêu cầu truy cập của tôi (
          {typeof totalCount === 'number' ? totalCount : myRequests.length})
        </CardTitle>

        <div className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto shrink-0">
          <div className="relative w-full sm:w-56 sm:order-2">
            <Search
              size={16}
              strokeWidth={1.75}
              className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-[#717171]"
              aria-hidden="true"
            />
            <Input
              id="reader-requests-search"
              name="reader-requests-search"
              type="text"
              aria-label="Tìm kiếm trong yêu cầu của tôi"
              placeholder="Tìm tên tài liệu, mã hoặc ghi chú…"
              value={localQuery}
              onChange={(e) => setLocalQuery(e.target.value)}
              className={`pl-10 ${localQuery ? 'pr-10' : ''} h-11 sm:h-9 rounded-[12px] sm:rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#222222] focus-visible:ring-2 focus-visible:ring-[#222222]/15 shadow-2xs`}
            />
            {localQuery && (
              <button
                type="button"
                onClick={() => setLocalQuery('')}
                aria-label="Xóa từ khóa tìm kiếm"
                className="absolute right-1.5 top-1/2 -translate-y-1/2 flex h-9 w-9 sm:h-7 sm:w-7 items-center justify-center rounded-full text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] cursor-pointer"
              >
                <X size={16} strokeWidth={2} aria-hidden="true" />
              </button>
            )}
          </div>

          {onStatusFilterChange && (
            <Select
              id="reader-requests-status-filter"
              name="reader-requests-status-filter"
              aria-label="Lọc yêu cầu theo trạng thái"
              value={statusFilter}
              onChange={(e) => onStatusFilterChange(e.target.value)}
              wrapperClassName="w-full sm:w-44 sm:order-1"
            >
              <option value="ALL">Tất cả trạng thái</option>
              <option value="PENDING">Chờ duyệt</option>
              <option value="APPROVED">Đã duyệt</option>
              <option value="REJECTED">Từ chối</option>
              <option value="CANCELLED">Đã hủy</option>
              <option value="EXPIRED">Đã hết hạn</option>
            </Select>
          )}
        </div>
      </CardHeader>

      <CardContent className="p-0">
        {isLoading && myRequests.length === 0 ? (
          <div className="py-10 flex flex-col items-center justify-center gap-2 text-xs text-[#717171]">
            <Loader2
              size={20}
              strokeWidth={2}
              className="animate-spin text-[#FF385C]"
              aria-hidden="true"
            />
            <span>Đang tải lịch sử yêu cầu truy cập…</span>
          </div>
        ) : visibleRequests.length === 0 ? (
          <div className="py-10 px-4 text-center text-xs text-[#717171]">
            {q || statusFilter !== 'ALL'
              ? 'Không có yêu cầu nào khớp bộ lọc hiện tại.'
              : 'Bạn chưa gửi yêu cầu quyền truy cập nào.'}
          </div>
        ) : (
          <>
            {/* Bố cục thẻ di động tối ưu 375px (V-58) */}
            <div className="md:hidden divide-y divide-[#ebebeb]">
              {visibleRequests.map((req) => {
                const durationLabel = formatRequestDurationLabel(
                  req.requestedFrom,
                  req.requestedUntil,
                );
                return (
                  <article key={req.id} className="px-4 py-4 space-y-3 bg-[#ffffff]">
                    <div className="flex items-center justify-between gap-2">
                      <Badge variant={badgeVariantFor(req.status)}>
                        {formatRequestStatusLabel(req.status)}
                      </Badge>
                      {req.documentCode && (
                        <span className="font-mono text-xs text-[#717171] truncate">
                          {req.documentCode}
                        </span>
                      )}
                    </div>

                    <h3 className="text-sm font-semibold text-[#222222] leading-snug break-words">
                      {req.documentTitle}
                    </h3>

                    <div className="rounded-[12px] bg-[#f7f7f7] px-3 py-2 space-y-1.5 text-xs">
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-[#717171] shrink-0">Quyền đề nghị</span>
                        <Badge variant="secondary">
                          {formatPermissionActionLabel(req.requestedAction)}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-[#717171] shrink-0">Ngày gửi</span>
                        <span className="text-[#222222] tabular-nums">
                          {formatSafeDateVi(req.createdAt, { includeTime: true })}
                        </span>
                      </div>
                      {req.requestedFrom && req.requestedUntil && (
                        <div className="flex items-start justify-between gap-3">
                          <span className="text-[#717171] shrink-0">Thời hạn</span>
                          <span className="text-[#222222] text-right tabular-nums">
                            {formatSafeDateVi(req.requestedFrom)} →{' '}
                            {formatSafeDateVi(req.requestedUntil)}
                            {durationLabel ? ` (${durationLabel})` : ''}
                          </span>
                        </div>
                      )}
                      {req.decidedAt && (
                        <div className="flex items-center justify-between gap-3">
                          <span className="text-[#717171] shrink-0">
                            {formatDecisionTimestampPrefix(req.status).replace(/:$/, '')}
                          </span>
                          <span className="text-[#717171] tabular-nums">
                            {formatSafeDateVi(req.decidedAt, { includeTime: true })}
                          </span>
                        </div>
                      )}
                    </div>

                    {req.justification && (
                      <p className="text-xs text-[#717171] leading-relaxed break-words">
                        <strong className="text-[#222222]">Lý do đề xuất:</strong>{' '}
                        {req.justification}
                      </p>
                    )}

                    {req.decisionNote && (
                      <p
                        className={`text-xs leading-relaxed break-words ${
                          req.status === 'REJECTED'
                            ? 'text-[#C13515] font-medium'
                            : 'text-[#222222]'
                        }`}
                      >
                        <strong>{formatDecisionNoteHeading(req.status)}</strong> {req.decisionNote}
                      </p>
                    )}

                    {req.status === 'PENDING' && canCancelRequest && (
                      <div className="pt-0.5">
                        <InteractiveHoverButton
                          size="sm"
                          variant="secondary"
                          text="Hủy yêu cầu"
                          onClick={() => onCancelRequest(req.id)}
                          isLoading={cancellingRequestId === req.id}
                          className="w-full"
                        />
                      </div>
                    )}
                  </article>
                );
              })}
            </div>

            {/* Bảng dữ liệu máy tính */}
            <div className="hidden md:block">
              <Table>
                <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                  <TableRow>
                    <TableHead className="text-xs text-[#717171]">Tài liệu &amp; Lý do</TableHead>
                    <TableHead className="text-xs text-[#717171]">Quyền yêu cầu</TableHead>
                    <TableHead className="text-xs text-[#717171]">Thời hạn đề nghị</TableHead>
                    <TableHead className="text-xs text-[#717171]">Ngày gửi</TableHead>
                    <TableHead className="text-xs text-[#717171]">
                      Trạng thái &amp; Phản hồi
                    </TableHead>
                    <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visibleRequests.map((req) => {
                    const durationLabel = formatRequestDurationLabel(
                      req.requestedFrom,
                      req.requestedUntil,
                    );
                    return (
                      <TableRow
                        key={req.id}
                        className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                      >
                        <TableCell>
                          <div className="font-semibold text-xs text-[#222222]">
                            {req.documentTitle}
                          </div>
                          {req.documentCode && (
                            <div className="text-xs font-bold text-[#717171]">
                              {req.documentCode}
                            </div>
                          )}
                          {req.justification && (
                            <div className="text-xs text-[#717171] line-clamp-2 mt-0.5 max-w-sm">
                              {req.justification}
                            </div>
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary">
                            {formatPermissionActionLabel(req.requestedAction)}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs text-[#222222]">
                          {req.requestedFrom && req.requestedUntil ? (
                            <div className="flex flex-col text-xs">
                              <span className="font-medium text-[#222222]">
                                {formatSafeDateVi(req.requestedFrom)} &rarr;{' '}
                                {formatSafeDateVi(req.requestedUntil)}
                              </span>
                              {durationLabel && (
                                <span className="text-xs text-[#717171]">({durationLabel})</span>
                              )}
                            </div>
                          ) : (
                            <span className="text-[#717171]">—</span>
                          )}
                        </TableCell>
                        <TableCell className="text-xs text-[#717171] font-medium">
                          {formatSafeDateVi(req.createdAt, { includeTime: true })}
                        </TableCell>
                        <TableCell>
                          <div className="space-y-1">
                            <Badge variant={badgeVariantFor(req.status)}>
                              {formatRequestStatusLabel(req.status)}
                            </Badge>
                            {req.decisionNote && (
                              <p
                                className={`text-xs leading-snug max-w-xs break-words ${
                                  req.status === 'REJECTED'
                                    ? 'text-[#C13515] font-medium'
                                    : 'text-[#717171]'
                                }`}
                              >
                                {req.decisionNote}
                              </p>
                            )}
                            {req.decidedAt && (
                              <div className="text-xs text-[#717171]">
                                {formatDecisionTimestampPrefix(req.status)}{' '}
                                {formatSafeDateVi(req.decidedAt, { includeTime: true })}
                              </div>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          {req.status === 'PENDING' && canCancelRequest && (
                            <InteractiveHoverButton
                              size="sm"
                              variant="secondary"
                              text="Hủy yêu cầu"
                              onClick={() => onCancelRequest(req.id)}
                              isLoading={cancellingRequestId === req.id}
                            />
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </>
        )}

        {onPageChange && (page > 1 || hasMore) && (
          <div className="flex items-center justify-between gap-2 border-t border-[#ebebeb] px-4 py-3 text-xs">
            <span className="text-[#717171] font-medium tabular-nums">Trang {page}</span>
            <div className="flex items-center gap-2">
              <InteractiveHoverButton
                type="button"
                size="sm"
                variant="secondary"
                text="Trang trước"
                icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
                disabled={page <= 1 || isLoading}
                onClick={() => onPageChange(Math.max(1, page - 1))}
              />
              <InteractiveHoverButton
                type="button"
                size="sm"
                variant="secondary"
                text="Trang sau"
                icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
                disabled={!hasMore || isLoading}
                onClick={() => onPageChange(page + 1)}
              />
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

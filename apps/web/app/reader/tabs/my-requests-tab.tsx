'use client';

import { useState } from 'react';
import { ChevronLeft, ChevronRight, Loader2, Search } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Input } from '@/components/ui/input';
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
      <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <CardTitle className="text-sm sm:text-base text-[#222222]">
          Yêu cầu truy cập của tôi (
          {typeof totalCount === 'number' ? totalCount : myRequests.length})
        </CardTitle>
        <div className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto shrink-0">
          {onStatusFilterChange && (
            <select
              id="reader-requests-status-filter"
              name="reader-requests-status-filter"
              aria-label="Lọc yêu cầu theo trạng thái"
              value={statusFilter}
              onChange={(e) => onStatusFilterChange(e.target.value)}
              className="min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
            >
              <option value="ALL">Tất cả trạng thái</option>
              <option value="PENDING">Chờ duyệt</option>
              <option value="APPROVED">Đã duyệt</option>
              <option value="REJECTED">Từ chối</option>
              <option value="CANCELLED">Đã hủy</option>
              <option value="EXPIRED">Đã hết hạn</option>
            </select>
          )}
          <div className="relative w-full sm:w-56">
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
              className="pl-10 min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
            />
          </div>
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
                  <article key={req.id} className="p-3.5 space-y-2 text-xs bg-[#ffffff]">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <h3 className="font-semibold text-[#222222] break-words">
                          {req.documentTitle}
                        </h3>
                        {req.documentCode && (
                          <div className="text-xs font-bold text-[#717171]">{req.documentCode}</div>
                        )}
                      </div>
                      <Badge variant={badgeVariantFor(req.status)}>
                        {formatRequestStatusLabel(req.status)}
                      </Badge>
                    </div>
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-[#717171]">
                      <Badge variant="secondary">
                        {formatPermissionActionLabel(req.requestedAction)}
                      </Badge>
                      <span>Gửi: {formatSafeDateVi(req.createdAt, { includeTime: true })}</span>
                    </div>
                    {req.requestedFrom && req.requestedUntil && (
                      <div className="text-xs text-[#222222]">
                        Thời hạn: {formatSafeDateVi(req.requestedFrom)} →{' '}
                        {formatSafeDateVi(req.requestedUntil)}
                        {durationLabel ? ` (${durationLabel})` : ''}
                      </div>
                    )}
                    {req.justification && (
                      <p className="text-xs text-[#717171] leading-relaxed">
                        <strong className="text-[#222222]">Lý do đề xuất:</strong>{' '}
                        {req.justification}
                      </p>
                    )}
                    {req.decisionNote && (
                      <p
                        className={`text-xs leading-relaxed ${
                          req.status === 'REJECTED'
                            ? 'text-[#C13515] font-medium'
                            : 'text-[#222222]'
                        }`}
                      >
                        <strong>Phản hồi phê duyệt:</strong> {req.decisionNote}
                      </p>
                    )}
                    {req.decidedAt && (
                      <div className="text-xs text-[#717171]">
                        Xử lý lúc: {formatSafeDateVi(req.decidedAt, { includeTime: true })}
                      </div>
                    )}
                    {req.status === 'PENDING' && canCancelRequest && (
                      <div className="pt-1">
                        <InteractiveHoverButton
                          size="sm"
                          variant="secondary"
                          text="Hủy yêu cầu"
                          onClick={() => onCancelRequest(req.id)}
                          isLoading={cancellingRequestId === req.id}
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
                                Duyệt: {formatSafeDateVi(req.decidedAt, { includeTime: true })}
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
            <span className="text-[#717171] font-medium">Trang {page}</span>
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

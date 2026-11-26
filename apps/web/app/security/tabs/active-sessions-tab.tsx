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
import { formatSafeDateVi, formatSessionStatusLabel } from '@/lib/ui-labels';
import type { DocumentSessionItem } from '../types';

interface ActiveSessionsTabProps {
  documentSessions: DocumentSessionItem[];
  totalCount: number;
  filteredCount?: number | undefined;
  activeCount: number;
  page: number;
  statusFilter: 'ACTIVE' | 'ALL' | 'ENDED' | 'TERMINATED';
  searchQuery: string;
  tabError?: string | null | undefined;
  terminatingSessionId: string | null;
  canTerminateSession?: boolean;
  onStatusChange: (status: 'ACTIVE' | 'ALL' | 'ENDED' | 'TERMINATED') => void;
  onSearchChange: (value: string) => void;
  onPageChange: (page: number) => void;
  onTerminateSession: (sessionId: string) => void;
}

const PAGE_SIZE = 20;

/**
 * Thuật toán: Giám Sát Phiên Đọc Trực Tuyến & Lịch Sử Phiên Theo Trạng Thái Kèm Thẻ Di Động `375px` (`ActiveSessionsTab`)
 * Mục đích: Khắc phục bộ đếm trùng nhau `N/N` bằng bộ lọc `ACTIVE`/`ALL`/`ENDED`/`TERMINATED` từ máy chủ kèm hiển thị `activeCount / totalCount` trung thực và phân trang chính xác theo `filteredCount` (#12, #14, #20, #38, BUG-032).
 */
export function ActiveSessionsTab({
  documentSessions,
  totalCount,
  filteredCount,
  activeCount,
  page,
  statusFilter,
  searchQuery,
  tabError,
  terminatingSessionId,
  canTerminateSession = true,
  onStatusChange,
  onSearchChange,
  onPageChange,
  onTerminateSession,
}: ActiveSessionsTabProps) {
  const effectiveFilteredTotal = filteredCount ?? totalCount;
  const totalPages = Math.max(
    1,
    Math.ceil(Math.max(documentSessions.length, effectiveFilteredTotal) / PAGE_SIZE),
  );
  const hasFilters = statusFilter !== 'ACTIVE' || searchQuery.trim() !== '';

  function getStatusVariant(status: DocumentSessionItem['status']) {
    if (status === 'ACTIVE') return 'success' as const;
    if (status === 'TERMINATED') return 'destructive' as const;
    return 'neutral' as const;
  }

  return (
    <Card>
      <CardHeader className="p-4 sm:p-5 pb-3.5 border-b border-[#ebebeb] space-y-3">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          <CardTitle className="text-sm sm:text-base text-[#222222] shrink-0">
            Danh sách phiên đọc ({activeCount} đang hoạt động / {totalCount} tổng)
          </CardTitle>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 w-full lg:w-auto">
            <div className="relative">
              <label htmlFor="soc-session-search" className="sr-only">
                Tìm kiếm phiên đọc
              </label>
              <Search
                size={16}
                strokeWidth={1.75}
                className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-[#717171]"
                aria-hidden="true"
              />
              <Input
                id="soc-session-search"
                maxLength={120}
                value={searchQuery}
                onChange={(e) => onSearchChange(e.target.value)}
                placeholder="Tìm người dùng, tài liệu, IP…"
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
              <label htmlFor="soc-session-status-filter" className="sr-only">
                Lọc trạng thái phiên đọc
              </label>
              <Select
                id="soc-session-status-filter"
                value={statusFilter}
                onChange={(e) =>
                  onStatusChange(e.target.value as 'ACTIVE' | 'ALL' | 'ENDED' | 'TERMINATED')
                }
              >
                <option value="ACTIVE">Đang hoạt động ({activeCount})</option>
                <option value="ALL">Tất cả phiên ({totalCount})</option>
                <option value="ENDED">Đã kết thúc</option>
                <option value="TERMINATED">Đã ngắt cưỡng bức</option>
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
        {documentSessions.length === 0 ? (
          <div className="py-10 px-4 text-center text-xs text-[#717171]">
            <div className="flex flex-col items-center gap-2.5">
              <span>
                {searchQuery.trim()
                  ? 'Không tìm thấy phiên đọc tài liệu phù hợp với từ khóa tìm kiếm.'
                  : statusFilter === 'ACTIVE'
                    ? 'Hiện không có phiên đọc tài liệu nào đang hoạt động.'
                    : 'Không tìm thấy phiên đọc tài liệu phù hợp với bộ lọc.'}
              </span>
              <div className="flex flex-wrap justify-center gap-2">
                {statusFilter === 'ACTIVE' && totalCount > 0 && (
                  <InteractiveHoverButton
                    type="button"
                    size="sm"
                    variant="secondary"
                    text={`Xem toàn bộ lịch sử (${totalCount})`}
                    onClick={() => onStatusChange('ALL')}
                  />
                )}
                {hasFilters && (
                  <InteractiveHoverButton
                    type="button"
                    size="sm"
                    variant="secondary"
                    text="Đặt lại bộ lọc"
                    icon={<RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />}
                    onClick={() => {
                      onStatusChange('ACTIVE');
                      onSearchChange('');
                    }}
                  />
                )}
              </div>
            </div>
          </div>
        ) : (
          <>
            <div className="md:hidden divide-y divide-[#ebebeb]">
              {documentSessions.map((sess) => (
                <article key={sess.id} className="px-4 py-4 space-y-3 bg-[#ffffff]">
                  <div className="flex items-center justify-between gap-2">
                    <Badge variant={getStatusVariant(sess.status)}>
                      {formatSessionStatusLabel(sess.status)}
                    </Badge>
                    <span className="font-mono text-xs text-[#717171] truncate">
                      {sess.documentCode} · v{sess.versionNo}
                    </span>
                  </div>

                  <div className="space-y-0.5 min-w-0">
                    <h3 className="text-sm font-semibold text-[#222222] leading-snug break-words">
                      {sess.documentTitle}
                    </h3>
                    <p className="text-xs text-[#717171]">
                      {sess.fullName} (@{sess.username})
                    </p>
                  </div>

                  <div className="rounded-[12px] bg-[#f7f7f7] px-3 py-2 space-y-1.5 text-xs">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-[#717171] shrink-0">Địa chỉ IP</span>
                      <span className="font-mono text-[#222222] tabular-nums">
                        {sess.ipAddress}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-[#717171] shrink-0">Bắt đầu lúc</span>
                      <span className="text-[#717171] tabular-nums">
                        {formatSafeDateVi(sess.startedAt, { includeTime: true })}
                      </span>
                    </div>
                  </div>

                  {sess.terminatedReason && (
                    <p className="text-xs text-[#717171] break-words">
                      <strong className="text-[#222222]">Lý do ngắt:</strong>{' '}
                      {sess.terminatedReason}
                    </p>
                  )}

                  {sess.status === 'ACTIVE' && canTerminateSession && (
                    <div className="pt-0.5">
                      <InteractiveHoverButton
                        size="sm"
                        variant="destructive"
                        text="Ngắt phiên"
                        onClick={() => onTerminateSession(sess.id)}
                        isLoading={terminatingSessionId === sess.id}
                        className="w-full"
                      />
                    </div>
                  )}
                </article>
              ))}
            </div>

            <div className="hidden md:block">
              <Table>
                <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                  <TableRow>
                    <TableHead className="text-xs text-[#717171]">Tài liệu</TableHead>
                    <TableHead className="text-xs text-[#717171]">Người dùng</TableHead>
                    <TableHead className="text-xs text-[#717171]">Địa chỉ IP</TableHead>
                    <TableHead className="text-xs text-[#717171]">Bắt đầu lúc</TableHead>
                    <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                    <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {documentSessions.map((sess) => (
                    <TableRow
                      key={sess.id}
                      className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                    >
                      <TableCell className="font-semibold text-xs text-[#222222]">
                        <div>{sess.documentTitle}</div>
                        <div className="text-xs text-[#717171] font-normal">
                          {sess.documentCode} · v{sess.versionNo}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-[#222222]">
                        <div className="font-medium">{sess.fullName}</div>
                        <div className="text-xs text-[#717171]">{sess.username}</div>
                      </TableCell>
                      <TableCell className="text-xs font-mono text-[#717171]">
                        <div>{sess.ipAddress}</div>
                        {sess.userAgent && (
                          <div
                            className="font-sans text-xs text-[#717171] max-w-[180px] truncate"
                            title={sess.userAgent}
                          >
                            {sess.userAgent}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-xs text-[#717171] whitespace-nowrap">
                        {formatSafeDateVi(sess.startedAt, { includeTime: true })}
                      </TableCell>
                      <TableCell>
                        <Badge variant={getStatusVariant(sess.status)}>
                          {formatSessionStatusLabel(sess.status)}
                        </Badge>
                        {sess.terminatedReason && (
                          <div
                            className="text-xs text-[#717171] max-w-[200px] truncate mt-0.5"
                            title={sess.terminatedReason}
                          >
                            {sess.terminatedReason}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-right whitespace-nowrap">
                        {sess.status === 'ACTIVE' && canTerminateSession ? (
                          <InteractiveHoverButton
                            size="sm"
                            variant="destructive"
                            text="Ngắt phiên"
                            onClick={() => onTerminateSession(sess.id)}
                            isLoading={terminatingSessionId === sess.id}
                          />
                        ) : (
                          <span className="text-xs text-[#717171]">—</span>
                        )}
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
              Trang {page} / {totalPages} · Tổng {effectiveFilteredTotal} phiên
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

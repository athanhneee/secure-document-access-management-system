'use client';

import { AlertTriangle, ChevronLeft, ChevronRight, RotateCcw } from 'lucide-react';
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
import { formatSafeDateVi, formatSessionStatusLabel } from '@/lib/ui-labels';
import type { DocumentSessionItem } from '../types';

interface ActiveSessionsTabProps {
  documentSessions: DocumentSessionItem[];
  totalCount: number;
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
 * Thuật toán: Giám Sát Phiên Đọc Trực Tuyến & Lịch Sử Phiên Theo Trạng Thái (`ActiveSessionsTab`)
 * Mục đích: Khắc phục bộ đếm trùng nhau `N/N` bằng bộ lọc `ACTIVE`/`ALL`/`ENDED`/`TERMINATED` từ máy chủ kèm hiển thị `activeCount / totalCount` trung thực (#12, #14, #20, #38).
 */
export function ActiveSessionsTab({
  documentSessions,
  totalCount,
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
  const totalPages = Math.max(
    1,
    Math.ceil(Math.max(documentSessions.length, totalCount) / PAGE_SIZE),
  );
  const hasFilters = statusFilter !== 'ACTIVE' || searchQuery.trim() !== '';

  return (
    <Card>
      <CardHeader className="pb-3 space-y-3">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          <CardTitle className="text-sm sm:text-base text-[#222222]">
            Danh sách phiên đọc ({activeCount} đang hoạt động / {totalCount} tổng)
          </CardTitle>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 w-full lg:w-auto">
            <div>
              <label htmlFor="soc-session-search" className="sr-only">
                Tìm kiếm phiên đọc
              </label>
              <Input
                id="soc-session-search"
                value={searchQuery}
                onChange={(e) => onSearchChange(e.target.value)}
                placeholder="Tìm người dùng, tài liệu, IP…"
                className="min-h-11 sm:h-9 w-full rounded-full border-[#dddddd] bg-[#ffffff] text-xs placeholder:text-[#717171]"
              />
            </div>

            <div>
              <label htmlFor="soc-session-status-filter" className="sr-only">
                Lọc trạng thái phiên đọc
              </label>
              <select
                id="soc-session-status-filter"
                value={statusFilter}
                onChange={(e) =>
                  onStatusChange(e.target.value as 'ACTIVE' | 'ALL' | 'ENDED' | 'TERMINATED')
                }
                className="min-h-11 sm:h-9 w-full rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
              >
                <option value="ACTIVE">Đang hoạt động ({activeCount})</option>
                <option value="ALL">Tất cả phiên ({totalCount})</option>
                <option value="ENDED">Đã kết thúc</option>
                <option value="TERMINATED">Đã ngắt cưỡng bức</option>
              </select>
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
            {documentSessions.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-8 text-[#717171] text-xs">
                  <div className="flex flex-col items-center gap-2">
                    <span>
                      {statusFilter === 'ACTIVE'
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
                </TableCell>
              </TableRow>
            ) : (
              documentSessions.map((sess) => (
                <TableRow key={sess.id} className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60">
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
                    <Badge
                      variant={
                        sess.status === 'ACTIVE'
                          ? 'success'
                          : sess.status === 'TERMINATED'
                            ? 'destructive'
                            : 'neutral'
                      }
                    >
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
              ))
            )}
          </TableBody>
        </Table>

        {statusFilter !== 'ACTIVE' && totalPages > 1 && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#ebebeb] px-4 py-3 text-xs text-[#717171]">
            <span>
              Trang {page} / {totalPages}
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

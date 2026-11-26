'use client';

import { useEffect, useRef } from 'react';
import { Plus, AlertOctagon, ChevronLeft, ChevronRight, RefreshCw } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
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
  formatGrantStatusLabel,
  formatPrincipalTypeLabel,
  formatSafeDateVi,
} from '@/lib/ui-labels';
import { formatGrantPermissionSummary } from '../grant-helpers';
import type { AccessGrantItem, GrantStatusFilter } from '../types';

interface GrantsTabProps {
  grants: AccessGrantItem[];
  activeGrantCount: number;
  grantsPage: number;
  grantsHasMore: boolean;
  grantsStatusFilter: GrantStatusFilter;
  isLoadingGrants: boolean;
  canCreateGrant?: boolean;
  canRevokeGrant?: boolean;
  onChangeStatusFilter: (status: GrantStatusFilter) => void;
  onLoadPage: (page: number) => void;
  onOpenDirectGrant: () => void;
  onOpenRevoke: (grant: AccessGrantItem) => void;
}

const GRANT_STATUS_FILTER_OPTIONS: ReadonlyArray<{ value: GrantStatusFilter; label: string }> = [
  { value: 'ALL', label: 'Tất cả' },
  { value: 'ACTIVE', label: 'Đang hiệu lực' },
  { value: 'SUSPENDED', label: 'Tạm ngưng' },
  { value: 'REVOKED', label: 'Đã thu hồi' },
  { value: 'EXPIRED', label: 'Đã hết hạn' },
];

/**
 * Thuật toán: Bảng Quản Lý Quyền Truy Cập Có Lọc Trạng Thái, Phân Trang Máy Chủ & Thẻ Di Động `375px` (`GrantsTab`)
 * Mục đích:
 *   - Hiển thị rõ số quyền đang hiệu lực đồng bộ với nhãn Tab và tổng số bản ghi đang xem.
 *   - Hợp nhất nhãn quyền hạn đơn nhất (`Chỉ xem` hoặc `Xem & Tải về`), hiển thị đầy đủ ngày giờ hiệu lực và thứ bậc chữ chuẩn.
 *   - Hỗ trợ lọc trạng thái (`ALL`/`ACTIVE`/`REVOKED`/`EXPIRED`), phân trang máy chủ và giao diện thẻ gọn gàng trên di động `375px`.
 */
export function GrantsTab({
  grants,
  activeGrantCount,
  grantsPage,
  grantsHasMore,
  grantsStatusFilter,
  isLoadingGrants,
  canCreateGrant = true,
  canRevokeGrant = true,
  onChangeStatusFilter,
  onLoadPage,
  onOpenDirectGrant,
  onOpenRevoke,
}: GrantsTabProps) {
  const tableScrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    tableScrollRef.current?.scrollTo({ top: 0 });
  }, [grantsPage, grantsStatusFilter]);

  function resolveStatusBadgeVariant(status: AccessGrantItem['status']) {
    if (status === 'ACTIVE') return 'success' as const;
    if (status === 'EXPIRED' || status === 'SUSPENDED') return 'warning' as const;
    return 'destructive' as const;
  }

  return (
    <Card>
      <CardHeader className="p-4 sm:p-5 pb-3.5 border-b border-[#ebebeb] space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="min-w-0">
            <CardTitle className="text-sm sm:text-base text-[#222222]">
              Quyền truy cập đã cấp ({activeGrantCount} đang hiệu lực)
            </CardTitle>
            <p className="text-xs text-[#717171] mt-0.5">
              Hiển thị {grants.length} bản ghi trên trang {grantsPage}.
            </p>
          </div>
          {canCreateGrant && (
            <InteractiveHoverButton
              variant="primary"
              size="sm"
              text="Cấp quyền trực tiếp"
              icon={<Plus size={16} strokeWidth={2} aria-hidden="true" />}
              onClick={onOpenDirectGrant}
              className="w-full sm:w-auto shrink-0"
            />
          )}
        </div>

        <fieldset
          aria-label="Lọc trạng thái quyền truy cập"
          className="border-0 p-0 m-0 min-w-0 flex overflow-x-auto no-scrollbar sm:flex-wrap items-center gap-1.5"
        >
          {GRANT_STATUS_FILTER_OPTIONS.map((option) => {
            const isSelected = grantsStatusFilter === option.value;
            return (
              <button
                key={option.value}
                type="button"
                aria-pressed={isSelected}
                disabled={isLoadingGrants}
                onClick={() => onChangeStatusFilter(option.value)}
                className={`shrink-0 min-h-11 sm:min-h-9 px-3.5 py-1.5 rounded-full border text-xs font-semibold transition-colors cursor-pointer disabled:opacity-60 whitespace-nowrap ${
                  isSelected
                    ? 'border-transparent bg-[#FF385C] text-[#ffffff]'
                    : 'border-[#dddddd] bg-[#ffffff] text-[#222222] hover:border-[#222222]'
                }`}
              >
                {option.label}
              </button>
            );
          })}
        </fieldset>
      </CardHeader>

      <CardContent className="p-0">
        {isLoadingGrants ? (
          <div className="py-10 flex flex-col items-center justify-center gap-2 text-xs text-[#717171]">
            <RefreshCw
              size={20}
              strokeWidth={1.75}
              className="animate-spin text-[#FF385C]"
              aria-hidden="true"
            />
            <span>Đang tải danh sách quyền truy cập…</span>
          </div>
        ) : grants.length === 0 ? (
          <div className="py-10 px-4 text-center text-xs text-[#717171]">
            {grantsStatusFilter === 'ALL'
              ? 'Chưa có quyền truy cập nào được cấp.'
              : 'Không có quyền truy cập nào phù hợp với trạng thái đang lọc.'}
          </div>
        ) : (
          <>
            <div className="md:hidden divide-y divide-[#ebebeb]">
              {grants.map((grant) => {
                const permissionSummary = formatGrantPermissionSummary(grant.permissions);
                return (
                  <article key={grant.id} className="px-4 py-4 space-y-3 bg-[#ffffff]">
                    <div className="flex items-center justify-between gap-2">
                      <Badge variant={resolveStatusBadgeVariant(grant.status)} className="text-xs">
                        {formatGrantStatusLabel(grant.status)}
                      </Badge>
                      <Badge
                        variant={permissionSummary.includesDownload ? 'info' : 'secondary'}
                        className="text-xs"
                      >
                        {permissionSummary.label}
                      </Badge>
                    </div>

                    <div className="space-y-0.5 min-w-0">
                      <h3 className="text-sm font-semibold text-[#222222] leading-snug break-words">
                        {grant.documentTitle}
                      </h3>
                      <p className="text-xs text-[#717171]">
                        {grant.principalName} · {formatPrincipalTypeLabel(grant.principalType)}
                      </p>
                    </div>

                    <div className="rounded-[12px] bg-[#f7f7f7] px-3 py-2 space-y-1.5 text-xs tabular-nums">
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-[#717171] shrink-0">Hiệu lực từ</span>
                        <span className="font-medium text-[#222222]">
                          {formatSafeDateVi(grant.validFrom, { includeTime: true })}
                        </span>
                      </div>
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-[#717171] shrink-0">Hiệu lực đến</span>
                        <span className="font-semibold text-[#222222]">
                          {formatSafeDateVi(grant.validUntil, { includeTime: true })}
                        </span>
                      </div>
                    </div>

                    {(grant.status === 'ACTIVE' || grant.status === 'SUSPENDED') &&
                      canRevokeGrant && (
                        <div className="pt-0.5">
                          <InteractiveHoverButton
                            size="sm"
                            variant="danger"
                            text="Thu hồi"
                            icon={<AlertOctagon size={16} strokeWidth={2} aria-hidden="true" />}
                            onClick={() => onOpenRevoke(grant)}
                            className="w-full"
                          />
                        </div>
                      )}
                  </article>
                );
              })}
            </div>

            <div className="hidden md:block">
              <Table containerRef={tableScrollRef} className="min-w-[760px]">
                <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                  <TableRow>
                    <TableHead className="text-xs text-[#717171]">Đối tượng được cấp</TableHead>
                    <TableHead className="text-xs text-[#717171]">Tài liệu</TableHead>
                    <TableHead className="text-xs text-[#717171]">Quyền hạn</TableHead>
                    <TableHead className="text-xs text-[#717171]">Thời hạn hiệu lực</TableHead>
                    <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                    <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {grants.map((grant) => {
                    const permissionSummary = formatGrantPermissionSummary(grant.permissions);
                    return (
                      <TableRow
                        key={grant.id}
                        className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                      >
                        <TableCell>
                          <div className="text-xs font-semibold text-[#222222]">
                            {grant.principalName}
                          </div>
                          <div className="text-[11px] font-medium text-[#717171] mt-0.5">
                            {formatPrincipalTypeLabel(grant.principalType)}
                          </div>
                        </TableCell>
                        <TableCell
                          title={grant.documentTitle}
                          className="text-xs text-[#222222] max-w-xs truncate"
                        >
                          {grant.documentTitle}
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          <Badge
                            variant={permissionSummary.includesDownload ? 'info' : 'secondary'}
                            className="text-xs"
                          >
                            {permissionSummary.label}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs whitespace-nowrap tabular-nums">
                          <div className="text-[#222222]">
                            <span className="font-medium text-[#717171]">Từ: </span>
                            <span className="font-semibold">
                              {formatSafeDateVi(grant.validFrom, { includeTime: true })}
                            </span>
                          </div>
                          <div className="text-[#717171] mt-0.5">
                            <span className="font-medium">Đến: </span>
                            <span className="font-semibold">
                              {formatSafeDateVi(grant.validUntil, { includeTime: true })}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          <Badge
                            variant={resolveStatusBadgeVariant(grant.status)}
                            className="text-xs"
                          >
                            {formatGrantStatusLabel(grant.status)}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right whitespace-nowrap">
                          {(grant.status === 'ACTIVE' || grant.status === 'SUSPENDED') &&
                            canRevokeGrant && (
                              <InteractiveHoverButton
                                size="sm"
                                variant="danger"
                                text="Thu hồi"
                                icon={<AlertOctagon size={16} strokeWidth={2} aria-hidden="true" />}
                                onClick={() => onOpenRevoke(grant)}
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

        <div className="px-4 py-2.5 border-t border-[#ebebeb] bg-[#f7f7f7]/60 flex flex-wrap items-center justify-between gap-2 text-xs text-[#717171]">
          <span>
            Đang hiển thị <strong className="text-[#222222]">{grants.length}</strong> bản ghi
          </span>
          <div className="flex items-center gap-2">
            <InteractiveHoverButton
              variant="secondary"
              size="sm"
              text="Trang trước"
              icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
              disabled={grantsPage <= 1 || isLoadingGrants}
              onClick={() => onLoadPage(grantsPage - 1)}
            />
            <span className="font-semibold text-[#222222] whitespace-nowrap tabular-nums">
              Trang {grantsPage}
            </span>
            <InteractiveHoverButton
              variant="secondary"
              size="sm"
              text="Trang sau"
              icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
              disabled={!grantsHasMore || isLoadingGrants}
              onClick={() => onLoadPage(grantsPage + 1)}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

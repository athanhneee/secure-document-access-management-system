'use client';

import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  FileCheck,
  FileSearch,
  RotateCcw,
} from 'lucide-react';
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
import { formatIncidentStatusLabel } from '@/lib/ui-labels';
import type { IncidentItem } from '../types';

interface IncidentsTabProps {
  incidents: IncidentItem[];
  total: number;
  page: number;
  statusFilter: string;
  searchQuery: string;
  tabError?: string | null | undefined;
  canCreateIncident?: boolean;
  onStatusChange: (value: string) => void;
  onSearchChange: (value: string) => void;
  onPageChange: (page: number) => void;
  onOpenCreateIncident: () => void;
  onSelectIncident: (incident: IncidentItem) => void;
}

const PAGE_SIZE = 20;

/**
 * Thuật toán: Theo Dõi Vòng Đời Hồ Sơ Sự Cố Có Lọc & Phân Trang Phía Máy Chủ (`IncidentsTab`)
 * Mục đích: Hiển thị tiến độ hoàn thành Corrective Actions, trạng thái 4 bước (`DRAFT`/`SUBMITTED`/`IN_REVIEW`/`CLOSED`) và phân trang thực `meta.total` (#13, #29, #33, #60).
 */
export function IncidentsTab({
  incidents,
  total,
  page,
  statusFilter,
  searchQuery,
  tabError,
  canCreateIncident = true,
  onStatusChange,
  onSearchChange,
  onPageChange,
  onOpenCreateIncident,
  onSelectIncident,
}: IncidentsTabProps) {
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const hasFilters = statusFilter !== 'ALL' || searchQuery.trim() !== '';

  return (
    <Card>
      <CardHeader className="pb-3 space-y-3">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          <CardTitle className="text-sm sm:text-base text-[#222222]">
            Hồ sơ sự cố an ninh ({total})
          </CardTitle>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
            <div>
              <label htmlFor="soc-incident-search" className="sr-only">
                Tìm kiếm hồ sơ sự cố
              </label>
              <Input
                id="soc-incident-search"
                value={searchQuery}
                onChange={(e) => onSearchChange(e.target.value)}
                placeholder="Tìm mã sự cố, tiêu đề…"
                className="min-h-11 sm:h-9 w-full sm:w-48 rounded-full border-[#dddddd] bg-[#ffffff] text-xs placeholder:text-[#717171]"
              />
            </div>

            <div>
              <label htmlFor="soc-incident-status-filter" className="sr-only">
                Lọc trạng thái sự cố
              </label>
              <select
                id="soc-incident-status-filter"
                value={statusFilter}
                onChange={(e) => onStatusChange(e.target.value)}
                className="min-h-11 sm:h-9 w-full sm:w-44 rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
              >
                <option value="ALL">Mọi trạng thái</option>
                <option value="DRAFT">Bản nháp</option>
                <option value="SUBMITTED">Chờ phê duyệt</option>
                <option value="IN_REVIEW">Đang xem xét</option>
                <option value="CLOSED">Đã đóng</option>
              </select>
            </div>

            {canCreateIncident && (
              <InteractiveHoverButton
                size="sm"
                variant="primary"
                text="Tạo hồ sơ mới"
                icon={<FileCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={onOpenCreateIncident}
                className="shrink-0"
              />
            )}
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
              <TableHead className="text-xs text-[#717171]">Tiêu đề sự cố</TableHead>
              <TableHead className="text-xs text-[#717171]">Tóm tắt diễn biến</TableHead>
              <TableHead className="text-xs text-[#717171]">Hành động khắc phục</TableHead>
              <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
              <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {incidents.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8 text-[#717171] text-xs">
                  <div className="flex flex-col items-center gap-2">
                    <span>
                      {hasFilters
                        ? 'Không tìm thấy hồ sơ sự cố khớp với bộ lọc hiện tại.'
                        : 'Chưa có hồ sơ sự cố an ninh nào được tạo.'}
                    </span>
                    {hasFilters && (
                      <InteractiveHoverButton
                        type="button"
                        size="sm"
                        variant="secondary"
                        text="Xóa bộ lọc"
                        icon={<RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />}
                        onClick={() => {
                          onStatusChange('ALL');
                          onSearchChange('');
                        }}
                      />
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ) : (
              incidents.map((inc) => (
                <TableRow key={inc.id} className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60">
                  <TableCell className="font-semibold text-xs text-[#222222]">
                    <div>{inc.title}</div>
                    {inc.incidentCode && (
                      <div className="text-xs font-mono font-normal text-[#717171]">
                        {inc.incidentCode}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="text-xs text-[#222222] max-w-sm truncate">
                    {inc.summary}
                  </TableCell>
                  <TableCell className="text-xs text-[#222222]">
                    {inc.actions && inc.actions.length > 0 ? (
                      <span className="text-[#008A05] font-medium">
                        {
                          inc.actions.filter(
                            (a) => Boolean(a.completedAt) || Boolean(a.isCompleted),
                          ).length
                        }
                        /{inc.actions.length} hoàn tất
                      </span>
                    ) : (
                      <span className="text-[#717171]">Chưa có hành động</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        inc.status === 'CLOSED'
                          ? 'success'
                          : inc.status === 'DRAFT'
                            ? 'warning'
                            : 'info'
                      }
                    >
                      {formatIncidentStatusLabel(inc.status)}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap">
                    <InteractiveHoverButton
                      size="sm"
                      variant="secondary"
                      text="Chi tiết"
                      icon={<FileSearch size={16} strokeWidth={1.75} aria-hidden="true" />}
                      onClick={() => onSelectIncident(inc)}
                    />
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>

        {totalPages > 1 && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#ebebeb] px-4 py-3 text-xs text-[#717171]">
            <span>
              Trang {page} / {totalPages} · Tổng {total} hồ sơ sự cố
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

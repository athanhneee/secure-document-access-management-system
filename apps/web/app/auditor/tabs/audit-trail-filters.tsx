'use client';

import { ArrowUpDown, RotateCcw, Search, User } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { formatAuditPartitionLabel } from '@/lib/ui-labels';
import { AUDIT_PARTITION_OPTIONS } from '../helpers';

interface AuditTrailFiltersBarProps {
  outcomeFilter: string;
  actionFilter: string;
  partitionFilter: string;
  actorFilter: string;
  fromDate: string;
  toDate: string;
  sortOrder: 'desc' | 'asc';
  dateRangeError: string | null;
  onOutcomeFilterChange: (value: string) => void;
  onActionFilterChange: (value: string) => void;
  onPartitionFilterChange: (value: string) => void;
  onActorFilterChange: (value: string) => void;
  onFromDateChange: (value: string) => void;
  onToDateChange: (value: string) => void;
  onSortOrderChange: (value: 'desc' | 'asc') => void;
  onResetFilters: () => void;
}

/**
 * Thuật toán: Thanh Lọc Đa Chiều Nhật Ký Kiểm Toán Tối Ưu Mobile 375px & Kiểm Định Khoảng Ngày (`AuditTrailFiltersBar`)
 * Mục đích: Cung cấp đầy đủ bộ lọc kết quả, phân vùng, hành động (chuỗi con không phân biệt hoa/thường), người thực hiện, khoảng ngày và sắp xếp, kèm nút đặt lại nhanh khi có bộ lọc đang áp dụng.
 */
export function AuditTrailFiltersBar({
  outcomeFilter,
  actionFilter,
  partitionFilter,
  actorFilter,
  fromDate,
  toDate,
  sortOrder,
  dateRangeError,
  onOutcomeFilterChange,
  onActionFilterChange,
  onPartitionFilterChange,
  onActorFilterChange,
  onFromDateChange,
  onToDateChange,
  onSortOrderChange,
  onResetFilters,
}: AuditTrailFiltersBarProps) {
  const hasActiveFilters =
    outcomeFilter !== 'ALL' ||
    partitionFilter !== 'ALL' ||
    actionFilter.trim() !== '' ||
    actorFilter.trim() !== '' ||
    fromDate !== '' ||
    toDate !== '' ||
    sortOrder !== 'desc';

  return (
    <div className="space-y-2">
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-2 min-w-0">
        <div className="min-w-0">
          <label htmlFor="auditor-outcome-filter" className="sr-only">
            Lọc theo kết quả kiểm toán
          </label>
          <Select
            id="auditor-outcome-filter"
            value={outcomeFilter}
            onChange={(e) => onOutcomeFilterChange(e.target.value)}
          >
            <option value="ALL">Tất cả kết quả</option>
            <option value="SUCCESS">Thành công</option>
            <option value="DENIED">Bị từ chối</option>
            <option value="FAILED">Thất bại</option>
          </Select>
        </div>

        <div className="min-w-0">
          <label htmlFor="auditor-partition-filter" className="sr-only">
            Lọc theo phân vùng kiểm toán
          </label>
          <Select
            id="auditor-partition-filter"
            value={partitionFilter}
            onChange={(e) => onPartitionFilterChange(e.target.value)}
          >
            <option value="ALL">Tất cả phân vùng</option>
            {AUDIT_PARTITION_OPTIONS.filter((p) => p !== 'ALL').map((partition) => (
              <option key={partition} value={partition}>
                {formatAuditPartitionLabel(partition)}
              </option>
            ))}
          </Select>
        </div>

        <div className="relative col-span-2 sm:col-span-1 min-w-0">
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
            maxLength={120}
            placeholder="Mã hành động (VD: LOGIN)…"
            value={actionFilter}
            onChange={(e) => onActionFilterChange(e.target.value)}
            className="pl-10 h-11 sm:h-9 w-full rounded-[12px] sm:rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#717171]"
          />
        </div>

        <div className="relative col-span-2 sm:col-span-1 min-w-0">
          <label htmlFor="auditor-actor-filter" className="sr-only">
            Lọc theo tên tài khoản thực hiện
          </label>
          <User
            size={16}
            strokeWidth={1.75}
            className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-[#717171]"
            aria-hidden="true"
          />
          <Input
            id="auditor-actor-filter"
            type="text"
            maxLength={120}
            placeholder="Tài khoản thực hiện…"
            value={actorFilter}
            onChange={(e) => onActorFilterChange(e.target.value)}
            className="pl-10 h-11 sm:h-9 w-full rounded-[12px] sm:rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#717171]"
          />
        </div>

        <div className="col-span-2 sm:col-span-1 min-w-0">
          <label
            htmlFor="auditor-from-date"
            className="block text-[11px] font-medium text-[#717171] mb-1"
          >
            Từ ngày
          </label>
          <Input
            id="auditor-from-date"
            type="date"
            value={fromDate}
            aria-invalid={Boolean(dateRangeError)}
            onChange={(e) => onFromDateChange(e.target.value)}
            className="h-11 sm:h-9 w-full rounded-[12px] sm:rounded-full bg-[#ffffff] border-[#dddddd] px-3 text-[#222222]"
          />
        </div>

        <div className="col-span-2 sm:col-span-1 min-w-0">
          <label
            htmlFor="auditor-to-date"
            className="block text-[11px] font-medium text-[#717171] mb-1"
          >
            Đến ngày
          </label>
          <Input
            id="auditor-to-date"
            type="date"
            value={toDate}
            aria-invalid={Boolean(dateRangeError)}
            onChange={(e) => onToDateChange(e.target.value)}
            className="h-11 sm:h-9 w-full rounded-[12px] sm:rounded-full bg-[#ffffff] border-[#dddddd] px-3 text-[#222222]"
          />
        </div>
      </div>

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-2 w-full sm:w-auto min-w-0">
          <ArrowUpDown
            size={16}
            strokeWidth={1.75}
            className="shrink-0 text-[#717171]"
            aria-hidden="true"
          />
          <label htmlFor="auditor-sort-order" className="sr-only">
            Thứ tự sắp xếp nhật ký
          </label>
          <Select
            id="auditor-sort-order"
            value={sortOrder}
            onChange={(e) => onSortOrderChange(e.target.value === 'asc' ? 'asc' : 'desc')}
            wrapperClassName="w-full sm:w-52"
          >
            <option value="desc">Thời gian: Mới nhất trước</option>
            <option value="asc">Thời gian: Cũ nhất trước</option>
          </Select>
        </div>

        {hasActiveFilters && (
          <InteractiveHoverButton
            type="button"
            variant="secondary"
            size="sm"
            text="Xóa bộ lọc"
            icon={<RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={onResetFilters}
            className="w-full sm:w-auto"
          />
        )}
      </div>

      {dateRangeError && (
        <p role="alert" className="text-xs font-medium text-[#C13515]">
          {dateRangeError}
        </p>
      )}
    </div>
  );
}

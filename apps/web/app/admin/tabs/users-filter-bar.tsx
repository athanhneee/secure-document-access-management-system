'use client';

import { RotateCcw, Search, X } from 'lucide-react';
import { CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import {
  formatUserSortOption,
  parseUserSortOption,
  UNASSIGNED_DEPARTMENT_LABEL,
  USER_SORT_OPTIONS,
  type UserActionFilter,
  type UserFilterFacets,
  type UserListQueryState,
  type UserStatusFilter,
} from '../users-query';

interface UsersFilterBarProps {
  totalLoadedCount: number;
  serverTotalCount?: number | null | undefined;
  displayedCount: number;
  filtersActive: boolean;
  canResetQuery: boolean;
  facets: UserFilterFacets;
  query: UserListQueryState;
  onUpdateQuery: (patch: Partial<UserListQueryState>) => void;
  onResetQuery: () => void;
}

/**
 * Thuật toán: Thanh Bộ Lọc Đa Chiều & Tìm Kiếm Tức Thì Cho Quản Trị Danh Tính (`UsersFilterBar`)
 * Tách riêng khỏi `UsersTab` để giữ mỗi mô-đun gọn gàng (< 300 dòng) và bảo toàn tiêu điểm ô nhập tiếng Việt Telex/VNI.
 */
export function UsersFilterBar({
  totalLoadedCount,
  serverTotalCount,
  displayedCount,
  filtersActive,
  canResetQuery,
  facets,
  query,
  onUpdateQuery,
  onResetQuery,
}: UsersFilterBarProps) {
  const sortSelectValue = formatUserSortOption(query.sortField, query.sortDirection);
  const effectiveTotal =
    typeof serverTotalCount === 'number' && serverTotalCount > totalLoadedCount
      ? serverTotalCount
      : totalLoadedCount;

  return (
    <CardHeader className="p-4 sm:p-5 pb-3.5 border-b border-[#ebebeb] space-y-3">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <CardTitle className="text-sm sm:text-base text-[#222222]">
          Danh sách tài khoản (
          {filtersActive ? `${displayedCount} / ${effectiveTotal}` : effectiveTotal})
        </CardTitle>

        <div className="relative w-full sm:w-72 shrink-0">
          <label htmlFor="admin-users-search" className="sr-only">
            Tìm kiếm tài khoản người dùng
          </label>
          <Search
            size={16}
            strokeWidth={1.75}
            className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-[#717171]"
            aria-hidden="true"
          />
          <Input
            id="admin-users-search"
            type="text"
            placeholder="Tìm theo họ tên, tên đăng nhập, email…"
            value={query.searchQuery}
            onChange={(e) => onUpdateQuery({ searchQuery: e.target.value })}
            className={`pl-10 ${query.searchQuery ? 'pr-10' : ''} h-11 sm:h-9 rounded-[12px] sm:rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#222222]`}
          />
          {query.searchQuery && (
            <button
              type="button"
              onClick={() => onUpdateQuery({ searchQuery: '' })}
              aria-label="Xóa từ khóa tìm kiếm"
              className="absolute right-1 top-1/2 -translate-y-1/2 flex h-11 w-11 sm:h-7 sm:w-7 items-center justify-center rounded-full text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] cursor-pointer"
            >
              <X size={16} strokeWidth={2} aria-hidden="true" />
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 sm:flex sm:flex-wrap items-stretch sm:items-center gap-2 pt-2.5 border-t border-[#ebebeb]">
        <div className="w-full sm:w-auto min-w-0">
          <label htmlFor="admin-users-status-filter" className="sr-only">
            Lọc theo trạng thái tài khoản
          </label>
          <Select
            id="admin-users-status-filter"
            value={query.statusFilter}
            onChange={(e) => onUpdateQuery({ statusFilter: e.target.value as UserStatusFilter })}
            className={query.statusFilter !== 'ALL' ? 'border-[#222222] font-semibold' : undefined}
          >
            <option value="ALL">Tất cả trạng thái ({totalLoadedCount})</option>
            <option value="ACTIVE">Đang hoạt động ({facets.statusCounts.ACTIVE})</option>
            <option value="LOCKED">Tạm khóa ({facets.statusCounts.LOCKED})</option>
            <option value="DISABLED">Vô hiệu hóa ({facets.statusCounts.DISABLED})</option>
            {(facets.statusCounts.PENDING > 0 || query.statusFilter === 'PENDING') && (
              <option value="PENDING">Chờ kích hoạt ({facets.statusCounts.PENDING})</option>
            )}
          </Select>
        </div>

        <div className="w-full sm:w-auto min-w-0">
          <label htmlFor="admin-users-department-filter" className="sr-only">
            Lọc theo phòng ban
          </label>
          <Select
            id="admin-users-department-filter"
            value={query.departmentFilter}
            onChange={(e) => onUpdateQuery({ departmentFilter: e.target.value })}
            className={
              query.departmentFilter !== 'ALL' ? 'border-[#222222] font-semibold' : undefined
            }
          >
            <option value="ALL">Tất cả phòng ban</option>
            {facets.departmentOptions.map((dept) => (
              <option key={dept.id} value={dept.id}>
                {dept.name} ({dept.count})
              </option>
            ))}
            <option value="UNASSIGNED">
              {UNASSIGNED_DEPARTMENT_LABEL} ({facets.unassignedDepartmentCount})
            </option>
          </Select>
        </div>

        <div className="w-full sm:w-auto min-w-0">
          <label htmlFor="admin-users-action-filter" className="sr-only">
            Lọc theo thao tác khả dụng
          </label>
          <Select
            id="admin-users-action-filter"
            value={query.actionFilter}
            onChange={(e) => onUpdateQuery({ actionFilter: e.target.value as UserActionFilter })}
            className={query.actionFilter !== 'ALL' ? 'border-[#222222] font-semibold' : undefined}
          >
            <option value="ALL">Tất cả thao tác</option>
            <option value="DISABLE">Thao tác: Vô hiệu hóa ({facets.actionCounts.DISABLE})</option>
            <option value="LOCK">Thao tác: Khóa ({facets.actionCounts.LOCK})</option>
            <option value="UNLOCK">Thao tác: Mở khóa ({facets.actionCounts.UNLOCK})</option>
            <option value="REACTIVATE">
              Thao tác: Kích hoạt ({facets.actionCounts.REACTIVATE})
            </option>
          </Select>
        </div>

        <div className="w-full sm:w-auto sm:ml-auto min-w-0">
          <label htmlFor="admin-users-sort" className="sr-only">
            Sắp xếp danh sách tài khoản
          </label>
          <Select
            id="admin-users-sort"
            value={sortSelectValue}
            onChange={(e) => onUpdateQuery(parseUserSortOption(e.target.value))}
          >
            {USER_SORT_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                Sắp xếp · {opt.label}
              </option>
            ))}
          </Select>
        </div>

        {canResetQuery && (
          <button
            type="button"
            onClick={onResetQuery}
            className="inline-flex min-h-11 sm:h-9 w-full sm:w-auto items-center justify-center gap-1.5 rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs font-medium text-[#717171] hover:border-[#222222] hover:text-[#222222] transition-colors cursor-pointer shrink-0"
          >
            <RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />
            <span>Đặt lại</span>
          </button>
        )}
      </div>
    </CardHeader>
  );
}

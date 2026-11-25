'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Ban,
  Key,
  Lock,
  Pencil,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Unlock,
} from 'lucide-react';
import { ClassificationBadge } from '@/components/classification-badge';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
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
import {
  buildDepartmentNameMap,
  computeUserFilterFacets,
  DEFAULT_USER_LIST_QUERY,
  filterAndSortUsers,
  formatUserSortOption,
  hasActiveUserFilters,
  isNonDefaultUserQuery,
  parseUserSortOption,
  resolveUserDepartmentName,
  toggleUserSort,
  UNASSIGNED_DEPARTMENT_LABEL,
  USER_SORT_OPTIONS,
  type UserActionFilter,
  type UserListQueryState,
  type UserSortField,
  type UserStatusFilter,
} from '../users-query';
import type { DepartmentRow, UserRow, UserStatusAction } from '../types';

interface UsersTabProps {
  users: UserRow[];
  departments: DepartmentRow[];
  query: UserListQueryState;
  onQueryChange: (nextQuery: UserListQueryState) => void;
  onOpenEditUser: (user: UserRow) => void;
  onOpenUpdateClearance: (user: UserRow) => void;
  onOpenAssignRole: (user: UserRow) => void;
  onChangeStatus: (user: UserRow, action: UserStatusAction) => Promise<boolean>;
  onClearError: () => void;
}

const SELECT_BASE_CLASS =
  'min-h-11 sm:h-9 w-full sm:w-auto min-w-0 max-w-full rounded-full border bg-[#ffffff] px-3.5 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer transition-colors';

/**
 * Thuật toán: Bảng Quản Lý Danh Tính Có Bộ Lọc Đa Chiều & Sắp Xếp Cột (`UsersTab`)
 * Mục đích: Kết hợp lọc tức thời theo trạng thái, phòng ban, thao tác khả dụng và tìm kiếm đa trường; hỗ trợ sắp xếp hai chiều ngay trên tiêu đề cột lẫn bộ chọn sắp xếp.
 */
export function UsersTab({
  users,
  departments,
  query,
  onQueryChange,
  onOpenEditUser,
  onOpenUpdateClearance,
  onOpenAssignRole,
  onChangeStatus,
  onClearError,
}: UsersTabProps) {
  const [pendingAction, setPendingAction] = useState<{
    user: UserRow;
    action: 'lock' | 'disable';
  } | null>(null);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [unlockingUserId, setUnlockingUserId] = useState<string | null>(null);
  const tableScrollRef = useRef<HTMLDivElement | null>(null);

  const departmentNamesById = useMemo(() => buildDepartmentNameMap(departments), [departments]);
  const facets = useMemo(() => computeUserFilterFacets(users, departments), [users, departments]);
  const displayedUsers = useMemo(
    () => filterAndSortUsers(users, departments, query),
    [users, departments, query],
  );

  const filtersActive = hasActiveUserFilters(query);
  const canResetQuery = isNonDefaultUserQuery(query);
  const sortSelectValue = formatUserSortOption(query.sortField, query.sortDirection);

  useEffect(() => {
    tableScrollRef.current?.scrollTo({ top: 0 });
  }, [
    query.searchQuery,
    query.statusFilter,
    query.departmentFilter,
    query.actionFilter,
    query.sortField,
    query.sortDirection,
  ]);

  function updateQuery(patch: Partial<UserListQueryState>) {
    onQueryChange({ ...query, ...patch });
  }

  function handleHeaderSort(field: UserSortField) {
    const nextSort = toggleUserSort(query.sortField, query.sortDirection, field);
    updateQuery(nextSort);
  }

  function handleResetQuery() {
    onQueryChange({ ...DEFAULT_USER_LIST_QUERY });
  }

  function getAriaSort(field: UserSortField): 'ascending' | 'descending' | 'none' {
    if (query.sortField !== field) return 'none';
    return query.sortDirection === 'asc' ? 'ascending' : 'descending';
  }

  function renderSortIcon(field: UserSortField) {
    if (query.sortField !== field) {
      return (
        <ArrowUpDown
          size={16}
          strokeWidth={1.75}
          className="shrink-0 text-[#b0b0b0]"
          aria-hidden="true"
        />
      );
    }
    return query.sortDirection === 'asc' ? (
      <ArrowUp
        size={16}
        strokeWidth={1.75}
        className="shrink-0 text-[#FF385C]"
        aria-hidden="true"
      />
    ) : (
      <ArrowDown
        size={16}
        strokeWidth={1.75}
        className="shrink-0 text-[#FF385C]"
        aria-hidden="true"
      />
    );
  }

  async function handleDirectUnlock(user: UserRow) {
    setUnlockingUserId(user.id);
    try {
      await onChangeStatus(user, 'unlock');
    } finally {
      setUnlockingUserId(null);
    }
  }

  return (
    <>
      <Card>
        <CardHeader className="pb-3 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <CardTitle className="text-sm sm:text-base text-[#222222]">
              Danh sách tài khoản (
              {filtersActive ? `${displayedUsers.length} / ${users.length}` : displayedUsers.length}
              )
            </CardTitle>

            <div className="relative w-full sm:w-72 shrink-0">
              <label htmlFor="admin-users-search" className="sr-only">
                Tìm kiếm tài khoản người dùng
              </label>
              <Search
                size={16}
                strokeWidth={1.75}
                className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#717171]"
                aria-hidden="true"
              />
              <Input
                id="admin-users-search"
                type="text"
                placeholder="Tìm tên, username, email, mã NV..."
                value={query.searchQuery}
                onChange={(e) => updateQuery({ searchQuery: e.target.value })}
                className="pl-9 min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
              />
            </div>
          </div>

          <div className="flex flex-col sm:flex-row sm:flex-wrap items-stretch sm:items-center gap-2 pt-2.5 border-t border-[#ebebeb]">
            <div className="w-full sm:w-auto min-w-0">
              <label htmlFor="admin-users-status-filter" className="sr-only">
                Lọc theo trạng thái tài khoản
              </label>
              <select
                id="admin-users-status-filter"
                value={query.statusFilter}
                onChange={(e) => updateQuery({ statusFilter: e.target.value as UserStatusFilter })}
                className={`${SELECT_BASE_CLASS} ${
                  query.statusFilter !== 'ALL'
                    ? 'border-[#222222] font-semibold'
                    : 'border-[#dddddd]'
                }`}
              >
                <option value="ALL">Tất cả trạng thái ({users.length})</option>
                <option value="ACTIVE">ACTIVE · Hoạt động ({facets.statusCounts.ACTIVE})</option>
                <option value="LOCKED">LOCKED · Đang khóa ({facets.statusCounts.LOCKED})</option>
                <option value="DISABLED">
                  DISABLED · Đã vô hiệu ({facets.statusCounts.DISABLED})
                </option>
                {(facets.statusCounts.PENDING > 0 || query.statusFilter === 'PENDING') && (
                  <option value="PENDING">
                    PENDING · Chờ kích hoạt ({facets.statusCounts.PENDING})
                  </option>
                )}
              </select>
            </div>

            <div className="w-full sm:w-auto min-w-0">
              <label htmlFor="admin-users-department-filter" className="sr-only">
                Lọc theo phòng ban
              </label>
              <select
                id="admin-users-department-filter"
                value={query.departmentFilter}
                onChange={(e) => updateQuery({ departmentFilter: e.target.value })}
                className={`${SELECT_BASE_CLASS} ${
                  query.departmentFilter !== 'ALL'
                    ? 'border-[#222222] font-semibold'
                    : 'border-[#dddddd]'
                }`}
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
              </select>
            </div>

            <div className="w-full sm:w-auto min-w-0">
              <label htmlFor="admin-users-action-filter" className="sr-only">
                Lọc theo thao tác khả dụng
              </label>
              <select
                id="admin-users-action-filter"
                value={query.actionFilter}
                onChange={(e) => updateQuery({ actionFilter: e.target.value as UserActionFilter })}
                className={`${SELECT_BASE_CLASS} ${
                  query.actionFilter !== 'ALL'
                    ? 'border-[#222222] font-semibold'
                    : 'border-[#dddddd]'
                }`}
              >
                <option value="ALL">Tất cả thao tác</option>
                <option value="DISABLE">Thao tác: Vô hiệu ({facets.actionCounts.DISABLE})</option>
                <option value="LOCK">Thao tác: Khóa ({facets.actionCounts.LOCK})</option>
                <option value="UNLOCK">Thao tác: Mở khóa ({facets.actionCounts.UNLOCK})</option>
                <option value="REACTIVATE">
                  Thao tác: Kích hoạt ({facets.actionCounts.REACTIVATE})
                </option>
              </select>
            </div>

            <div className="w-full sm:w-auto sm:ml-auto min-w-0">
              <label htmlFor="admin-users-sort" className="sr-only">
                Sắp xếp danh sách tài khoản
              </label>
              <select
                id="admin-users-sort"
                value={sortSelectValue}
                onChange={(e) => updateQuery(parseUserSortOption(e.target.value))}
                className={`${SELECT_BASE_CLASS} border-[#dddddd]`}
              >
                {USER_SORT_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    Sắp xếp · {opt.label}
                  </option>
                ))}
              </select>
            </div>

            {canResetQuery && (
              <button
                type="button"
                onClick={handleResetQuery}
                className="inline-flex min-h-11 sm:h-9 w-full sm:w-auto items-center justify-center gap-1.5 rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs font-medium text-[#717171] hover:border-[#222222] hover:text-[#222222] transition-colors cursor-pointer shrink-0"
              >
                <RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Đặt lại</span>
              </button>
            )}
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Table containerRef={tableScrollRef}>
            <TableHeader>
              <TableRow>
                <TableHead aria-sort={getAriaSort('fullName')}>
                  <button
                    type="button"
                    onClick={() => handleHeaderSort('fullName')}
                    title="Sắp xếp theo tên tài khoản"
                    className={`inline-flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wider transition-colors cursor-pointer whitespace-nowrap ${
                      query.sortField === 'fullName'
                        ? 'text-[#222222]'
                        : 'text-[#717171] hover:text-[#222222]'
                    }`}
                  >
                    <span>Tài khoản</span>
                    {renderSortIcon('fullName')}
                  </button>
                </TableHead>
                <TableHead aria-sort={getAriaSort('email')}>
                  <button
                    type="button"
                    onClick={() => handleHeaderSort('email')}
                    title="Sắp xếp theo địa chỉ email"
                    className={`inline-flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wider transition-colors cursor-pointer whitespace-nowrap ${
                      query.sortField === 'email'
                        ? 'text-[#222222]'
                        : 'text-[#717171] hover:text-[#222222]'
                    }`}
                  >
                    <span>Email</span>
                    {renderSortIcon('email')}
                  </button>
                </TableHead>
                <TableHead aria-sort={getAriaSort('department')}>
                  <button
                    type="button"
                    onClick={() => handleHeaderSort('department')}
                    title="Sắp xếp theo phòng ban"
                    className={`inline-flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wider transition-colors cursor-pointer whitespace-nowrap ${
                      query.sortField === 'department'
                        ? 'text-[#222222]'
                        : 'text-[#717171] hover:text-[#222222]'
                    }`}
                  >
                    <span>Phòng ban</span>
                    {renderSortIcon('department')}
                  </button>
                </TableHead>
                <TableHead aria-sort={getAriaSort('clearance')}>
                  <button
                    type="button"
                    onClick={() => handleHeaderSort('clearance')}
                    title="Sắp xếp theo cấp độ thẩm tra (Clearance)"
                    className={`inline-flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wider transition-colors cursor-pointer whitespace-nowrap ${
                      query.sortField === 'clearance'
                        ? 'text-[#222222]'
                        : 'text-[#717171] hover:text-[#222222]'
                    }`}
                  >
                    <span>Độ mật</span>
                    {renderSortIcon('clearance')}
                  </button>
                </TableHead>
                <TableHead aria-sort={getAriaSort('status')}>
                  <button
                    type="button"
                    onClick={() => handleHeaderSort('status')}
                    title="Sắp xếp theo trạng thái tài khoản"
                    className={`inline-flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wider transition-colors cursor-pointer whitespace-nowrap ${
                      query.sortField === 'status'
                        ? 'text-[#222222]'
                        : 'text-[#717171] hover:text-[#222222]'
                    }`}
                  >
                    <span>Trạng thái</span>
                    {renderSortIcon('status')}
                  </button>
                </TableHead>
                <TableHead className="text-right" aria-sort={getAriaSort('action')}>
                  <button
                    type="button"
                    onClick={() => handleHeaderSort('action')}
                    title="Sắp xếp theo nhóm thao tác (Vô hiệu / Kích hoạt)"
                    className={`ml-auto inline-flex items-center justify-end gap-1 text-[11px] font-semibold uppercase tracking-wider transition-colors cursor-pointer whitespace-nowrap ${
                      query.sortField === 'action'
                        ? 'text-[#222222]'
                        : 'text-[#717171] hover:text-[#222222]'
                    }`}
                  >
                    <span>Thao tác</span>
                    {renderSortIcon('action')}
                  </button>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {displayedUsers.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-xs text-[#717171]">
                    <div className="flex flex-col items-center gap-2.5">
                      <span>
                        {filtersActive
                          ? 'Không tìm thấy tài khoản nào khớp với bộ lọc hiện tại'
                          : 'Không tìm thấy tài khoản nào'}
                      </span>
                      {filtersActive && (
                        <button
                          type="button"
                          onClick={handleResetQuery}
                          className="inline-flex min-h-9 items-center gap-1.5 rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs font-medium text-[#222222] hover:border-[#222222] transition-colors cursor-pointer"
                        >
                          <RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />
                          <span>Đặt lại bộ lọc</span>
                        </button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                displayedUsers.map((u) => {
                  const deptName =
                    resolveUserDepartmentName(u, departmentNamesById) ??
                    UNASSIGNED_DEPARTMENT_LABEL;
                  const canReactivateDisabled = u.status === 'DISABLED';

                  return (
                    <TableRow key={u.id}>
                      <TableCell>
                        <div className="font-semibold text-xs text-[#222222]">{u.fullName}</div>
                        <div className="text-xs text-[#717171]">
                          @{u.username}
                          {u.employeeCode ? ` · ${u.employeeCode}` : ''}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-[#717171] max-w-[220px] truncate">
                        {u.email}
                      </TableCell>
                      <TableCell className="text-xs text-[#222222] whitespace-nowrap">
                        {deptName}
                      </TableCell>
                      <TableCell className="whitespace-nowrap">
                        {u.clearanceCode ? (
                          <ClassificationBadge
                            code={u.clearanceCode}
                            rank={u.clearanceRank ?? 0}
                            showRank
                            size="sm"
                          />
                        ) : (
                          <span
                            className="staff-badge bg-transparent border-0 p-0 inline-flex items-center gap-1 text-xs font-semibold text-[#C13515]"
                            title="Chưa gán cấp thẩm tra an ninh (Rank 0)"
                          >
                            <ShieldAlert size={16} strokeWidth={1.75} aria-hidden="true" />
                            <span>CHƯA CẤP · R0</span>
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="whitespace-nowrap">
                        <Badge
                          variant={
                            u.status === 'ACTIVE'
                              ? 'success'
                              : u.status === 'LOCKED'
                                ? 'warning'
                                : u.status === 'PENDING'
                                  ? 'info'
                                  : 'destructive'
                          }
                        >
                          {u.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right whitespace-nowrap">
                        <div className="inline-flex items-center justify-end gap-1.5">
                          <InteractiveHoverButton
                            variant="ghost"
                            size="sm"
                            text="Sửa"
                            icon={<Pencil size={16} strokeWidth={1.75} aria-hidden="true" />}
                            onClick={() => onOpenEditUser(u)}
                          />
                          <InteractiveHoverButton
                            variant="secondary"
                            size="sm"
                            text="Độ mật"
                            icon={<ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
                            onClick={() => onOpenUpdateClearance(u)}
                          />
                          <InteractiveHoverButton
                            variant="secondary"
                            size="sm"
                            text="Vai trò"
                            icon={<Key size={16} strokeWidth={1.75} aria-hidden="true" />}
                            onClick={() => onOpenAssignRole(u)}
                          />
                          {u.status === 'ACTIVE' && (
                            <InteractiveHoverButton
                              variant="ghost"
                              size="sm"
                              text="Khóa"
                              icon={<Lock size={16} strokeWidth={1.75} aria-hidden="true" />}
                              onClick={() => {
                                onClearError();
                                setPendingAction({ user: u, action: 'lock' });
                              }}
                            />
                          )}
                          {u.status === 'LOCKED' && (
                            <InteractiveHoverButton
                              variant="secondary"
                              size="sm"
                              text="Mở khóa"
                              icon={<Unlock size={16} strokeWidth={1.75} aria-hidden="true" />}
                              isLoading={unlockingUserId === u.id}
                              disabled={unlockingUserId === u.id}
                              onClick={() => void handleDirectUnlock(u)}
                            />
                          )}
                          {canReactivateDisabled && (
                            <InteractiveHoverButton
                              variant="secondary"
                              size="sm"
                              text="Kích hoạt"
                              icon={<Unlock size={16} strokeWidth={1.75} aria-hidden="true" />}
                              isLoading={unlockingUserId === u.id}
                              disabled={unlockingUserId === u.id}
                              onClick={() => void handleDirectUnlock(u)}
                            />
                          )}
                          {u.status !== 'DISABLED' && (
                            <InteractiveHoverButton
                              variant="danger"
                              size="sm"
                              text="Vô hiệu"
                              icon={<Ban size={16} strokeWidth={1.75} aria-hidden="true" />}
                              onClick={() => {
                                onClearError();
                                setPendingAction({ user: u, action: 'disable' });
                              }}
                            />
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <ConfirmDialog
        open={Boolean(pendingAction)}
        onOpenChange={(open) => {
          if (!open && !isUpdatingStatus) setPendingAction(null);
        }}
        title={
          pendingAction?.action === 'disable'
            ? 'Xác nhận vô hiệu hóa tài khoản'
            : 'Xác nhận khóa tạm thời tài khoản'
        }
        description={
          pendingAction?.action === 'disable'
            ? `Tài khoản @${pendingAction.user.username} (${pendingAction.user.fullName}) sẽ bị vô hiệu hóa và thu hồi mọi phiên hoạt động.`
            : `Tài khoản @${pendingAction?.user.username ?? ''} (${pendingAction?.user.fullName ?? ''}) sẽ bị khóa đăng nhập tạm thời.`
        }
        confirmLabel={
          pendingAction?.action === 'disable' ? 'Xác nhận vô hiệu hóa' : 'Xác nhận khóa'
        }
        variant={pendingAction?.action === 'disable' ? 'danger' : 'primary'}
        isLoading={isUpdatingStatus}
        onConfirm={async () => {
          if (!pendingAction) return;
          setIsUpdatingStatus(true);
          try {
            const ok = await onChangeStatus(pendingAction.user, pendingAction.action);
            if (ok) setPendingAction(null);
          } finally {
            setIsUpdatingStatus(false);
          }
        }}
      />
    </>
  );
}

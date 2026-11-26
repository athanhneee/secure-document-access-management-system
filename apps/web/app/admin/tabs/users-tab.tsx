'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Ban,
  ChevronLeft,
  ChevronRight,
  Key,
  Lock,
  Pencil,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Unlock,
} from 'lucide-react';
import { ClassificationBadge } from '@/components/classification-badge';
import { Badge } from '@/components/ui/badge';
import { formatUserStatusLabel } from '@/lib/ui-labels';
import { Card, CardContent } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
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
  hasActiveUserFilters,
  isNonDefaultUserQuery,
  resolveUserDepartmentName,
  toggleUserSort,
  UNASSIGNED_DEPARTMENT_LABEL,
  type UserListQueryState,
  type UserSortField,
} from '../users-query';
import type { DepartmentRow, UserRow, UserStatusAction } from '../types';
import { UsersFilterBar } from './users-filter-bar';

const USERS_PAGE_SIZE = 20;

interface UsersTabProps {
  users: UserRow[];
  usersPage?: number | undefined;
  usersTotalPages?: number | undefined;
  usersTotal?: number | null | undefined;
  usersTruncated?: boolean | undefined;
  isLoadingUsers?: boolean | undefined;
  onUsersPageChange?: ((page: number) => void) | undefined;
  departments: DepartmentRow[];
  currentUserId?: string | undefined;
  query: UserListQueryState;
  onQueryChange: (nextQuery: UserListQueryState) => void;
  onOpenEditUser: (user: UserRow) => void;
  onOpenUpdateClearance: (user: UserRow) => void;
  onOpenAssignRole: (user: UserRow) => void;
  onChangeStatus: (user: UserRow, action: UserStatusAction) => Promise<boolean>;
  onClearError: () => void;
}

/**
 * Thuật toán: Bảng Quản Lý Danh Tính Có Phân Trang Máy Chủ `375px`, Đồng Bộ Máy Trạng Thái Vòng Đời & Chống Tự Khóa (`UsersTab`, BUG-098, BUG-105)
 * Mục đích:
 *   - Đồng bộ nút thao tác với máy trạng thái máy chủ (`LOCK` chỉ cho `ACTIVE`, `UNLOCK` cho `LOCKED`, `REACTIVATE` cho `DISABLED` hoặc `PENDING`, `DISABLE` cho `status !== 'DISABLED'`).
 *   - Hỗ trợ phân trang máy chủ (`20` tài khoản/trang) cho phép tìm kiếm và duyệt toàn bộ nhân sự vượt quá 200 bản ghi mà không làm mất tiêu điểm ô nhập tiếng Việt.
 */
export function UsersTab({
  users,
  usersPage,
  usersTotalPages,
  usersTotal,
  usersTruncated = false,
  isLoadingUsers = false,
  onUsersPageChange,
  departments,
  currentUserId,
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
    action: 'lock' | 'disable' | 'reactivate';
  } | null>(null);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [unlockingUserId, setUnlockingUserId] = useState<string | null>(null);
  const [localPage, setLocalPage] = useState(1);
  const tableScrollRef = useRef<HTMLDivElement | null>(null);

  const isServerPaged = typeof onUsersPageChange === 'function' && typeof usersPage === 'number';
  const departmentNamesById = useMemo(() => buildDepartmentNameMap(departments), [departments]);
  const facets = useMemo(() => computeUserFilterFacets(users, departments), [users, departments]);
  const displayedUsers = useMemo(
    () => filterAndSortUsers(users, departments, query),
    [users, departments, query],
  );

  const totalPages = isServerPaged
    ? Math.max(1, usersTotalPages ?? 1)
    : Math.max(1, Math.ceil(displayedUsers.length / USERS_PAGE_SIZE));
  const safePage = isServerPaged
    ? Math.min(Math.max(1, usersPage), totalPages)
    : Math.min(localPage, totalPages);
  const startIdx = (safePage - 1) * USERS_PAGE_SIZE;
  const paginatedUsers = useMemo(
    () =>
      isServerPaged ? displayedUsers : displayedUsers.slice(startIdx, startIdx + USERS_PAGE_SIZE),
    [isServerPaged, displayedUsers, startIdx],
  );

  const filtersActive = hasActiveUserFilters(query);
  const canResetQuery = isNonDefaultUserQuery(query);
  const showTruncationNotice =
    !isServerPaged &&
    (usersTruncated || (typeof usersTotal === 'number' && usersTotal > users.length));

  const handlePageChange = (nextPage: number) => {
    const clamped = Math.min(totalPages, Math.max(1, nextPage));
    if (isServerPaged) {
      onUsersPageChange(clamped);
    } else {
      setLocalPage(clamped);
    }
  };

  useEffect(() => {
    tableScrollRef.current?.scrollTo({ top: 0 });
  }, [safePage, query]);

  function updateQuery(patch: Partial<UserListQueryState>) {
    if (isServerPaged) {
      onUsersPageChange(1);
    } else {
      setLocalPage(1);
    }
    onQueryChange({ ...query, ...patch });
  }

  function handleHeaderSort(field: UserSortField) {
    updateQuery(toggleUserSort(query.sortField, query.sortDirection, field));
  }

  function handleResetQuery() {
    if (isServerPaged) {
      onUsersPageChange(1);
    } else {
      setLocalPage(1);
    }
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
    const Icon = query.sortDirection === 'asc' ? ArrowUp : ArrowDown;
    return (
      <Icon size={16} strokeWidth={1.75} className="shrink-0 text-[#FF385C]" aria-hidden="true" />
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

  function getUserStatusVariant(status: UserRow['status']) {
    if (status === 'ACTIVE') return 'success' as const;
    if (status === 'LOCKED') return 'warning' as const;
    if (status === 'PENDING') return 'info' as const;
    return 'destructive' as const;
  }

  function renderUserActions(u: UserRow, isMobile: boolean) {
    const isSelf = Boolean(currentUserId && u.id === currentUserId);
    const normalizedStatus = u.status.trim().toUpperCase();
    const canLock = !isSelf && normalizedStatus === 'ACTIVE';
    const canUnlock = normalizedStatus === 'LOCKED';
    const canReactivate = normalizedStatus === 'DISABLED' || normalizedStatus === 'PENDING';
    const canDisable = !isSelf && normalizedStatus !== 'DISABLED';
    const btnVariant = isMobile ? ('secondary' as const) : ('ghost' as const);

    return (
      <>
        <InteractiveHoverButton
          variant={btnVariant}
          size="sm"
          text="Sửa"
          icon={<Pencil size={16} strokeWidth={1.75} aria-hidden="true" />}
          onClick={() => onOpenEditUser(u)}
          className={isMobile ? 'w-full' : undefined}
        />
        <InteractiveHoverButton
          variant="secondary"
          size="sm"
          text="Thẩm quyền"
          icon={<ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
          onClick={() => onOpenUpdateClearance(u)}
          className={isMobile ? 'w-full' : undefined}
        />
        <InteractiveHoverButton
          variant="secondary"
          size="sm"
          text="Vai trò"
          icon={<Key size={16} strokeWidth={1.75} aria-hidden="true" />}
          onClick={() => onOpenAssignRole(u)}
          className={isMobile ? 'w-full' : undefined}
        />
        {canLock && (
          <InteractiveHoverButton
            variant={btnVariant}
            size="sm"
            text="Khóa"
            icon={<Lock size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={() => {
              onClearError();
              setPendingAction({ user: u, action: 'lock' });
            }}
            className={isMobile ? 'w-full' : undefined}
          />
        )}
        {canUnlock && (
          <InteractiveHoverButton
            variant="secondary"
            size="sm"
            text="Mở khóa"
            icon={<Unlock size={16} strokeWidth={1.75} aria-hidden="true" />}
            isLoading={unlockingUserId === u.id}
            disabled={unlockingUserId === u.id}
            onClick={() => void handleDirectUnlock(u)}
            className={isMobile ? 'w-full' : undefined}
          />
        )}
        {canReactivate && (
          <InteractiveHoverButton
            variant="secondary"
            size="sm"
            text="Kích hoạt"
            icon={<Unlock size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={() => {
              onClearError();
              setPendingAction({ user: u, action: 'reactivate' });
            }}
            className={isMobile ? 'w-full' : undefined}
          />
        )}
        {canDisable && (
          <InteractiveHoverButton
            variant="danger"
            size="sm"
            text="Vô hiệu hóa"
            icon={<Ban size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={() => {
              onClearError();
              setPendingAction({ user: u, action: 'disable' });
            }}
            className={isMobile ? 'col-span-2 w-full' : undefined}
          />
        )}
      </>
    );
  }

  return (
    <>
      <Card>
        <UsersFilterBar
          totalLoadedCount={users.length}
          serverTotalCount={usersTotal}
          displayedCount={displayedUsers.length}
          filtersActive={filtersActive}
          canResetQuery={canResetQuery}
          facets={facets}
          query={query}
          onUpdateQuery={updateQuery}
          onResetQuery={handleResetQuery}
        />

        <CardContent className="p-0">
          {displayedUsers.length === 0 ? (
            <div className="py-10 px-4 text-center text-xs text-[#717171]">
              <div className="flex flex-col items-center gap-2.5">
                <span>
                  {filtersActive
                    ? 'Không tìm thấy tài khoản nào khớp với bộ lọc hiện tại.'
                    : 'Chưa có tài khoản nào trong hệ thống.'}
                </span>
                {filtersActive && (
                  <button
                    type="button"
                    onClick={handleResetQuery}
                    className="inline-flex min-h-11 sm:min-h-9 items-center gap-1.5 rounded-full border border-[#dddddd] bg-[#ffffff] px-4 text-xs font-medium text-[#222222] hover:border-[#222222] transition-colors cursor-pointer"
                  >
                    <RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>Đặt lại bộ lọc</span>
                  </button>
                )}
              </div>
            </div>
          ) : (
            <>
              {/* Bố cục thẻ di động tối ưu 375px */}
              <div className="md:hidden divide-y divide-[#ebebeb]">
                {paginatedUsers.map((u) => {
                  const deptName =
                    resolveUserDepartmentName(u, departmentNamesById) ??
                    UNASSIGNED_DEPARTMENT_LABEL;
                  return (
                    <article key={u.id} className="px-4 py-4 space-y-3 bg-[#ffffff]">
                      <div className="flex items-center justify-between gap-2">
                        {u.clearanceCode ? (
                          <ClassificationBadge
                            code={u.clearanceCode}
                            rank={u.clearanceRank ?? 0}
                            showRank
                            subject="user"
                            size="sm"
                          />
                        ) : (
                          <span className="staff-badge bg-transparent border-0 p-0 inline-flex shrink-0 items-center gap-1 whitespace-nowrap text-xs font-semibold text-[#C13515]">
                            <ShieldAlert size={16} strokeWidth={1.75} aria-hidden="true" />
                            <span>CHƯA CẤP · Cấp 0</span>
                          </span>
                        )}
                        <Badge variant={getUserStatusVariant(u.status)}>
                          {formatUserStatusLabel(u.status)}
                        </Badge>
                      </div>
                      <div className="space-y-0.5 min-w-0">
                        <h3 className="text-sm font-semibold text-[#222222] leading-snug break-words">
                          {u.fullName}
                        </h3>
                        <p className="text-xs text-[#717171] truncate">
                          @{u.username}
                          {u.employeeCode ? ` · ${u.employeeCode}` : ''}
                        </p>
                      </div>
                      <div className="rounded-[12px] bg-[#f7f7f7] px-3 py-2 space-y-1.5 text-xs">
                        <div className="flex items-center justify-between gap-3">
                          <span className="text-[#717171] shrink-0">Email</span>
                          <span className="text-[#222222] text-right truncate">{u.email}</span>
                        </div>
                        <div className="flex items-center justify-between gap-3">
                          <span className="text-[#717171] shrink-0">Phòng ban</span>
                          <span className="font-medium text-[#222222] text-right truncate">
                            {deptName}
                          </span>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-2 pt-0.5">
                        {renderUserActions(u, true)}
                      </div>
                    </article>
                  );
                })}
              </div>

              {/* Bảng dữ liệu máy tính */}
              <div className="hidden md:block">
                <Table containerRef={tableScrollRef}>
                  <TableHeader>
                    <TableRow>
                      {(
                        [
                          ['fullName', 'Tài khoản', 'Sắp xếp theo tên tài khoản'],
                          ['email', 'Email', 'Sắp xếp theo địa chỉ email'],
                          ['department', 'Phòng ban', 'Sắp xếp theo phòng ban'],
                          ['clearance', 'Cấp thẩm quyền', 'Sắp xếp theo cấp thẩm quyền bảo mật'],
                          ['status', 'Trạng thái', 'Sắp xếp theo trạng thái tài khoản'],
                        ] as const
                      ).map(([field, label, title]) => (
                        <TableHead key={field} aria-sort={getAriaSort(field)}>
                          <button
                            type="button"
                            onClick={() => handleHeaderSort(field)}
                            title={title}
                            className={`inline-flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wider transition-colors cursor-pointer whitespace-nowrap ${
                              query.sortField === field
                                ? 'text-[#222222]'
                                : 'text-[#717171] hover:text-[#222222]'
                            }`}
                          >
                            <span>{label}</span>
                            {renderSortIcon(field)}
                          </button>
                        </TableHead>
                      ))}
                      <TableHead className="text-right" aria-sort={getAriaSort('action')}>
                        <button
                          type="button"
                          onClick={() => handleHeaderSort('action')}
                          title="Sắp xếp theo nhóm thao tác (Vô hiệu hóa / Kích hoạt)"
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
                    {paginatedUsers.map((u) => {
                      const deptName =
                        resolveUserDepartmentName(u, departmentNamesById) ??
                        UNASSIGNED_DEPARTMENT_LABEL;
                      return (
                        <TableRow key={u.id}>
                          <TableCell className="min-w-[160px] max-w-[210px]">
                            <div
                              className="font-semibold text-xs text-[#222222] truncate"
                              title={`${u.fullName} (@${u.username})`}
                            >
                              {u.fullName}
                            </div>
                            {u.employeeCode && (
                              <div className="text-[11px] text-[#717171] truncate tabular-nums">
                                {u.employeeCode}
                              </div>
                            )}
                          </TableCell>
                          <TableCell
                            className="text-xs text-[#717171] max-w-[180px] truncate"
                            title={u.email}
                          >
                            {u.email}
                          </TableCell>
                          <TableCell
                            className="text-xs text-[#222222] max-w-[165px] truncate"
                            title={deptName}
                          >
                            {deptName}
                          </TableCell>
                          <TableCell className="whitespace-nowrap">
                            {u.clearanceCode ? (
                              <ClassificationBadge
                                code={u.clearanceCode}
                                rank={u.clearanceRank ?? 0}
                                showRank
                                subject="user"
                                size="sm"
                              />
                            ) : (
                              <span className="staff-badge bg-transparent border-0 p-0 inline-flex items-center gap-1 text-xs font-semibold text-[#C13515]">
                                <ShieldAlert size={16} strokeWidth={1.75} aria-hidden="true" />
                                <span>CHƯA CẤP · Cấp 0</span>
                              </span>
                            )}
                          </TableCell>
                          <TableCell className="whitespace-nowrap">
                            <Badge variant={getUserStatusVariant(u.status)}>
                              {formatUserStatusLabel(u.status)}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="ml-auto flex flex-wrap items-center justify-end gap-1 min-w-[215px] max-w-[300px] 2xl:max-w-none">
                              {renderUserActions(u, false)}
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>

              {(totalPages > 1 || showTruncationNotice) && (
                <div className="px-4 py-2.5 border-t border-[#ebebeb] bg-[#f7f7f7]/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-[#717171]">
                  <div className="space-y-0.5">
                    <span className="tabular-nums">
                      Hiển thị{' '}
                      <strong className="text-[#222222]">
                        {paginatedUsers.length === 0
                          ? '0'
                          : `${startIdx + 1}–${startIdx + paginatedUsers.length}`}
                      </strong>{' '}
                      /{' '}
                      <strong className="text-[#222222]">
                        {isServerPaged
                          ? (usersTotal ?? paginatedUsers.length)
                          : displayedUsers.length}
                      </strong>{' '}
                      tài khoản
                    </span>
                    {showTruncationNotice && (
                      <p className="text-[11px] text-[#717171]">
                        Đang nạp {users.length} / {usersTotal ?? users.length} tài khoản trên máy
                        chủ.
                      </p>
                    )}
                  </div>
                  {totalPages > 1 && (
                    <div className="flex items-center justify-between sm:justify-end gap-2">
                      <InteractiveHoverButton
                        type="button"
                        variant="secondary"
                        size="sm"
                        text="Trang trước"
                        icon={<ChevronLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
                        disabled={safePage <= 1 || isLoadingUsers}
                        onClick={() => handlePageChange(safePage - 1)}
                      />
                      <span className="font-semibold text-[#222222] whitespace-nowrap tabular-nums">
                        Trang {safePage} / {totalPages}
                      </span>
                      <InteractiveHoverButton
                        type="button"
                        variant="secondary"
                        size="sm"
                        text="Trang sau"
                        icon={<ChevronRight size={16} strokeWidth={1.75} aria-hidden="true" />}
                        disabled={safePage >= totalPages || isLoadingUsers}
                        onClick={() => handlePageChange(safePage + 1)}
                      />
                    </div>
                  )}
                </div>
              )}
            </>
          )}
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
            : pendingAction?.action === 'reactivate'
              ? 'Xác nhận kích hoạt tài khoản'
              : 'Xác nhận khóa tạm thời tài khoản'
        }
        description={
          pendingAction?.action === 'disable'
            ? `Tài khoản @${pendingAction.user.username} (${pendingAction.user.fullName}) sẽ bị vô hiệu hóa và thu hồi tức thì mọi phiên hoạt động.`
            : pendingAction?.action === 'reactivate'
              ? `Tài khoản @${pendingAction.user.username} (${pendingAction.user.fullName}) sẽ được chuyển từ trạng thái ${formatUserStatusLabel(pendingAction.user.status)} sang Đang hoạt động và có thể đăng nhập hệ thống.`
              : `Tài khoản @${pendingAction?.user.username ?? ''} (${pendingAction?.user.fullName ?? ''}) sẽ bị khóa đăng nhập tạm thời và thu hồi tức thì mọi phiên đang mở.`
        }
        confirmLabel={
          pendingAction?.action === 'disable'
            ? 'Xác nhận vô hiệu hóa'
            : pendingAction?.action === 'reactivate'
              ? 'Xác nhận kích hoạt'
              : 'Xác nhận khóa'
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

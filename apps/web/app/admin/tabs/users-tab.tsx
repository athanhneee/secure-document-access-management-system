'use client';

import { useState } from 'react';
import { Ban, Key, Lock, Pencil, Search, Unlock } from 'lucide-react';
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
import { filterUsersByQuery } from '../helpers';
import type { DepartmentRow, UserRow, UserStatusAction } from '../types';

interface UsersTabProps {
  users: UserRow[];
  departments: DepartmentRow[];
  searchQuery: string;
  onSearchQueryChange: (query: string) => void;
  onOpenEditUser: (user: UserRow) => void;
  onOpenAssignRole: (user: UserRow) => void;
  onChangeStatus: (user: UserRow, action: UserStatusAction) => Promise<boolean>;
  onClearError: () => void;
}

/**
 * Thuật toán: Bảng Quản Lý Danh Tính & Vòng Đời Trạng Thái Tài Khoản Nhân Sự (`UsersTab`)
 * Mục đích: Kết hợp lọc tức thời đa trường, chỉnh sửa hồ sơ OCC, gán vai trò RBAC, khóa/mở khóa và khôi phục tài khoản `DISABLED` (ngoại trừ tài khoản `.demo` khóa mật khẩu).
 */
export function UsersTab({
  users,
  departments,
  searchQuery,
  onSearchQueryChange,
  onOpenEditUser,
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

  const filteredUsers = filterUsersByQuery(users, searchQuery);

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
        <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <CardTitle className="text-sm sm:text-base text-[#222222]">
            Danh sách tài khoản ({filteredUsers.length})
          </CardTitle>
          <div className="relative w-full sm:w-64 shrink-0">
            <Search
              size={16}
              strokeWidth={1.75}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#717171]"
              aria-hidden="true"
            />
            <Input
              id="admin-users-search"
              type="text"
              aria-label="Tìm kiếm tài khoản người dùng"
              placeholder="Tìm tên, username, email..."
              value={searchQuery}
              onChange={(e) => onSearchQueryChange(e.target.value)}
              className="pl-9 min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
            />
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Tài khoản</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Phòng ban</TableHead>
                <TableHead>Trạng thái</TableHead>
                <TableHead className="text-right">Thao tác</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredUsers.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8 text-xs text-[#717171]">
                    Không tìm thấy tài khoản nào
                  </TableCell>
                </TableRow>
              ) : (
                filteredUsers.map((u) => {
                  const deptName =
                    departments.find((d) => String(d.id) === String(u.departmentId))?.name ||
                    'Chưa gán';
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
                        <Badge
                          variant={
                            u.status === 'ACTIVE'
                              ? 'success'
                              : u.status === 'LOCKED'
                                ? 'warning'
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

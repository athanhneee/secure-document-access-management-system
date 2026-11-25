'use client';

import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { AlertTriangle } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { formatLocalDateTimeInput, getDefaultRoleAssignmentWindow } from '../helpers';
import type { RoleRow, UserRoleAssignmentRow, UserRow } from '../types';
import { UserRoleAssignmentsList } from './user-role-assignments-list';

interface AssignRoleModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  targetUser: UserRow | null;
  currentUserId?: string | undefined;
  roles: RoleRow[];
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

export function AssignRoleModal({
  open,
  onOpenChange,
  targetUser,
  currentUserId,
  roles,
  onClearError,
  onSuccess,
  onError,
}: AssignRoleModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Quản lý vai trò: {targetUser?.fullName}
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Xem vai trò hiện có, thu hồi hoặc gán mới vai trò với khoảng thời gian hiệu lực hợp lệ.
          </DialogDescription>
        </DialogHeader>

        {open && targetUser && (
          <AssignRoleForm
            key={targetUser.id}
            targetUser={targetUser}
            isSelf={Boolean(currentUserId && targetUser.id === currentUserId)}
            roles={roles}
            onClose={() => onOpenChange(false)}
            onClearError={onClearError}
            onSuccess={onSuccess}
            onError={onError}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

interface AssignRoleFormProps {
  targetUser: UserRow;
  isSelf: boolean;
  roles: RoleRow[];
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

const CLIENT_PAST_TOLERANCE_MS = 60_000;

/**
 * Thuật toán: Biểu Mẫu Gán & Thu Hồi Vai Trò Có Lọc Vai Trò Đang Hoạt Động & Chặn Ngày Quá Khứ (`AssignRoleForm`)
 */
function AssignRoleForm({
  targetUser,
  isSelf,
  roles,
  onClose,
  onClearError,
  onSuccess,
  onError,
}: AssignRoleFormProps) {
  const activeRoles = useMemo(() => roles.filter((r) => r.isActive), [roles]);
  const [assignRoleId, setAssignRoleId] = useState<string>('');
  const effectiveRoleId = activeRoles.some((r) => r.id === assignRoleId)
    ? assignRoleId
    : (activeRoles[0]?.id ?? '');
  const [minDateTimeLocal] = useState(() => formatLocalDateTimeInput(new Date()));
  const [assignValidFrom, setAssignValidFrom] = useState(
    () => getDefaultRoleAssignmentWindow().validFrom,
  );
  const [assignValidTo, setAssignValidTo] = useState(
    () => getDefaultRoleAssignmentWindow().validTo,
  );
  const [isAssigningRole, setIsAssigningRole] = useState(false);
  const [assignments, setAssignments] = useState<UserRoleAssignmentRow[]>([]);
  const [assignmentsAsOfMs, setAssignmentsAsOfMs] = useState<number>(() => Date.now());
  const [loadingAssignments, setLoadingAssignments] = useState(true);

  const reloadAssignments = useCallback(async () => {
    try {
      const detail = await apiClient<{ roleAssignments?: UserRoleAssignmentRow[] }>(
        `/users/${targetUser.id}`,
      );
      setAssignments(detail.roleAssignments ?? []);
      setAssignmentsAsOfMs(Date.now());
    } catch {
      setAssignments([]);
    } finally {
      setLoadingAssignments(false);
    }
  }, [targetUser.id]);

  useEffect(() => {
    let active = true;
    void apiClient<{ roleAssignments?: UserRoleAssignmentRow[] }>(`/users/${targetUser.id}`)
      .then((detail) => {
        if (!active) return;
        setAssignments(detail.roleAssignments ?? []);
        setAssignmentsAsOfMs(Date.now());
      })
      .catch(() => {
        if (!active) return;
        setAssignments([]);
      })
      .finally(() => {
        if (!active) return;
        setLoadingAssignments(false);
      });
    return () => {
      active = false;
    };
  }, [targetUser.id]);

  async function handleRevokeAssignment(assignment: UserRoleAssignmentRow): Promise<boolean> {
    onClearError();
    try {
      await apiClient(`/rbac/users/${targetUser.id}/roles/${assignment.id}`, {
        method: 'DELETE',
      });
      await reloadAssignments();
      await onSuccess(
        `Đã thu hồi vai trò ${assignment.roleName || assignment.roleCode} của ${targetUser.fullName}.`,
      );
      return true;
    } catch (err) {
      onError(
        err instanceof ApiError
          ? err.message || 'Không thể thu hồi vai trò.'
          : 'Đã xảy ra lỗi khi thu hồi vai trò.',
      );
      return false;
    }
  }

  async function handleAssignUserRole(e: FormEvent) {
    e.preventDefault();
    if (isSelf) {
      onError('Quản trị viên không thể tự gán vai trò cho chính mình.');
      return;
    }
    if (!effectiveRoleId) {
      onError('Vui lòng chọn vai trò đang hoạt động để gán.');
      return;
    }

    const nowMs = Date.now();
    const validFromDate = assignValidFrom ? new Date(assignValidFrom) : new Date(nowMs);
    if (!Number.isFinite(validFromDate.getTime())) {
      onError('Thời điểm bắt đầu hiệu lực không hợp lệ.');
      return;
    }
    if (validFromDate.getTime() < nowMs - CLIENT_PAST_TOLERANCE_MS) {
      onError('Thời điểm bắt đầu hiệu lực không được nằm trong quá khứ.');
      return;
    }

    let validToDate: Date | null = null;
    if (assignValidTo) {
      validToDate = new Date(assignValidTo);
      if (!Number.isFinite(validToDate.getTime())) {
        onError('Thời điểm kết thúc hiệu lực không hợp lệ.');
        return;
      }
      if (validToDate.getTime() <= nowMs) {
        onError('Thời điểm kết thúc hiệu lực phải nằm trong tương lai.');
        return;
      }
      if (validToDate.getTime() <= validFromDate.getTime()) {
        onError('Thời điểm kết thúc phải lớn hơn thời điểm bắt đầu.');
        return;
      }
    }

    setIsAssigningRole(true);
    onClearError();
    try {
      await apiClient(`/rbac/users/${targetUser.id}/roles`, {
        method: 'POST',
        body: JSON.stringify({
          roleId: effectiveRoleId,
          scopeDepartmentId: null,
          validFrom: validFromDate.toISOString(),
          validTo: validToDate ? validToDate.toISOString() : null,
        }),
      });

      onClose();
      await onSuccess(`Đã gán vai trò thành công cho người dùng ${targetUser.fullName}.`);
    } catch (err) {
      if (err instanceof ApiError) {
        onError(err.message || 'Không thể gán vai trò.');
      } else {
        onError('Đã xảy ra lỗi khi gán vai trò cho người dùng.');
      }
    } finally {
      setIsAssigningRole(false);
    }
  }

  return (
    <div className="space-y-3.5 py-2 text-xs">
      <UserRoleAssignmentsList
        assignments={assignments}
        asOfMs={assignmentsAsOfMs}
        isLoading={loadingAssignments}
        canRevoke={!isSelf}
        onRevoke={handleRevokeAssignment}
      />

      {isSelf ? (
        <Alert variant="warning" className="text-xs">
          <AlertTriangle
            size={16}
            strokeWidth={1.75}
            className="shrink-0 text-[#E07912]"
            aria-hidden="true"
          />
          <AlertDescription className="ml-2">
            Quản trị viên không thể tự gán hoặc tự thu hồi vai trò của chính mình theo nguyên tắc
            kiểm soát nội bộ.
          </AlertDescription>
        </Alert>
      ) : (
        <form onSubmit={handleAssignUserRole} className="space-y-3.5">
          <div className="space-y-1">
            <label htmlFor="assign-role-id" className="font-medium text-[#222222]">
              Chọn vai trò mới để gán <span className="text-[#C13515]">*</span>
            </label>
            <select
              id="assign-role-id"
              value={effectiveRoleId}
              onChange={(e) => setAssignRoleId(e.target.value)}
              disabled={activeRoles.length === 0}
              className="w-full min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer disabled:opacity-60"
            >
              {activeRoles.length === 0 ? (
                <option value="">
                  {roles.length === 0
                    ? 'Đang tải danh sách vai trò…'
                    : 'Không có vai trò nào đang hoạt động'}
                </option>
              ) : (
                activeRoles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name} ({r.code})
                  </option>
                ))
              )}
            </select>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <label htmlFor="assign-valid-from" className="font-medium text-[#222222]">
                Bắt đầu (từ hiện tại trở đi)
              </label>
              <Input
                id="assign-valid-from"
                type="datetime-local"
                min={minDateTimeLocal}
                value={assignValidFrom}
                onChange={(e) => setAssignValidFrom(e.target.value)}
                className="min-h-11 sm:h-9 text-xs rounded-full"
              />
            </div>
            <div className="space-y-1">
              <label htmlFor="assign-valid-to" className="font-medium text-[#222222]">
                Kết thúc (tùy chọn)
              </label>
              <Input
                id="assign-valid-to"
                type="datetime-local"
                min={assignValidFrom || minDateTimeLocal}
                value={assignValidTo}
                onChange={(e) => setAssignValidTo(e.target.value)}
                className="min-h-11 sm:h-9 text-xs rounded-full"
              />
            </div>
          </div>

          <DialogFooter className="pt-2">
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Đóng"
              onClick={onClose}
            />
            <InteractiveHoverButton
              type="submit"
              variant="primary"
              size="sm"
              text="Xác nhận gán"
              disabled={isAssigningRole || activeRoles.length === 0}
              isLoading={isAssigningRole}
            />
          </DialogFooter>
        </form>
      )}
    </div>
  );
}

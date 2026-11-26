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
import { Select } from '@/components/ui/select';
import {
  CLIENT_PAST_TOLERANCE_MS,
  formatLocalDateTimeInput,
  getDefaultRoleAssignmentWindow,
} from '../helpers';
import { buildAssignableRoleScopeOptions } from '../role-scope-options';
import type { DepartmentRow, RoleRow, UserRoleAssignmentRow, UserRow } from '../types';
import { UserRoleAssignmentsList } from './user-role-assignments-list';

interface AssignRoleModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  targetUser: UserRow | null;
  currentUserId?: string | undefined;
  hasGlobalUserManage?: boolean | undefined;
  userManageDepartmentIds?: readonly string[] | undefined;
  departments: DepartmentRow[];
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
  hasGlobalUserManage,
  userManageDepartmentIds,
  departments,
  roles,
  onClearError,
  onSuccess,
  onError,
}: AssignRoleModalProps) {
  const [isAssigningRole, setIsAssigningRole] = useState(false);

  function handleDialogOpenChange(nextOpen: boolean) {
    if (!nextOpen && isAssigningRole) return;
    onOpenChange(nextOpen);
  }

  return (
    <Dialog open={open} onOpenChange={handleDialogOpenChange}>
      <DialogContent
        showClose={!isAssigningRole}
        className="max-w-lg border-[#ebebeb] bg-[#ffffff] text-[#222222]"
      >
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Quản lý vai trò: {targetUser?.fullName}
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Xem vai trò hiện có, thu hồi hoặc gán mới vai trò với phạm vi phòng ban và khoảng thời
            gian hiệu lực hợp lệ.
          </DialogDescription>
        </DialogHeader>

        {open && targetUser && (
          <AssignRoleForm
            key={targetUser.id}
            targetUser={targetUser}
            isSelf={Boolean(currentUserId && targetUser.id === currentUserId)}
            hasGlobalUserManage={hasGlobalUserManage}
            userManageDepartmentIds={userManageDepartmentIds}
            departments={departments}
            roles={roles}
            isAssigningRole={isAssigningRole}
            setIsAssigningRole={setIsAssigningRole}
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
  hasGlobalUserManage?: boolean | undefined;
  userManageDepartmentIds?: readonly string[] | undefined;
  departments: DepartmentRow[];
  roles: RoleRow[];
  isAssigningRole: boolean;
  setIsAssigningRole: (busy: boolean) => void;
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

/**
 * Thuật toán: Biểu Mẫu Gán & Thu Hồi Vai Trò Chốt Mốc `minDateTimeLocal` Một Lần & Dung Sai 5 Phút (`AssignRoleForm`, BUG-093)
 * Mục đích:
 *   - Chốt `minDateTimeLocal` đúng một lần khi mở hộp thoại thay vì tính lại mỗi lần render.
 *   - Nếu quản trị viên không tự sửa ô `validFrom`, tự động gửi `new Date().toISOString()` tại thời điểm nhấn lưu; nếu đã sửa thủ công, áp dụng dung sai `CLIENT_PAST_TOLERANCE_MS` (5 phút) khớp máy chủ và luôn kiểm tra `validFrom < validTo`.
 */
function AssignRoleForm({
  targetUser,
  isSelf,
  hasGlobalUserManage,
  userManageDepartmentIds,
  departments,
  roles,
  isAssigningRole,
  setIsAssigningRole,
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

  const scopeOptions = useMemo(
    () =>
      buildAssignableRoleScopeOptions({
        targetDepartmentId: targetUser.departmentId,
        departments,
        hasGlobalUserManage,
        userManageDepartmentIds,
      }),
    [targetUser.departmentId, departments, hasGlobalUserManage, userManageDepartmentIds],
  );
  const [selectedScopeValue, setSelectedScopeValue] = useState<string | null>(null);
  const effectiveScopeOption = useMemo(() => {
    if (selectedScopeValue !== null) {
      const matched = scopeOptions.find((opt) => opt.value === selectedScopeValue);
      if (matched) return matched;
    }
    return scopeOptions[0] ?? null;
  }, [scopeOptions, selectedScopeValue]);

  const [initialWindow] = useState(() => {
    const now = new Date();
    return {
      minLocal: formatLocalDateTimeInput(now),
      defaults: getDefaultRoleAssignmentWindow(),
    };
  });
  const minDateTimeLocal = initialWindow.minLocal;
  const [assignValidFrom, setAssignValidFrom] = useState(() => initialWindow.defaults.validFrom);
  const [validFromEdited, setValidFromEdited] = useState(false);
  const [assignValidTo, setAssignValidTo] = useState(() => initialWindow.defaults.validTo);
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
    if (!effectiveScopeOption) {
      onError('Không có phạm vi phòng ban hợp lệ trong thẩm quyền quản trị của bạn.');
      return;
    }

    const nowMs = Date.now();
    const validFromDate =
      !validFromEdited || !assignValidFrom ? new Date(nowMs) : new Date(assignValidFrom);
    if (!Number.isFinite(validFromDate.getTime())) {
      onError('Thời điểm bắt đầu hiệu lực không hợp lệ.');
      return;
    }
    if (validFromEdited && validFromDate.getTime() < nowMs - CLIENT_PAST_TOLERANCE_MS) {
      onError('Thời điểm bắt đầu hiệu lực không được nằm trong quá khứ quá 5 phút.');
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
          scopeDepartmentId: effectiveScopeOption.scopeDepartmentId,
          validFrom: !validFromEdited ? new Date().toISOString() : validFromDate.toISOString(),
          validTo: validToDate ? validToDate.toISOString() : null,
        }),
      });

      setIsAssigningRole(false);
      onClose();
      await onSuccess(`Đã gán vai trò thành công cho người dùng ${targetUser.fullName}.`);
    } catch (err) {
      if (err instanceof ApiError) {
        onError(err.message || 'Không thể gán vai trò.');
      } else {
        onError('Đã xảy ra lỗi khi gán vai trò cho người dùng.');
      }
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
        <form onSubmit={handleAssignUserRole} noValidate className="space-y-3.5">
          <div className="space-y-1">
            <label htmlFor="assign-role-id" className="font-medium text-[#222222]">
              Chọn vai trò mới để gán <span className="text-[#C13515]">*</span>
            </label>
            <Select
              id="assign-role-id"
              value={effectiveRoleId}
              onChange={(e) => setAssignRoleId(e.target.value)}
              disabled={activeRoles.length === 0 || isAssigningRole}
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
            </Select>
          </div>

          <div className="space-y-1">
            <label htmlFor="assign-role-scope" className="font-medium text-[#222222]">
              Phạm vi áp dụng vai trò <span className="text-[#C13515]">*</span>
            </label>
            <Select
              id="assign-role-scope"
              value={effectiveScopeOption?.value ?? ''}
              onChange={(e) => setSelectedScopeValue(e.target.value)}
              disabled={scopeOptions.length === 0 || isAssigningRole}
            >
              {scopeOptions.length === 0 ? (
                <option value="">Không có phạm vi phòng ban hợp lệ cho tài khoản người nhận</option>
              ) : (
                scopeOptions.map((opt) => (
                  <option key={opt.value || '__global__'} value={opt.value}>
                    {opt.label}
                  </option>
                ))
              )}
            </Select>
            <p className="text-[11px] text-[#717171]">
              Chỉ cho phép chọn phạm vi bao hàm phòng ban hiện tại của người nhận và nằm trong thẩm
              quyền của bạn.
            </p>
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
                disabled={isAssigningRole}
                onChange={(e) => {
                  setValidFromEdited(true);
                  setAssignValidFrom(e.target.value);
                }}
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
                disabled={isAssigningRole}
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
              disabled={isAssigningRole}
              onClick={onClose}
            />
            <InteractiveHoverButton
              type="submit"
              variant="primary"
              size="sm"
              text="Xác nhận gán"
              disabled={isAssigningRole || activeRoles.length === 0 || !effectiveScopeOption}
              isLoading={isAssigningRole}
            />
          </DialogFooter>
        </form>
      )}
    </div>
  );
}

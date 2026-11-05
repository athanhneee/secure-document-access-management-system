'use client';

import { useState, type FormEvent } from 'react';
import { apiClient, ApiError } from '@/lib/api-client';
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
import { getDefaultRoleAssignmentWindow } from '../helpers';
import type { RoleRow, UserRow } from '../types';

interface AssignRoleModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  targetUser: UserRow | null;
  roles: RoleRow[];
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

export function AssignRoleModal({
  open,
  onOpenChange,
  targetUser,
  roles,
  onClearError,
  onSuccess,
  onError,
}: AssignRoleModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Gán vai trò cho: {targetUser?.fullName}
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Gán vai trò RBAC có thời hạn hiệu lực cho nhân sự
          </DialogDescription>
        </DialogHeader>

        {open && targetUser && (
          <AssignRoleForm
            key={targetUser.id}
            targetUser={targetUser}
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
  roles: RoleRow[];
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

function AssignRoleForm({
  targetUser,
  roles,
  onClose,
  onClearError,
  onSuccess,
  onError,
}: AssignRoleFormProps) {
  const [assignRoleId, setAssignRoleId] = useState(() => roles[0]?.id ?? '');
  const [assignValidFrom, setAssignValidFrom] = useState(
    () => getDefaultRoleAssignmentWindow().validFrom,
  );
  const [assignValidTo, setAssignValidTo] = useState(
    () => getDefaultRoleAssignmentWindow().validTo,
  );
  const [isAssigningRole, setIsAssigningRole] = useState(false);

  async function handleAssignUserRole(e: FormEvent) {
    e.preventDefault();
    if (!assignRoleId) {
      onError('Vui lòng chọn vai trò để gán.');
      return;
    }

    setIsAssigningRole(true);
    onClearError();
    try {
      await apiClient(`/rbac/users/${targetUser.id}/roles`, {
        method: 'POST',
        body: JSON.stringify({
          roleId: assignRoleId,
          scopeDepartmentId: null,
          validFrom: assignValidFrom
            ? new Date(assignValidFrom).toISOString()
            : new Date().toISOString(),
          validTo: assignValidTo ? new Date(assignValidTo).toISOString() : null,
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
    <form onSubmit={handleAssignUserRole} className="space-y-3.5 py-2 text-xs">
      <div className="space-y-1">
        <label htmlFor="assign-role-id" className="font-medium text-[#222222]">
          Chọn vai trò <span className="text-[#C13515]">*</span>
        </label>
        <select
          id="assign-role-id"
          value={assignRoleId}
          onChange={(e) => setAssignRoleId(e.target.value)}
          className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
        >
          {roles.map((r) => (
            <option key={r.id} value={r.id}>
              {r.name} ({r.code})
            </option>
          ))}
        </select>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <label htmlFor="assign-valid-from" className="font-medium text-[#222222]">
            Bắt đầu:
          </label>
          <Input
            id="assign-valid-from"
            type="datetime-local"
            value={assignValidFrom}
            onChange={(e) => setAssignValidFrom(e.target.value)}
            className="h-8 text-xs rounded-full"
          />
        </div>
        <div className="space-y-1">
          <label htmlFor="assign-valid-to" className="font-medium text-[#222222]">
            Kết thúc:
          </label>
          <Input
            id="assign-valid-to"
            type="datetime-local"
            value={assignValidTo}
            onChange={(e) => setAssignValidTo(e.target.value)}
            className="h-8 text-xs rounded-full"
          />
        </div>
      </div>

      <DialogFooter className="pt-2">
        <InteractiveHoverButton
          type="button"
          variant="ghost"
          size="sm"
          text="Hủy"
          onClick={onClose}
        />
        <InteractiveHoverButton
          type="submit"
          variant="primary"
          size="sm"
          text="Xác nhận gán"
          disabled={isAssigningRole}
          isLoading={isAssigningRole}
        />
      </DialogFooter>
    </form>
  );
}

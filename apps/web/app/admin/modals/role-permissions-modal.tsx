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
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { resolveRolePermissionIds } from '../helpers';
import type { PermissionRow, RoleRow } from '../types';

interface RolePermissionsModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  role: RoleRow | null;
  permissions: PermissionRow[];
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

export function RolePermissionsModal({
  open,
  onOpenChange,
  role,
  permissions,
  onClearError,
  onSuccess,
  onError,
}: RolePermissionsModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Phân quyền cho vai trò: {role?.name} ({role?.code})
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Chọn các thẩm quyền hành động gắn liền với vai trò này
          </DialogDescription>
        </DialogHeader>

        {open && role && (
          <RolePermissionsForm
            key={role.id}
            role={role}
            permissions={permissions}
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

interface RolePermissionsFormProps {
  role: RoleRow;
  permissions: PermissionRow[];
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

function RolePermissionsForm({
  role,
  permissions,
  onClose,
  onClearError,
  onSuccess,
  onError,
}: RolePermissionsFormProps) {
  const [selectedPermIds, setSelectedPermIds] = useState<string[]>(() =>
    resolveRolePermissionIds(role, permissions),
  );
  const [isSavingPerms, setIsSavingPerms] = useState(false);

  async function handleSaveRolePermissions(e: FormEvent) {
    e.preventDefault();
    setIsSavingPerms(true);
    onClearError();
    try {
      await apiClient(`/rbac/roles/${role.id}/permissions`, {
        method: 'PUT',
        body: JSON.stringify({ permissionIds: selectedPermIds }),
      });

      onClose();
      await onSuccess(`Đã cập nhật ma trận quyền hạn cho vai trò "${role.name}".`);
    } catch (err) {
      if (err instanceof ApiError) {
        onError(err.message || 'Không thể cập nhật quyền.');
      } else {
        onError('Đã xảy ra lỗi khi cập nhật quyền hạn vai trò.');
      }
    } finally {
      setIsSavingPerms(false);
    }
  }

  return (
    <form onSubmit={handleSaveRolePermissions} className="space-y-4 py-2 text-xs">
      <div className="max-h-80 overflow-y-auto pr-1 space-y-2">
        <div className="grid grid-cols-2 gap-2">
          {permissions.map((perm) => {
            const isChecked = selectedPermIds.includes(perm.id);
            return (
              <label
                key={perm.id}
                htmlFor={`role-perm-${perm.id}`}
                aria-label={perm.code}
                className={`flex items-start gap-2 p-2 rounded-[16px] border cursor-pointer transition-colors ${
                  isChecked
                    ? 'border-[#FF385C] bg-[#FF385C]/5'
                    : 'border-[#ebebeb] hover:bg-[#f7f7f7]'
                }`}
              >
                <input
                  id={`role-perm-${perm.id}`}
                  type="checkbox"
                  checked={isChecked}
                  onChange={(e) => {
                    if (e.target.checked) {
                      setSelectedPermIds((prev) => Array.from(new Set([...prev, perm.id])));
                    } else {
                      setSelectedPermIds((prev) => prev.filter((id) => id !== perm.id));
                    }
                  }}
                  className="mt-0.5 rounded border-[#dddddd] text-[#FF385C] focus:ring-[#FF385C]"
                />
                <div>
                  <div className="font-mono font-bold text-[11px] text-[#222222]">{perm.code}</div>
                  <div className="text-[10px] text-[#717171]">
                    {perm.resource || perm.resourceType} : {perm.action}
                  </div>
                </div>
              </label>
            );
          })}
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
          text="Cập nhật quyền hạn"
          disabled={isSavingPerms}
          isLoading={isSavingPerms}
        />
      </DialogFooter>
    </form>
  );
}

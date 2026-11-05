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
import { Textarea } from '@/components/ui/textarea';
import type { RoleRow } from '../types';

interface EditRoleModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  role: RoleRow | null;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

export function EditRoleModal({
  open,
  onOpenChange,
  role,
  onClearError,
  onSuccess,
  onError,
}: EditRoleModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Chỉnh sửa vai trò: {role?.code}
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Cập nhật tên hiển thị và phần mô tả nghiệp vụ
          </DialogDescription>
        </DialogHeader>

        {open && role && (
          <EditRoleForm
            key={role.id}
            role={role}
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

interface EditRoleFormProps {
  role: RoleRow;
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

function EditRoleForm({ role, onClose, onClearError, onSuccess, onError }: EditRoleFormProps) {
  const [editRoleName, setEditRoleName] = useState(role.name);
  const [editRoleDesc, setEditRoleDesc] = useState(role.description || '');
  const [isEditingRole, setIsEditingRole] = useState(false);

  async function handleEditRole(e: FormEvent) {
    e.preventDefault();
    if (!editRoleName.trim()) return;

    setIsEditingRole(true);
    onClearError();
    try {
      await apiClient(`/rbac/roles/${role.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          name: editRoleName.trim(),
          description: editRoleDesc.trim() || null,
          expectedVersion: role.version,
        }),
      });

      const updatedName = editRoleName.trim();
      onClose();
      await onSuccess(`Đã cập nhật thông tin vai trò "${updatedName}".`);
    } catch (err) {
      if (err instanceof ApiError) {
        onError(err.message || 'Không thể cập nhật vai trò.');
      } else {
        onError('Đã xảy ra lỗi khi cập nhật vai trò.');
      }
    } finally {
      setIsEditingRole(false);
    }
  }

  return (
    <form onSubmit={handleEditRole} className="space-y-3.5 py-2 text-xs">
      <div className="space-y-1">
        <label htmlFor="edit-role-name" className="font-medium text-[#222222]">
          Tên hiển thị <span className="text-[#C13515]">*</span>
        </label>
        <Input
          id="edit-role-name"
          required
          value={editRoleName}
          onChange={(e) => setEditRoleName(e.target.value)}
          className="h-8 text-xs rounded-full"
        />
      </div>

      <div className="space-y-1">
        <label htmlFor="edit-role-desc" className="font-medium text-[#222222]">
          Mô tả vai trò
        </label>
        <Textarea
          id="edit-role-desc"
          rows={3}
          value={editRoleDesc}
          onChange={(e) => setEditRoleDesc(e.target.value)}
          className="text-xs rounded-[20px]"
        />
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
          text="Lưu thay đổi"
          disabled={isEditingRole}
          isLoading={isEditingRole}
        />
      </DialogFooter>
    </form>
  );
}

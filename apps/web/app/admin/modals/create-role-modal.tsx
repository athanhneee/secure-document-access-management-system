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

interface CreateRoleModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

export function CreateRoleModal({
  open,
  onOpenChange,
  onClearError,
  onSuccess,
  onError,
}: CreateRoleModalProps) {
  const [newRoleCode, setNewRoleCode] = useState('');
  const [newRoleName, setNewRoleName] = useState('');
  const [newRoleDesc, setNewRoleDesc] = useState('');
  const [isCreatingRole, setIsCreatingRole] = useState(false);

  async function handleCreateRole(e: FormEvent) {
    e.preventDefault();
    if (!newRoleCode.trim() || !newRoleName.trim()) {
      onError('Mã vai trò và tên vai trò là bắt buộc.');
      return;
    }

    setIsCreatingRole(true);
    onClearError();
    try {
      await apiClient('/rbac/roles', {
        method: 'POST',
        body: JSON.stringify({
          code: newRoleCode.trim().toUpperCase(),
          name: newRoleName.trim(),
          description: newRoleDesc.trim() || null,
        }),
      });

      const createdName = newRoleName.trim();
      onOpenChange(false);
      setNewRoleCode('');
      setNewRoleName('');
      setNewRoleDesc('');
      await onSuccess(`Đã tạo vai trò mới "${createdName}" thành công.`);
    } catch (err) {
      if (err instanceof ApiError) {
        onError(err.message || 'Không thể tạo vai trò mới.');
      } else {
        onError('Đã xảy ra lỗi khi tạo vai trò.');
      }
    } finally {
      setIsCreatingRole(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Tạo vai trò mới
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Mã vai trò gồm chữ in hoa và gạch dưới (ví dụ: AUDIT_SPECIALIST)
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleCreateRole} className="space-y-3.5 py-2 text-xs">
          <div className="space-y-1">
            <label htmlFor="role-code" className="font-medium text-[#222222]">
              Mã vai trò (Code) <span className="text-[#C13515]">*</span>
            </label>
            <Input
              id="role-code"
              required
              value={newRoleCode}
              onChange={(e) => setNewRoleCode(e.target.value.toUpperCase())}
              placeholder="COMPLIANCE_OFFICER"
              className="h-8 text-xs rounded-full uppercase"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="role-name" className="font-medium text-[#222222]">
              Tên vai trò hiển thị <span className="text-[#C13515]">*</span>
            </label>
            <Input
              id="role-name"
              required
              value={newRoleName}
              onChange={(e) => setNewRoleName(e.target.value)}
              placeholder="Cán bộ Giám sát Tuân thủ"
              className="h-8 text-xs rounded-full"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="role-desc" className="font-medium text-[#222222]">
              Mô tả vai trò
            </label>
            <Textarea
              id="role-desc"
              rows={3}
              value={newRoleDesc}
              onChange={(e) => setNewRoleDesc(e.target.value)}
              placeholder="Nhiệm vụ và phạm vi thẩm quyền của vai trò..."
              className="text-xs rounded-[20px]"
            />
          </div>

          <DialogFooter className="pt-2">
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Hủy"
              onClick={() => onOpenChange(false)}
            />
            <InteractiveHoverButton
              type="submit"
              variant="primary"
              size="sm"
              text="Tạo vai trò"
              disabled={isCreatingRole}
              isLoading={isCreatingRole}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

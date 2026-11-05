'use client';

import { useState, type FormEvent } from 'react';
import { UserPlus } from 'lucide-react';
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
import type { DepartmentRow } from '../types';

interface CreateUserModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  departments: DepartmentRow[];
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

export function CreateUserModal({
  open,
  onOpenChange,
  departments,
  onClearError,
  onSuccess,
  onError,
}: CreateUserModalProps) {
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newFullName, setNewFullName] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newDepartmentId, setNewDepartmentId] = useState('');

  async function handleCreateUser(e: FormEvent) {
    e.preventDefault();
    setCreateSubmitting(true);
    onClearError();

    try {
      await apiClient('/users', {
        method: 'POST',
        body: JSON.stringify({
          username: newUsername.trim(),
          email: newEmail.trim(),
          fullName: newFullName.trim(),
          password: newPassword,
          departmentId: newDepartmentId ? newDepartmentId : null,
        }),
      });

      onOpenChange(false);
      setNewUsername('');
      setNewFullName('');
      setNewEmail('');
      setNewPassword('');
      setNewDepartmentId('');
      await onSuccess('Đã tạo tài khoản mới thành công.');
    } catch (err) {
      if (err instanceof ApiError) {
        onError(err.message || 'Không thể tạo tài khoản.');
      } else {
        onError('Đã xảy ra lỗi khi tạo tài khoản.');
      }
    } finally {
      setCreateSubmitting(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Khởi tạo tài khoản người dùng mới
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Điền thông tin định danh và phòng ban trực thuộc. Mật khẩu phải từ 15 ký tự trở lên.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleCreateUser} className="space-y-3.5 py-2">
          <div className="space-y-1">
            <label htmlFor="modal-username" className="text-xs font-medium text-[#222222]">
              Tên đăng nhập <span className="text-[#C13515]">*</span>
            </label>
            <Input
              id="modal-username"
              required
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              placeholder="nguyenvana"
              className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="modal-fullname" className="text-xs font-medium text-[#222222]">
              Họ và tên đầy đủ <span className="text-[#C13515]">*</span>
            </label>
            <Input
              id="modal-fullname"
              required
              value={newFullName}
              onChange={(e) => setNewFullName(e.target.value)}
              placeholder="Nguyễn Văn A"
              className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="modal-email" className="text-xs font-medium text-[#222222]">
              Email nội bộ <span className="text-[#C13515]">*</span>
            </label>
            <Input
              id="modal-email"
              type="email"
              required
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              placeholder="a.nguyen@tochuc.gov.vn"
              className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="modal-password" className="text-xs font-medium text-[#222222]">
              Mật khẩu khởi tạo (Tối thiểu 15 ký tự) <span className="text-[#C13515]">*</span>
            </label>
            <Input
              id="modal-password"
              type="password"
              minLength={15}
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="••••••••••••••••"
              className="h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="modal-department" className="text-xs font-medium text-[#222222]">
              Phòng ban trực thuộc
            </label>
            <select
              id="modal-department"
              value={newDepartmentId}
              onChange={(e) => setNewDepartmentId(e.target.value)}
              className="w-full h-10 rounded-full border border-[#ebebeb] bg-[#f7f7f7] px-4 py-2 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
            >
              <option value="">Không gán phòng ban</option>
              {departments
                .filter((d) => d.isActive)
                .map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name} ({d.code})
                  </option>
                ))}
            </select>
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
              text="Tạo tài khoản"
              icon={<UserPlus size={16} strokeWidth={1.75} aria-hidden="true" />}
              isLoading={createSubmitting}
              disabled={createSubmitting}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

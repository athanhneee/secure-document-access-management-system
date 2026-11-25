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
import type { ClearanceOptionRow, DepartmentRow } from '../types';

interface CreateUserModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  departments: DepartmentRow[];
  clearanceOptions: ClearanceOptionRow[];
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

/**
 * Thuật toán: Tạo Tài Khoản Người Dùng Bắt Buộc Gán Phòng Ban ABAC (`CreateUserModal`)
 * Mục đích: Đồng bộ trường `departmentId` bắt buộc với thuộc tính `SUBJECT_DEPARTMENT` (`is_required = true`) của chính sách ABAC để ngăn tạo tài khoản không thể mở xem tài liệu.
 */
export function CreateUserModal({
  open,
  onOpenChange,
  departments,
  clearanceOptions,
  onClearError,
  onSuccess,
  onError,
}: CreateUserModalProps) {
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newFullName, setNewFullName] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const activeDepartments = departments.filter((d) => d.isActive);
  const defaultDepartmentId = activeDepartments[0]?.id ? String(activeDepartments[0].id) : '';
  const [newDepartmentId, setNewDepartmentId] = useState<string | null>(null);
  const effectiveDepartmentId = newDepartmentId === null ? defaultDepartmentId : newDepartmentId;
  const defaultClearanceId =
    clearanceOptions.find((opt) => opt.code === 'INTERNAL')?.id ?? clearanceOptions[0]?.id ?? '';
  const [newClearanceOptionId, setNewClearanceOptionId] = useState<string | null>(null);
  const effectiveClearanceOptionId =
    newClearanceOptionId === null ? defaultClearanceId : newClearanceOptionId;

  async function handleCreateUser(e: FormEvent) {
    e.preventDefault();
    if (!effectiveDepartmentId) {
      onError('Vui lòng chọn phòng ban trực thuộc cho tài khoản.');
      return;
    }
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
          departmentId: effectiveDepartmentId,
          clearanceOptionId: effectiveClearanceOptionId ? effectiveClearanceOptionId : null,
        }),
      });

      onOpenChange(false);
      setNewUsername('');
      setNewFullName('');
      setNewEmail('');
      setNewPassword('');
      setNewDepartmentId(null);
      setNewClearanceOptionId(null);
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
            Tạo tài khoản người dùng mới
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Nhập thông tin tài khoản và phòng ban trực thuộc. Mật khẩu tối thiểu 15 ký tự.
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
              className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
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
              className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
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
              placeholder="a.nguyen@doanhnghiep.vn"
              className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="modal-password" className="text-xs font-medium text-[#222222]">
              Mật khẩu khởi tạo (tối thiểu 15 ký tự) <span className="text-[#C13515]">*</span>
            </label>
            <Input
              id="modal-password"
              type="password"
              minLength={15}
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="••••••••••••••••"
              className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="modal-department" className="text-xs font-medium text-[#222222]">
              Phòng ban trực thuộc <span className="text-[#C13515]">*</span>
            </label>
            <select
              id="modal-department"
              required
              value={effectiveDepartmentId}
              onChange={(e) => setNewDepartmentId(e.target.value)}
              className="w-full min-h-11 sm:h-10 rounded-full border border-[#ebebeb] bg-[#f7f7f7] px-4 py-2 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
            >
              {activeDepartments.length === 0 ? (
                <option value="" disabled>
                  Chưa có phòng ban đang hoạt động
                </option>
              ) : (
                <option value="" disabled>
                  Chọn phòng ban trực thuộc…
                </option>
              )}
              {activeDepartments.map((d) => (
                <option key={d.id} value={String(d.id)}>
                  {d.name} ({d.code})
                </option>
              ))}
            </select>
            <p className="text-[11px] text-[#717171]">
              Bắt buộc theo chính sách bảo mật để tài khoản được phép tải lên và xem tài liệu.
            </p>
          </div>

          <div className="space-y-1">
            <label htmlFor="modal-clearance" className="text-xs font-medium text-[#222222]">
              Cấp thẩm quyền bảo mật
            </label>
            <select
              id="modal-clearance"
              value={effectiveClearanceOptionId}
              onChange={(e) => setNewClearanceOptionId(e.target.value)}
              className="w-full min-h-11 sm:h-10 rounded-full border border-[#ebebeb] bg-[#f7f7f7] px-4 py-2 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
            >
              <option value="">Chưa cấp (Cấp 0 — Không được truy cập tài liệu mật)</option>
              {clearanceOptions.map((opt) => (
                <option key={opt.id} value={opt.id}>
                  {opt.name} · Cấp {opt.rank}
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
              disabled={createSubmitting || !effectiveDepartmentId}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

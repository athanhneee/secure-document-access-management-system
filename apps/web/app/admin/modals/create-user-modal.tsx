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
import { Select } from '@/components/ui/select';
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
 * Thuật toán: Tạo Tài Khoản Người Dùng Xóa Trắng Mật Khẩu Khi Đóng & Chặn Thoát Giữa Giao Tác (`CreateUserModal`, BUG-095)
 * Mục đích:
 *   - Gọi `resetForm()` xóa sạch toàn bộ dữ liệu nháp (đặc biệt `newPassword = ''`) ngay khi đóng modal để không lộ mật khẩu ở lần mở kế tiếp.
 *   - Khóa đóng modal khi đang gửi API, gắn `autoComplete="new-password"` và `noValidate`.
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
  const [newEmployeeCode, setNewEmployeeCode] = useState('');
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

  function resetForm() {
    setNewUsername('');
    setNewFullName('');
    setNewEmployeeCode('');
    setNewEmail('');
    setNewPassword('');
    setNewDepartmentId(null);
    setNewClearanceOptionId(null);
  }

  const [wasOpen, setWasOpen] = useState(open);
  if (wasOpen !== open) {
    setWasOpen(open);
    if (!open) {
      resetForm();
    }
  }

  function handleDialogOpenChange(nextOpen: boolean) {
    if (!nextOpen && createSubmitting) return;
    if (!nextOpen) {
      resetForm();
      onClearError();
    }
    onOpenChange(nextOpen);
  }

  async function handleCreateUser(e: FormEvent) {
    e.preventDefault();
    if (!newUsername.trim() || !newFullName.trim() || !newEmail.trim()) {
      onError('Vui lòng nhập đầy đủ tên đăng nhập, họ tên và địa chỉ email nội bộ.');
      return;
    }
    if (newPassword.length < 15) {
      onError('Mật khẩu khởi tạo phải có tối thiểu 15 ký tự.');
      return;
    }
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
          employeeCode: newEmployeeCode.trim() || null,
          password: newPassword,
          departmentId: effectiveDepartmentId,
          clearanceOptionId: effectiveClearanceOptionId ? effectiveClearanceOptionId : null,
        }),
      });

      resetForm();
      setCreateSubmitting(false);
      onOpenChange(false);
      await onSuccess('Đã tạo tài khoản mới thành công.');
    } catch (err) {
      if (err instanceof ApiError) {
        onError(err.message || 'Không thể tạo tài khoản.');
      } else {
        onError('Đã xảy ra lỗi khi tạo tài khoản.');
      }
      setCreateSubmitting(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleDialogOpenChange}>
      <DialogContent
        showClose={!createSubmitting}
        className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]"
      >
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Tạo tài khoản người dùng mới
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Nhập thông tin tài khoản và phòng ban trực thuộc. Mật khẩu tối thiểu 15 ký tự.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleCreateUser} noValidate className="space-y-3.5 py-2">
          <div className="space-y-1">
            <label htmlFor="modal-username" className="text-xs font-medium text-[#222222]">
              Tên đăng nhập <span className="text-[#C13515]">*</span>
            </label>
            <Input
              id="modal-username"
              required
              disabled={createSubmitting}
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
              disabled={createSubmitting}
              value={newFullName}
              onChange={(e) => setNewFullName(e.target.value)}
              placeholder="Nguyễn Văn A"
              className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="modal-employee-code" className="text-xs font-medium text-[#222222]">
              Mã nhân viên (tùy chọn)
            </label>
            <Input
              id="modal-employee-code"
              maxLength={50}
              disabled={createSubmitting}
              value={newEmployeeCode}
              onChange={(e) => setNewEmployeeCode(e.target.value)}
              placeholder="VD: NV-2026-001"
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
              disabled={createSubmitting}
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
              autoComplete="new-password"
              minLength={15}
              required
              disabled={createSubmitting}
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
            <Select
              id="modal-department"
              required
              disabled={createSubmitting}
              value={effectiveDepartmentId}
              onChange={(e) => setNewDepartmentId(e.target.value)}
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
            </Select>
            <p className="text-[11px] text-[#717171]">
              Bắt buộc theo chính sách bảo mật để tài khoản được phép tải lên và xem tài liệu.
            </p>
          </div>

          <div className="space-y-1">
            <label htmlFor="modal-clearance" className="text-xs font-medium text-[#222222]">
              Cấp thẩm quyền bảo mật
            </label>
            <Select
              id="modal-clearance"
              disabled={createSubmitting}
              value={effectiveClearanceOptionId}
              onChange={(e) => setNewClearanceOptionId(e.target.value)}
            >
              <option value="">Chưa cấp (Cấp 0 — Không được truy cập tài liệu mật)</option>
              {clearanceOptions.map((opt) => (
                <option key={opt.id} value={opt.id}>
                  {opt.name} · Cấp {opt.rank}
                </option>
              ))}
            </Select>
          </div>

          <DialogFooter className="pt-2">
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Hủy"
              disabled={createSubmitting}
              onClick={() => handleDialogOpenChange(false)}
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

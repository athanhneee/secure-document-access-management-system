'use client';

import { useState, type FormEvent } from 'react';
import { Check } from 'lucide-react';
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
import type { DepartmentRow, UserRow } from '../types';

interface EditUserModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  user: UserRow | null;
  departments: DepartmentRow[];
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

/**
 * Thuật toán: Cập Nhật Hồ Sơ Nhân Sự Có Kiểm Soát Tương Tranh OCC (`EditUserModal`)
 * Mục đích: Đồng bộ trường `fullName`, `email`, `employeeCode`, `departmentId` kèm `expectedVersion` qua `PATCH /users/:id`; chỉ đóng `<dialog>` sau khi máy chủ xác nhận thành công.
 */
export function EditUserModal({
  open,
  onOpenChange,
  user,
  departments,
  onClearError,
  onSuccess,
  onError,
}: EditUserModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Chỉnh sửa tài khoản: @{user?.username}
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Cập nhật họ tên, email, mã nhân viên và đơn vị công tác (phiên bản v{user?.version ?? 0}
            )
          </DialogDescription>
        </DialogHeader>

        {open && user && (
          <EditUserForm
            key={`${user.id}-${user.version}`}
            user={user}
            departments={departments}
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

interface EditUserFormProps {
  user: UserRow;
  departments: DepartmentRow[];
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

function EditUserForm({
  user,
  departments,
  onClose,
  onClearError,
  onSuccess,
  onError,
}: EditUserFormProps) {
  const [fullName, setFullName] = useState(user.fullName);
  const [email, setEmail] = useState(user.email);
  const [employeeCode, setEmployeeCode] = useState(user.employeeCode ?? '');
  const [departmentId, setDepartmentId] = useState(
    user.departmentId ? String(user.departmentId) : '',
  );
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!fullName.trim() || !email.trim()) {
      onError('Vui lòng nhập đầy đủ họ tên và địa chỉ email hợp lệ.');
      return;
    }

    setIsSubmitting(true);
    onClearError();
    try {
      await apiClient(`/users/${user.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          expectedVersion: user.version,
          fullName: fullName.trim(),
          email: email.trim(),
          employeeCode: employeeCode.trim() ? employeeCode.trim() : null,
          departmentId: departmentId ? departmentId : null,
        }),
      });

      onClose();
      await onSuccess(`Đã cập nhật thông tin tài khoản @${user.username} thành công.`);
    } catch (err) {
      onError(
        err instanceof ApiError
          ? err.message || 'Không thể cập nhật thông tin người dùng.'
          : 'Đã xảy ra lỗi khi cập nhật thông tin người dùng.',
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3.5 py-2 text-xs">
      <div className="space-y-1">
        <label htmlFor="edit-user-fullname" className="font-medium text-[#222222]">
          Họ và tên đầy đủ <span className="text-[#C13515]">*</span>
        </label>
        <Input
          id="edit-user-fullname"
          required
          maxLength={150}
          value={fullName}
          onChange={(e) => setFullName(e.target.value)}
          className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
        />
      </div>

      <div className="space-y-1">
        <label htmlFor="edit-user-email" className="font-medium text-[#222222]">
          Email nội bộ <span className="text-[#C13515]">*</span>
        </label>
        <Input
          id="edit-user-email"
          type="email"
          required
          maxLength={255}
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
        />
      </div>

      <div className="space-y-1">
        <label htmlFor="edit-user-empcode" className="font-medium text-[#222222]">
          Mã nhân viên (Employee Code)
        </label>
        <Input
          id="edit-user-empcode"
          maxLength={50}
          value={employeeCode}
          onChange={(e) => setEmployeeCode(e.target.value)}
          placeholder="VD: EMP-00102"
          className="min-h-11 sm:h-9 text-xs font-mono rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
        />
      </div>

      <div className="space-y-1">
        <label htmlFor="edit-user-department" className="font-medium text-[#222222]">
          Phòng ban trực thuộc
        </label>
        <select
          id="edit-user-department"
          value={departmentId}
          onChange={(e) => setDepartmentId(e.target.value)}
          className="w-full min-h-11 sm:h-10 rounded-full border border-[#dddddd] bg-[#ffffff] px-4 py-2 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
        >
          <option value="">Không gán phòng ban</option>
          {departments
            .filter((d) => d.isActive || String(d.id) === departmentId)
            .map((d) => (
              <option key={d.id} value={String(d.id)}>
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
          disabled={isSubmitting}
          onClick={onClose}
        />
        <InteractiveHoverButton
          type="submit"
          variant="primary"
          size="sm"
          text="Lưu thay đổi"
          icon={<Check size={16} strokeWidth={2} aria-hidden="true" />}
          isLoading={isSubmitting}
          disabled={isSubmitting}
        />
      </DialogFooter>
    </form>
  );
}

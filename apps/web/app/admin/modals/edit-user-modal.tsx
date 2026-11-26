'use client';

import { useState, type FormEvent } from 'react';
import { AlertTriangle, Check } from 'lucide-react';
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
import type { ClearanceOptionRow, DepartmentRow, UserRow } from '../types';

interface EditUserModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  user: UserRow | null;
  departments: DepartmentRow[];
  clearanceOptions: ClearanceOptionRow[];
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

/**
 * Thuật toán: Cập Nhật Hồ Sơ Nhân Sự Có Kiểm Soát Tương Tranh OCC (`EditUserModal`)
 * Mục đích: Đồng bộ trường `fullName`, `email`, `employeeCode`, `departmentId`, `clearanceOptionId` kèm `expectedVersion` qua `PATCH /users/:id`; chỉ đóng `<dialog>` sau khi máy chủ xác nhận thành công.
 */
export function EditUserModal({
  open,
  onOpenChange,
  user,
  departments,
  clearanceOptions,
  onClearError,
  onSuccess,
  onError,
}: EditUserModalProps) {
  const [isSubmitting, setIsSubmitting] = useState(false);

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen && isSubmitting) return;
        onOpenChange(nextOpen);
      }}
    >
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Chỉnh sửa tài khoản: @{user?.username}
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Cập nhật họ tên, email, mã nhân viên, phòng ban trực thuộc và cấp thẩm quyền bảo mật.
          </DialogDescription>
        </DialogHeader>

        {open && user && (
          <EditUserForm
            key={`${user.id}-${user.version}-${user.clearanceOptionId ?? 'none'}`}
            user={user}
            departments={departments}
            clearanceOptions={clearanceOptions}
            onSubmittingChange={setIsSubmitting}
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
  clearanceOptions: ClearanceOptionRow[];
  onSubmittingChange: (submitting: boolean) => void;
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

function EditUserForm({
  user,
  departments,
  clearanceOptions,
  onSubmittingChange,
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
  const [clearanceOptionId, setClearanceOptionId] = useState(user.clearanceOptionId ?? '');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const currentRank = user.clearanceRank ?? 0;
  const selectedClearance = clearanceOptions.find(
    (opt) => String(opt.id) === String(clearanceOptionId),
  );
  const nextRank = selectedClearance?.rank ?? 0;
  const isClearanceDowngrade = nextRank < currentRank;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!fullName.trim() || !email.trim()) {
      onError('Vui lòng nhập đầy đủ họ tên và địa chỉ email hợp lệ.');
      return;
    }
    if (!departmentId) {
      onError('Vui lòng chọn phòng ban trực thuộc cho tài khoản.');
      return;
    }

    setIsSubmitting(true);
    onSubmittingChange(true);
    onClearError();
    try {
      await apiClient(`/users/${user.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          expectedVersion: user.version,
          fullName: fullName.trim(),
          email: email.trim(),
          employeeCode: employeeCode.trim() ? employeeCode.trim() : null,
          departmentId,
          clearanceOptionId: clearanceOptionId ? clearanceOptionId : null,
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
      onSubmittingChange(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} noValidate className="space-y-3.5 py-2 text-xs">
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
          Mã nhân viên
        </label>
        <Input
          id="edit-user-empcode"
          maxLength={50}
          value={employeeCode}
          onChange={(e) => setEmployeeCode(e.target.value)}
          placeholder="VD: NV-00102"
          className="min-h-11 sm:h-9 text-xs font-mono rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
        />
      </div>

      <div className="space-y-1">
        <label htmlFor="edit-user-department" className="font-medium text-[#222222]">
          Phòng ban trực thuộc <span className="text-[#C13515]">*</span>
        </label>
        <select
          id="edit-user-department"
          required
          value={departmentId}
          onChange={(e) => setDepartmentId(e.target.value)}
          className="w-full min-h-11 sm:h-10 rounded-full border border-[#dddddd] bg-[#ffffff] px-4 py-2 text-xs text-[#222222] focus:outline-none focus:border-[#222222] focus-visible:ring-2 focus-visible:ring-[#222222]/15 cursor-pointer"
        >
          <option value="" disabled>
            Chọn phòng ban trực thuộc…
          </option>
          {departments
            .filter((d) => d.isActive || String(d.id) === departmentId)
            .map((d) => (
              <option key={d.id} value={String(d.id)}>
                {d.name} ({d.code})
              </option>
            ))}
        </select>
        {!departmentId && (
          <div className="mt-1.5 rounded-[16px] border border-[#E07912]/40 bg-[#f7f7f7] p-2.5 flex items-start gap-2 text-[11px] text-[#717171]">
            <AlertTriangle
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#E07912] mt-0.5"
              aria-hidden="true"
            />
            <span>
              Tài khoản chưa được gán phòng ban nên sẽ bị chính sách bảo mật từ chối truy cập tài
              liệu. Vui lòng chọn phòng ban trước khi lưu.
            </span>
          </div>
        )}
      </div>

      <div className="space-y-1">
        <label htmlFor="edit-user-clearance" className="font-medium text-[#222222]">
          Cấp thẩm quyền bảo mật
        </label>
        <select
          id="edit-user-clearance"
          value={clearanceOptionId}
          onChange={(e) => setClearanceOptionId(e.target.value)}
          className="w-full min-h-11 sm:h-10 rounded-full border border-[#dddddd] bg-[#ffffff] px-4 py-2 text-xs text-[#222222] focus:outline-none focus:border-[#222222] focus-visible:ring-2 focus-visible:ring-[#222222]/15 cursor-pointer"
        >
          <option value="">Chưa cấp / Thu hồi thẩm quyền (Cấp 0)</option>
          {clearanceOptions.map((opt) => (
            <option key={opt.id} value={String(opt.id)}>
              {opt.name} · Cấp {opt.rank}
            </option>
          ))}
        </select>
        {isClearanceDowngrade && (
          <div className="mt-1.5 rounded-[16px] border border-[#E07912]/40 bg-[#f7f7f7] p-2.5 flex items-start gap-2 text-[11px] text-[#717171]">
            <AlertTriangle
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#E07912] mt-0.5"
              aria-hidden="true"
            />
            <span>
              Hạ cấp thẩm quyền (Cấp {currentRank} → Cấp {nextRank}) sẽ tự động thu hồi quyền truy
              cập và ngắt các phiên đọc tài liệu có mức độ mật cao hơn Cấp {nextRank}.
            </span>
          </div>
        )}
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
          disabled={isSubmitting || !departmentId}
        />
      </DialogFooter>
    </form>
  );
}

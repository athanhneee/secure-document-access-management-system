'use client';

import { useMemo, useState, type FormEvent } from 'react';
import { Building2, Check } from 'lucide-react';
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
import { collectDepartmentSubtreeIds } from '../helpers';
import type { DepartmentRow } from '../types';

interface DepartmentModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  department: DepartmentRow | null;
  departments: DepartmentRow[];
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

const DEPT_CODE_REGEX = /^[A-Z0-9_]{2,30}$/u;

/**
 * Thuật toán: Khởi Tạo & Cập Nhật Nút Cây Phòng Ban Chống Chu Trình Cây Con BFS (`DepartmentModal`, BUG-120)
 * Mục đích: Loại trừ cả phòng ban đang sửa lẫn toàn bộ cây con hậu duệ (BFS) khỏi danh sách đơn vị cấp trên,
 * sử dụng thành phần `<Select>` chuẩn hóa và chặn đóng modal khi đang lưu.
 */
export function DepartmentModal({
  open,
  onOpenChange,
  department,
  departments,
  onClearError,
  onSuccess,
  onError,
}: DepartmentModalProps) {
  const isEdit = Boolean(department);
  const [isSubmitting, setIsSubmitting] = useState(false);

  function handleDialogOpenChange(nextOpen: boolean) {
    if (!nextOpen && isSubmitting) return;
    onOpenChange(nextOpen);
  }

  return (
    <Dialog open={open} onOpenChange={handleDialogOpenChange}>
      <DialogContent
        showClose={!isSubmitting}
        className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]"
      >
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            {isEdit ? `Chỉnh sửa phòng ban: ${department?.code}` : 'Thêm phòng ban mới'}
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            {isEdit
              ? 'Cập nhật tên gọi và phòng ban cấp trên.'
              : 'Mã phòng ban từ 2–30 ký tự, gồm chữ in hoa A–Z, chữ số 0–9 hoặc dấu gạch dưới.'}
          </DialogDescription>
        </DialogHeader>

        {open && (
          <DepartmentForm
            key={department ? `${department.id}-${department.version}` : 'create-department'}
            department={department}
            departments={departments}
            isSubmitting={isSubmitting}
            setIsSubmitting={setIsSubmitting}
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

interface DepartmentFormProps {
  department: DepartmentRow | null;
  departments: DepartmentRow[];
  isSubmitting: boolean;
  setIsSubmitting: (busy: boolean) => void;
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

function DepartmentForm({
  department,
  departments,
  isSubmitting,
  setIsSubmitting,
  onClose,
  onClearError,
  onSuccess,
  onError,
}: DepartmentFormProps) {
  const isEdit = Boolean(department);
  const [code, setCode] = useState(department?.code ?? '');
  const [name, setName] = useState(department?.name ?? '');
  const [parentId, setParentId] = useState(department?.parentId ? String(department.parentId) : '');

  const excludedSubtreeIds = useMemo(
    () =>
      department
        ? collectDepartmentSubtreeIds(departments, String(department.id))
        : new Set<string>(),
    [department, departments],
  );

  const parentCandidates = useMemo(
    () =>
      departments.filter(
        (d) => !excludedSubtreeIds.has(String(d.id)) && (d.isActive || String(d.id) === parentId),
      ),
    [departments, excludedSubtreeIds, parentId],
  );

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmedName = name.trim();
    const normalizedCode = code.trim().toUpperCase();

    if (!trimmedName) {
      onError('Tên phòng ban không được để trống.');
      return;
    }
    if (!isEdit && !DEPT_CODE_REGEX.test(normalizedCode)) {
      onError(
        'Mã phòng ban phải dài 2–30 ký tự, chỉ gồm chữ in hoa (A-Z), số (0-9) và dấu gạch dưới (_).',
      );
      return;
    }

    setIsSubmitting(true);
    onClearError();
    try {
      if (department) {
        await apiClient(`/departments/${department.id}`, {
          method: 'PATCH',
          body: JSON.stringify({
            expectedVersion: department.version,
            name: trimmedName,
            parentId: parentId ? parentId : null,
          }),
        });
        setIsSubmitting(false);
        onClose();
        await onSuccess(`Đã cập nhật phòng ban "${trimmedName}" (${department.code}).`);
      } else {
        await apiClient('/departments', {
          method: 'POST',
          body: JSON.stringify({
            code: normalizedCode,
            name: trimmedName,
            parentId: parentId ? parentId : null,
          }),
        });
        setIsSubmitting(false);
        onClose();
        await onSuccess(`Đã thêm phòng ban mới "${trimmedName}" (${normalizedCode}).`);
      }
    } catch (err) {
      onError(
        err instanceof ApiError
          ? err.message || 'Không thể lưu thông tin phòng ban.'
          : 'Đã xảy ra lỗi khi lưu thông tin phòng ban.',
      );
      setIsSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} noValidate className="space-y-3.5 py-2 text-xs">
      <div className="space-y-1">
        <label htmlFor="dept-modal-code" className="font-medium text-[#222222]">
          Mã phòng ban <span className="text-[#C13515]">*</span>
        </label>
        <Input
          id="dept-modal-code"
          required
          disabled={isEdit || isSubmitting}
          maxLength={30}
          value={code}
          onChange={(e) => setCode(e.target.value.toUpperCase())}
          placeholder="VD: LEGAL_COMPLIANCE"
          className="min-h-11 sm:h-9 text-xs font-mono uppercase rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] disabled:bg-[#f7f7f7] disabled:text-[#717171]"
        />
      </div>

      <div className="space-y-1">
        <label htmlFor="dept-modal-name" className="font-medium text-[#222222]">
          Tên phòng ban <span className="text-[#C13515]">*</span>
        </label>
        <Input
          id="dept-modal-name"
          required
          disabled={isSubmitting}
          maxLength={150}
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="VD: Ban Pháp chế & Tuân thủ"
          className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
        />
      </div>

      <div className="space-y-1">
        <label htmlFor="dept-modal-parent" className="font-medium text-[#222222]">
          Phòng ban cấp trên
        </label>
        <Select
          id="dept-modal-parent"
          disabled={isSubmitting}
          value={parentId}
          onChange={(e) => setParentId(e.target.value)}
        >
          <option value="">Trụ sở chính (Cấp cao nhất)</option>
          {parentCandidates.map((d) => (
            <option key={d.id} value={String(d.id)}>
              {d.name} ({d.code})
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
          disabled={isSubmitting}
          onClick={onClose}
        />
        <InteractiveHoverButton
          type="submit"
          variant="primary"
          size="sm"
          text={isEdit ? 'Lưu thay đổi' : 'Tạo phòng ban'}
          icon={
            isEdit ? (
              <Check size={16} strokeWidth={2} aria-hidden="true" />
            ) : (
              <Building2 size={16} strokeWidth={1.75} aria-hidden="true" />
            )
          }
          isLoading={isSubmitting}
          disabled={isSubmitting}
        />
      </DialogFooter>
    </form>
  );
}

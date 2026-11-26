'use client';

import { type FormEvent } from 'react';
import { Calendar, Check, Pencil, RefreshCw, X } from 'lucide-react';
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
import { Textarea } from '@/components/ui/textarea';
import { getMinRetentionDate, validateRetentionDateInput } from '../helpers';
import type { DepartmentLookupItem, DocumentItem } from '../types';

interface EditDocumentModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  document: DocumentItem | null;
  departments: DepartmentLookupItem[];
  title: string;
  onTitleChange: (value: string) => void;
  description: string;
  onDescriptionChange: (value: string) => void;
  departmentId: number;
  onDepartmentIdChange: (value: number) => void;
  retentionDate: string;
  onRetentionDateChange: (value: string) => void;
  isLoadingDetail: boolean;
  isSaving: boolean;
  onSubmit: (e: FormEvent) => void;
}

/**
 * Thuật toán: Biểu Mẫu Cập Nhật Siêu Dữ Liệu Tài Liệu (`PATCH /documents/:id`, BUG-030 / HIGH-16)
 * Mục đích:
 *   - Cho phép chủ sở hữu cập nhật tiêu đề (`1..255`), mô tả (`<= 2000`), phòng ban chủ quản thuộc phạm vi được phép và thời hạn lưu trữ bảo mật (`YYYY-MM-DD` hoặc gỡ bỏ).
 *   - Khóa đóng hộp thoại khi đang lưu (`showClose={!isSaving}`), tắt pop-up HTML5 bằng `noValidate` và tuân thủ chuẩn `staff-001` không viền đỏ.
 */
export function EditDocumentModal({
  open,
  onOpenChange,
  document,
  departments,
  title,
  onTitleChange,
  description,
  onDescriptionChange,
  departmentId,
  onDepartmentIdChange,
  retentionDate,
  onRetentionDateChange,
  isLoadingDetail,
  isSaving,
  onSubmit,
}: EditDocumentModalProps) {
  const minRetentionDate = getMinRetentionDate();
  const retentionError = validateRetentionDateInput(retentionDate);
  const trimmedTitle = title.trim();

  const hasCurrentDeptInList = departments.some((d) => Number(d.id) === Number(departmentId));
  const departmentOptions: DepartmentLookupItem[] =
    !hasCurrentDeptInList && document?.departmentId
      ? [
          {
            id: document.departmentId,
            code: String(document.departmentId),
            name: document.departmentName || `Phòng ban #${document.departmentId}`,
          },
          ...departments,
        ]
      : departments;

  const isSubmitDisabled =
    isSaving ||
    isLoadingDetail ||
    !trimmedTitle ||
    trimmedTitle.length > 255 ||
    description.length > 2000 ||
    Boolean(retentionError);

  return (
    <Dialog open={open} onOpenChange={(next) => !isSaving && onOpenChange(next)}>
      <DialogContent
        showClose={!isSaving}
        className="max-w-lg max-h-[88vh] overflow-y-auto border-[#ebebeb] bg-[#ffffff] text-[#222222]"
      >
        <DialogHeader>
          <div className="flex items-center gap-2">
            <Pencil size={20} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
            <DialogTitle className="text-base font-semibold text-[#222222]">
              Chỉnh sửa thông tin tài liệu
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Cập nhật tiêu đề, mô tả, phòng ban chủ quản và thời hạn lưu trữ cho tài liệu{' '}
            <strong className="text-[#222222]">{document?.documentCode || document?.title}</strong>.
          </DialogDescription>
        </DialogHeader>

        {isLoadingDetail ? (
          <div className="py-8 text-center text-xs text-[#717171]">
            <RefreshCw
              size={20}
              strokeWidth={1.75}
              className="animate-spin mx-auto mb-2 text-[#FF385C]"
              aria-hidden="true"
            />
            Đang tải chi tiết tài liệu…
          </div>
        ) : (
          <form onSubmit={onSubmit} noValidate className="space-y-3.5 py-2 text-xs">
            <div className="space-y-1">
              <label htmlFor="edit-doc-title" className="font-medium text-[#222222]">
                Tiêu đề tài liệu <span className="text-[#C13515]">*</span>
              </label>
              <Input
                id="edit-doc-title"
                maxLength={255}
                disabled={isSaving}
                value={title}
                onChange={(e) => onTitleChange(e.target.value)}
                placeholder="Nhập tiêu đề tài liệu (tối đa 255 ký tự)…"
                className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#717171]"
              />
              <p className="text-[11px] text-[#717171]">{trimmedTitle.length}/255 ký tự</p>
            </div>

            <div className="space-y-1">
              <label htmlFor="edit-doc-dept" className="font-medium text-[#222222]">
                Phòng ban chủ quản <span className="text-[#C13515]">*</span>
              </label>
              <Select
                id="edit-doc-dept"
                disabled={isSaving || departmentOptions.length === 0}
                value={departmentOptions.length === 0 ? '' : String(departmentId)}
                onChange={(e) => onDepartmentIdChange(Number(e.target.value))}
              >
                {departmentOptions.length === 0 ? (
                  <option value="">Chưa có dữ liệu phòng ban</option>
                ) : (
                  departmentOptions.map((dept) => (
                    <option key={dept.id} value={String(dept.id)}>
                      {dept.name}
                    </option>
                  ))
                )}
              </Select>
            </div>

            <div className="space-y-1">
              <label htmlFor="edit-doc-description" className="font-medium text-[#222222]">
                Mô tả tài liệu (tùy chọn)
              </label>
              <Textarea
                id="edit-doc-description"
                rows={3}
                maxLength={2000}
                disabled={isSaving}
                value={description}
                onChange={(e) => onDescriptionChange(e.target.value)}
                placeholder="Tóm tắt nội dung nghiệp vụ và phạm vi áp dụng của tài liệu…"
                className="text-xs rounded-[18px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#717171]"
              />
              <p className="text-[11px] text-[#717171]">{description.length}/2000 ký tự</p>
            </div>

            <div className="space-y-1">
              <label htmlFor="edit-doc-retention" className="font-medium text-[#222222]">
                Thời hạn lưu trữ bảo mật (tùy chọn)
              </label>
              <div className="flex items-center gap-2">
                <div className="relative flex-1">
                  <Calendar
                    size={16}
                    strokeWidth={1.75}
                    className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-[#717171]"
                    aria-hidden="true"
                  />
                  <Input
                    id="edit-doc-retention"
                    type="date"
                    min={minRetentionDate}
                    disabled={isSaving}
                    value={retentionDate}
                    onChange={(e) => onRetentionDateChange(e.target.value)}
                    className="pl-10 min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222]"
                  />
                </div>
                {retentionDate && (
                  <button
                    type="button"
                    disabled={isSaving}
                    onClick={() => onRetentionDateChange('')}
                    aria-label="Gỡ bỏ thời hạn lưu trữ"
                    title="Gỡ bỏ thời hạn lưu trữ"
                    className="inline-flex h-11 w-11 sm:h-9 sm:w-9 shrink-0 items-center justify-center rounded-full border border-[#dddddd] bg-[#ffffff] text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] cursor-pointer disabled:opacity-50"
                  >
                    <X size={16} strokeWidth={2} aria-hidden="true" />
                  </button>
                )}
              </div>
              {retentionError ? (
                <p role="alert" className="text-xs font-medium text-[#C13515]">
                  {retentionError}
                </p>
              ) : (
                <p className="text-[11px] text-[#717171]">
                  Để trống nếu không giới hạn ngày lưu trữ. Hệ thống sẽ cảnh báo trước khi hết hạn.
                </p>
              )}
            </div>

            <DialogFooter className="pt-2">
              <InteractiveHoverButton
                type="button"
                variant="ghost"
                size="sm"
                text="Hủy"
                disabled={isSaving}
                onClick={() => onOpenChange(false)}
              />
              <InteractiveHoverButton
                type="submit"
                variant="primary"
                size="sm"
                text={isSaving ? 'Đang lưu…' : 'Lưu thay đổi'}
                icon={<Check size={16} strokeWidth={2} aria-hidden="true" />}
                isLoading={isSaving}
                disabled={isSubmitDisabled}
              />
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

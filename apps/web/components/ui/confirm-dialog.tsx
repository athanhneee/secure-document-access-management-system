'use client';

import { AlertTriangle, Check } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from './dialog';
import { InteractiveHoverButton } from './interactive-hover-button';

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmText?: string | undefined;
  confirmLabel?: string | undefined;
  cancelText?: string | undefined;
  variant?: 'danger' | 'primary' | undefined;
  isLoading?: boolean | undefined;
  onConfirm: () => void | Promise<void>;
}

/**
 * Thuật toán: Hộp thoại Xác nhận Hành động Nhạy cảm Tuân thủ WCAG (`ConfirmDialog`)
 * Mục đích: Thay thế hoàn toàn hộp thoại xác nhận mặc định của trình duyệt bằng `<dialog>` `.showModal()` có bẫy tiêu điểm bàn phím, hỗ trợ phím `Escape` và trạng thái chờ bất đồng bộ.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmText,
  confirmLabel,
  cancelText = 'Hủy bỏ',
  variant = 'danger',
  isLoading = false,
  onConfirm,
}: ConfirmDialogProps) {
  const resolvedConfirmText = confirmLabel ?? confirmText ?? 'Xác nhận thực hiện';

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen && isLoading) return;
        onOpenChange(nextOpen);
      }}
    >
      <DialogContent className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base font-semibold text-[#222222]">
            <AlertTriangle
              size={20}
              strokeWidth={1.75}
              className={
                variant === 'danger' ? 'text-[#C13515] shrink-0' : 'text-[#E31C5F] shrink-0'
              }
              aria-hidden="true"
            />
            <span>{title}</span>
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171] leading-relaxed">
            {description}
          </DialogDescription>
        </DialogHeader>

        <DialogFooter className="pt-2">
          <InteractiveHoverButton
            type="button"
            variant="ghost"
            size="sm"
            text={cancelText}
            disabled={isLoading}
            onClick={() => onOpenChange(false)}
          />
          <InteractiveHoverButton
            type="button"
            variant={variant}
            size="sm"
            text={resolvedConfirmText}
            icon={<Check size={16} strokeWidth={2} aria-hidden="true" />}
            isLoading={isLoading}
            disabled={isLoading}
            onClick={() => onConfirm()}
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

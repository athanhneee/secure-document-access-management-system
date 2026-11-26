import * as React from 'react';
import { cn } from '@/lib/utils';

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  error?: string;
  helperText?: string;
}

/**
 * Thuật toán: Vùng Nhập Văn Bản Đa Dòng Liên Kết Lỗi Trợ Năng WAI-ARIA (`Textarea`)
 * Mục đích: Đồng bộ trạng thái `aria-invalid` và liên kết `aria-describedby` tự động theo `id` cho các trường ghi chú xử lý sự cố và lý do cấp quyền.
 */
export const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className, error, helperText, id, ...props }, ref) => {
    const errorId = id && error ? `${id}-error` : undefined;
    const helperId = id && helperText ? `${id}-helper` : undefined;
    const describedBy = [errorId, helperId].filter(Boolean).join(' ') || undefined;

    return (
      <div className="w-full">
        <textarea
          id={id}
          className={cn(
            'flex min-h-[90px] w-full rounded-[28px] border border-[#dddddd] bg-[#ffffff] p-4 text-xs text-[#222222] shadow-2xs transition-all placeholder:text-[#b0b0b0] focus-visible:outline-none focus-visible:border-[#222222] focus-visible:ring-2 focus-visible:ring-[#222222]/15 disabled:cursor-not-allowed disabled:opacity-50',
            error && 'border-[#222222]',
            className,
          )}
          ref={ref}
          aria-invalid={error ? 'true' : undefined}
          aria-describedby={describedBy}
          {...props}
        />
        {helperText && !error && (
          <p id={helperId} className="mt-1 text-xs text-[#717171]">
            {helperText}
          </p>
        )}
        {error && (
          <p id={errorId} className="mt-1 text-xs text-[#C13515] font-medium">
            {error}
          </p>
        )}
      </div>
    );
  },
);
Textarea.displayName = 'Textarea';

'use client';

import * as React from 'react';
import { cn } from '@/lib/utils';

export interface DialogContextValue {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  titleId: string;
  descriptionId: string;
  hasDescription: boolean;
  setHasDescription: (present: boolean) => void;
}

export const DialogContext = React.createContext<DialogContextValue>({
  open: false,
  onOpenChange: () => {},
  titleId: '',
  descriptionId: '',
  hasDescription: false,
  setHasDescription: () => {},
});

/**
 * Thuật toán: Các Thành Phần Cấu Trúc Đầu Đề, Mô Tả ARIA & Chân Trang Hộp Thoại (`DialogHeader`, `DialogTitle`, `DialogDescription`, `DialogFooter`)
 * Mục đích: Giữ khoảng đệm `pr-12` tránh đè nút đóng `X` trên `375px` và tự động đăng ký `aria-describedby` khi có mô tả.
 */
export function DialogHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn('flex flex-col space-y-1 text-left mb-3.5 pr-11', className)} {...props} />
  );
}

export function DialogTitle({
  id,
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLHeadingElement>) {
  const { titleId } = React.useContext(DialogContext);
  return (
    <h2
      id={id ?? titleId}
      className={cn(
        'text-base sm:text-lg font-semibold leading-snug tracking-tight text-[#222222]',
        className,
      )}
      {...props}
    >
      {children}
    </h2>
  );
}

export function DialogDescription({
  id,
  className,
  ...props
}: React.HTMLAttributes<HTMLParagraphElement>) {
  const { descriptionId, setHasDescription } = React.useContext(DialogContext);
  React.useEffect(() => {
    setHasDescription(true);
    return () => setHasDescription(false);
  }, [setHasDescription]);
  return (
    <p
      id={id ?? descriptionId}
      className={cn('text-xs text-[#717171] mt-0.5 leading-relaxed', className)}
      {...props}
    />
  );
}

export function DialogFooter({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'flex flex-col-reverse sm:flex-row sm:flex-wrap sm:justify-end mt-5 gap-2',
        className,
      )}
      {...props}
    />
  );
}

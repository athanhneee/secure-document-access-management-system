import * as React from 'react';
import { cn } from '@/lib/utils';

/**
 * Thuật toán: Các Thành Phần Khung Thẻ Bề Mặt Chuẩn Hóa Bo Góc `28px` (`Card`, `CardHeader`, `CardTitle`, `CardDescription`, `CardContent`, `CardFooter`)
 * Mục đích: Đồng bộ khoảng đệm thích ứng di động (`p-4 sm:p-5`) và hiệu ứng nâng nhẹ bề mặt có bảo vệ `prefers-reduced-motion`.
 */
export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'rounded-[28px] border border-[#ebebeb] bg-[#ffffff] text-[#222222] shadow-[0_6px_20px_rgba(0,0,0,0.04)] hover-card',
        className,
      )}
      {...props}
    />
  );
}

export function CardHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('flex flex-col space-y-1 p-4 sm:p-5', className)} {...props} />;
}

export function CardTitle({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3
      className={cn(
        'text-sm sm:text-base font-semibold leading-snug tracking-tight text-[#222222]',
        className,
      )}
      {...props}
    >
      {children}
    </h3>
  );
}

export function CardDescription({
  className,
  ...props
}: React.HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn('text-xs text-[#717171] leading-relaxed', className)} {...props} />;
}

export function CardContent({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('p-4 sm:p-5 pt-0', className)} {...props} />;
}

export function CardFooter({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('flex items-center p-4 sm:p-5 pt-0', className)} {...props} />;
}

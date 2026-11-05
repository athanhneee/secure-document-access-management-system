import * as React from 'react';
import { cn } from '@/lib/utils';

export interface BadgeProps extends Omit<React.HTMLAttributes<HTMLSpanElement>, 'style'> {
  variant?:
    | 'default'
    | 'secondary'
    | 'destructive'
    | 'danger'
    | 'outline'
    | 'success'
    | 'warning'
    | 'info'
    | 'primary'
    | 'neutral';
  showDot?: boolean;
}

export function Badge({
  className,
  variant = 'default',
  showDot = true,
  children,
  ...props
}: BadgeProps) {
  // CONFLICT-RESOLVED: Giữ biểu diễn phẳng staff-001 qua lớp CSS .staff-badge trong globals.css, loại bỏ hoàn toàn thuộc tính style nội tuyến để tương thích CSP nonce.
  const styles: Record<string, { text: string; dot: string }> = {
    default: { text: 'text-[#008489]', dot: 'bg-[#008489]' },
    info: { text: 'text-[#008489]', dot: 'bg-[#008489]' },
    success: { text: 'text-[#008A05]', dot: 'bg-[#008A05]' },
    warning: { text: 'text-[#E07912]', dot: 'bg-[#E07912]' },
    destructive: { text: 'text-[#C13515]', dot: 'bg-[#C13515]' },
    danger: { text: 'text-[#C13515]', dot: 'bg-[#C13515]' },
    primary: { text: 'text-[#FF385C]', dot: 'bg-[#FF385C]' },
    secondary: { text: 'text-[#717171]', dot: 'bg-[#717171]' },
    outline: { text: 'text-[#717171]', dot: 'bg-[#717171]' },
    neutral: { text: 'text-[#717171]', dot: 'bg-[#717171]' },
  };

  const fallbackStyle = { text: 'text-[#008489]', dot: 'bg-[#008489]' };
  const currentStyle = (variant ? styles[variant] : undefined) ?? fallbackStyle;

  return (
    <span
      className={cn(
        'staff-badge inline-flex items-center gap-1.5 text-xs font-semibold select-none',
        currentStyle.text,
        className,
      )}
      {...props}
    >
      {showDot && <span className={cn('dot', currentStyle.dot)} aria-hidden="true" />}
      <span>{children}</span>
    </span>
  );
}

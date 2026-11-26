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

/**
 * Thuật toán: Biểu Diễn Nhãn Trạng Thái Phẳng Theo Mẫu `staff-001` & Đảm Bảo Tương Phản WCAG 2.1 AA (`Badge`)
 * Mục đích: Hiển thị chấm tròn ngữ nghĩa `6px` kèm chữ in đậm không nền, không viền hộp capsule (`bg-transparent border-0 p-0`) với mọi biến thể màu chữ đều đạt độ tương phản `>= 4.5:1` trên nền trắng `#FFFFFF`.
 */
export function Badge({
  className,
  variant = 'default',
  showDot = true,
  children,
  ...props
}: BadgeProps) {
  // CONFLICT-RESOLVED: Giữ biểu diễn phẳng staff-001 qua lớp CSS .staff-badge kết hợp bg-transparent border-0 p-0, loại bỏ hoàn toàn thuộc tính style nội tuyến để tương thích CSP nonce.
  const styles: Record<string, { text: string; dot: string }> = {
    default: { text: 'text-[#008489]', dot: 'bg-[#008489]' },
    info: { text: 'text-[#008489]', dot: 'bg-[#008489]' },
    success: { text: 'text-[#008A05]', dot: 'bg-[#008A05]' },
    warning: { text: 'text-[#222222]', dot: 'bg-[#E07912]' },
    destructive: { text: 'text-[#C13515]', dot: 'bg-[#C13515]' },
    danger: { text: 'text-[#C13515]', dot: 'bg-[#C13515]' },
    primary: { text: 'text-[#E31C5F]', dot: 'bg-[#FF385C]' },
    secondary: { text: 'text-[#717171]', dot: 'bg-[#717171]' },
    outline: { text: 'text-[#717171]', dot: 'bg-[#717171]' },
    neutral: { text: 'text-[#717171]', dot: 'bg-[#717171]' },
  };

  const fallbackStyle = { text: 'text-[#008489]', dot: 'bg-[#008489]' };
  const currentStyle = (variant ? styles[variant] : undefined) ?? fallbackStyle;

  return (
    <span
      className={cn(
        'staff-badge bg-transparent border-0 p-0 inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap text-xs font-semibold select-none',
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

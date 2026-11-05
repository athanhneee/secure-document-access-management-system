import * as React from 'react';
import { ShieldCheck, ShieldAlert, Lock, AlertTriangle, Flame } from 'lucide-react';
import { cn } from '@/lib/utils';

export type ClassificationCode =
  'UNCLASSIFIED' | 'INTERNAL' | 'RESTRICTED' | 'CONFIDENTIAL' | 'SECRET' | 'TOP_SECRET' | string;

export interface ClassificationBadgeProps extends Omit<
  React.HTMLAttributes<HTMLSpanElement>,
  'style'
> {
  code?: ClassificationCode;
  level?: ClassificationCode;
  rank?: number;
  showRank?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

/**
 * Thuật toán: Ánh Xạ Phân Tầng Nhãn Mật Độ Bảo Mật Tài Liệu 5 Cấp (5-Tier Security Classification Badge Mapper)
 * Mục đích: Chuẩn hóa mã phân loại mật (`UNCLASSIFIED` -> `TOP_SECRET`) sang biểu diễn phẳng `staff-001` với màu chữ chuẩn, biểu tượng cảnh báo `16px`/`20px` và chỉ số thứ bậc `R0..R4`.
 * Cơ chế hoạt động:
 *   - Chuẩn hóa chuỗi đầu vào sang chữ in hoa, phân nhánh tất định theo 5 cấp độ bảo mật tiêu chuẩn và sinh nhãn trợ năng `aria-label` tương ứng.
 */
export function ClassificationBadge({
  code,
  level,
  rank,
  showRank = false,
  size = 'md',
  className,
  ...props
}: ClassificationBadgeProps) {
  const normalized = (level ?? code ?? '').toUpperCase();

  const sizeClasses = {
    sm: 'text-xs gap-1',
    md: 'text-xs gap-1.5',
    lg: 'text-sm gap-2',
  };

  // CONFLICT-RESOLVED: Chuẩn hóa kích thước icon về thang {16, 20} và loại bỏ thuộc tính style nội tuyến để tuân thủ CSP nghiêm ngặt.
  const iconPixelSize: 16 | 20 = size === 'lg' ? 20 : 16;

  // CONFLICT-RESOLVED: Đồng bộ nhãn cấp bậc hiển thị (UNCLASSIFIED: R0, INTERNAL/RESTRICTED: R1, CONFIDENTIAL: R2, SECRET: R3, TOP_SECRET: R4) khớp với thang bậc CSDL và @sda/contracts.
  switch (normalized) {
    case 'UNCLASSIFIED':
      return (
        <span
          className={cn(
            'staff-badge inline-flex items-center font-semibold text-[#717171] select-none tracking-wide',
            sizeClasses[size],
            className,
          )}
          title="Tài liệu không phân loại mật (Cấp 0)"
          aria-label={`Mức mật: Không mật (Unclassified)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <ShieldCheck
            size={iconPixelSize}
            strokeWidth={1.75}
            className="shrink-0"
            aria-hidden="true"
          />
          <span>KHÔNG MẬT</span>
          {showRank && <span className="opacity-70 font-bold text-[13px]">· R0</span>}
        </span>
      );

    case 'INTERNAL':
    case 'RESTRICTED':
      return (
        <span
          className={cn(
            'staff-badge inline-flex items-center font-semibold text-[#008489] select-none tracking-wide',
            sizeClasses[size],
            className,
          )}
          title="Tài liệu lưu hành nội bộ (Cấp 1)"
          aria-label={`Mức mật: Nội bộ (Internal)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <ShieldAlert
            size={iconPixelSize}
            strokeWidth={1.75}
            className="shrink-0"
            aria-hidden="true"
          />
          <span>NỘI BỘ</span>
          {showRank && <span className="opacity-75 font-bold text-[13px]">· R1</span>}
        </span>
      );

    case 'CONFIDENTIAL':
      // CONFLICT-RESOLVED: Chuẩn hóa màu nhãn mức MẬT sang màu nhấn thương hiệu #FF385C theo rules/ui-design-system.md §5.
      return (
        <span
          className={cn(
            'staff-badge inline-flex items-center font-bold text-[#FF385C] select-none tracking-wide',
            sizeClasses[size],
            className,
          )}
          title="Tài liệu mật theo quy định tổ chức (Cấp 2)"
          aria-label={`Mức mật: Mật (Confidential)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <Lock size={iconPixelSize} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
          <span>MẬT</span>
          {showRank && <span className="opacity-75 font-bold text-[13px]">· R2</span>}
        </span>
      );

    case 'SECRET':
      return (
        <span
          className={cn(
            'staff-badge inline-flex items-center font-bold text-[#E07912] select-none tracking-wider',
            sizeClasses[size],
            className,
          )}
          title="Tài liệu tối mật (Cấp 3)"
          aria-label={`Mức mật: Tối mật (Secret)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <AlertTriangle
            size={iconPixelSize}
            strokeWidth={1.75}
            className="shrink-0"
            aria-hidden="true"
          />
          <span>TỐI MẬT</span>
          {showRank && <span className="opacity-75 font-bold text-[13px]">· R3</span>}
        </span>
      );

    case 'TOP_SECRET':
      return (
        <span
          className={cn(
            'staff-badge inline-flex items-center font-extrabold text-[#C13515] select-none tracking-wider uppercase',
            sizeClasses[size],
            className,
          )}
          title="Tài liệu tuyệt mật mức cao nhất (Cấp 4)"
          aria-label={`Mức mật: Tuyệt mật (Top Secret)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <Flame
            size={iconPixelSize}
            strokeWidth={1.75}
            className="shrink-0 animate-pulse"
            aria-hidden="true"
          />
          <span>TUYỆT MẬT</span>
          {showRank && <span className="opacity-80 font-bold text-[13px]">· R4</span>}
        </span>
      );

    default:
      return (
        <span
          className={cn(
            'staff-badge inline-flex items-center text-xs font-semibold text-[#717171] select-none',
            className,
          )}
          {...props}
        >
          <span>{normalized || 'CHƯA PHÂN LOẠI'}</span>
        </span>
      );
  }
}

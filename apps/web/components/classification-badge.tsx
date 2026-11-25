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
  subject?: 'document' | 'user';
  size?: 'sm' | 'md' | 'lg';
}

/**
 * Thuật toán: Ánh Xạ Phân Tầng Nhãn Mật Độ Bảo Mật Tài Liệu & Cấp Thẩm Quyền 5 Cấp Đạt Chuẩn Tương Phản WCAG 2.1 AA (`ClassificationBadge`)
 * Mục đích:
 *   - Chuẩn hóa mã phân loại mật (`UNCLASSIFIED` -> `TOP_SECRET`) sang biểu diễn phẳng `staff-001` hoàn toàn không viền, không nền (`background: transparent`, `border: none`, `padding: 0`) kèm nhãn ngữ cảnh phù hợp cho tài liệu hoặc thẩm quyền người dùng.
 *   - Đảm bảo mọi màu chữ trên nền sáng `#FFFFFF` đạt tỷ lệ tương phản `>= 4.5:1` theo chuẩn WCAG 2.1 AA: `#717171` (`4.88:1`) cho `UNCLASSIFIED`, `#008489` (`4.50:1`) cho `INTERNAL`, `#222222` (`15.91:1` kèm biểu tượng khóa `#E07912`) cho `CONFIDENTIAL`, và `#C13515` (`5.54:1`) cho `SECRET` / `TOP_SECRET`.
 */
export function ClassificationBadge({
  code,
  level,
  rank,
  showRank = false,
  subject = 'document',
  size = 'md',
  className,
  ...props
}: ClassificationBadgeProps) {
  const normalized = (level ?? code ?? '').toUpperCase();
  const isUserSubject = subject === 'user';
  const subjectPrefix = isUserSubject ? 'Cấp thẩm quyền bảo mật' : 'Mức độ mật tài liệu';

  const sizeClasses = {
    sm: 'text-xs gap-1',
    md: 'text-xs gap-1.5',
    lg: 'text-sm gap-2',
  };

  // CONFLICT-RESOLVED: Chuẩn hóa kích thước icon về thang {16, 20} và loại bỏ thuộc tính style nội tuyến để tuân thủ CSP nghiêm ngặt.
  const iconPixelSize: 16 | 20 = size === 'lg' ? 20 : 16;

  // CONFLICT-RESOLVED: Đồng bộ nhãn cấp bậc hiển thị (UNCLASSIFIED: Cấp 0, INTERNAL/RESTRICTED: Cấp 1, CONFIDENTIAL: Cấp 2, SECRET: Cấp 3, TOP_SECRET: Cấp 4) và nâng cấp màu chữ đạt tương phản WCAG 2.1 AA >= 4.5:1.
  switch (normalized) {
    case 'UNCLASSIFIED':
      return (
        <span
          className={cn(
            'staff-badge bg-transparent border-0 p-0 inline-flex items-center font-semibold text-[#717171] select-none tracking-wide',
            sizeClasses[size],
            className,
          )}
          title={
            isUserSubject
              ? 'Cấp thẩm quyền bảo mật: Không mật (Cấp 0)'
              : 'Tài liệu không phân loại mật (Cấp 0)'
          }
          aria-label={`${subjectPrefix}: Không mật${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <ShieldCheck
            size={iconPixelSize}
            strokeWidth={1.75}
            className="shrink-0"
            aria-hidden="true"
          />
          <span>KHÔNG MẬT</span>
          {showRank && <span className="font-bold text-[13px]">· Cấp 0</span>}
        </span>
      );

    case 'INTERNAL':
    case 'RESTRICTED':
      return (
        <span
          className={cn(
            'staff-badge bg-transparent border-0 p-0 inline-flex items-center font-semibold text-[#008489] select-none tracking-wide',
            sizeClasses[size],
            className,
          )}
          title={
            isUserSubject
              ? 'Cấp thẩm quyền bảo mật: Nội bộ (Cấp 1)'
              : 'Tài liệu lưu hành nội bộ (Cấp 1)'
          }
          aria-label={`${subjectPrefix}: Nội bộ${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <ShieldAlert
            size={iconPixelSize}
            strokeWidth={1.75}
            className="shrink-0"
            aria-hidden="true"
          />
          <span>NỘI BỘ</span>
          {showRank && <span className="font-bold text-[13px]">· Cấp 1</span>}
        </span>
      );

    case 'CONFIDENTIAL':
      return (
        <span
          className={cn(
            'staff-badge bg-transparent border-0 p-0 inline-flex items-center font-bold text-[#222222] select-none tracking-wide',
            sizeClasses[size],
            className,
          )}
          title={
            isUserSubject
              ? 'Cấp thẩm quyền bảo mật: Mật (Cấp 2)'
              : 'Tài liệu mật theo quy định tổ chức (Cấp 2)'
          }
          aria-label={`${subjectPrefix}: Mật${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <Lock
            size={iconPixelSize}
            strokeWidth={1.75}
            className="shrink-0 text-[#E07912]"
            aria-hidden="true"
          />
          <span>MẬT</span>
          {showRank && <span className="font-bold text-[13px]">· Cấp 2</span>}
        </span>
      );

    case 'SECRET':
      return (
        <span
          className={cn(
            'staff-badge bg-transparent border-0 p-0 inline-flex items-center font-bold text-[#C13515] select-none tracking-wider',
            sizeClasses[size],
            className,
          )}
          title={
            isUserSubject ? 'Cấp thẩm quyền bảo mật: Tối mật (Cấp 3)' : 'Tài liệu tối mật (Cấp 3)'
          }
          aria-label={`${subjectPrefix}: Tối mật${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <AlertTriangle
            size={iconPixelSize}
            strokeWidth={1.75}
            className="shrink-0"
            aria-hidden="true"
          />
          <span>TỐI MẬT</span>
          {showRank && <span className="font-bold text-[13px]">· Cấp 3</span>}
        </span>
      );

    case 'TOP_SECRET':
      return (
        <span
          className={cn(
            'staff-badge bg-transparent border-0 p-0 inline-flex items-center font-extrabold text-[#C13515] select-none tracking-wider uppercase',
            sizeClasses[size],
            className,
          )}
          title={
            isUserSubject
              ? 'Cấp thẩm quyền bảo mật: Tuyệt mật (Cấp 4)'
              : 'Tài liệu tuyệt mật mức cao nhất (Cấp 4)'
          }
          aria-label={`${subjectPrefix}: Tuyệt mật${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <Flame
            size={iconPixelSize}
            strokeWidth={1.75}
            className="shrink-0 animate-pulse"
            aria-hidden="true"
          />
          <span>TUYỆT MẬT</span>
          {showRank && <span className="font-bold text-[13px]">· Cấp 4</span>}
        </span>
      );

    default:
      return (
        <span
          className={cn(
            'staff-badge bg-transparent border-0 p-0 inline-flex items-center text-xs font-semibold text-[#717171] select-none',
            className,
          )}
          {...props}
        >
          <span>{normalized || 'CHƯA PHÂN LOẠI'}</span>
        </span>
      );
  }
}

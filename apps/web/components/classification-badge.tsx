import * as React from 'react';
import { ShieldCheck, ShieldAlert, Lock, AlertTriangle, Flame } from 'lucide-react';
import { cn } from '@/lib/utils';

export type ClassificationCode =
  'UNCLASSIFIED' | 'RESTRICTED' | 'CONFIDENTIAL' | 'SECRET' | 'TOP_SECRET' | string;

export interface ClassificationBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  code?: ClassificationCode;
  level?: ClassificationCode;
  rank?: number;
  showRank?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

export function ClassificationBadge({
  code,
  level,
  rank,
  showRank = false,
  size = 'md',
  className,
  style,
  ...props
}: ClassificationBadgeProps) {
  const normalized = (level ?? code ?? '').toUpperCase();

  const sizeClasses = {
    sm: 'text-[11px] gap-1',
    md: 'text-xs gap-1.5',
    lg: 'text-sm gap-2',
  };

  const iconSizes = {
    sm: 'h-3.5 w-3.5',
    md: 'h-4 w-4',
    lg: 'h-4.5 w-4.5',
  };

  const baseStyle: React.CSSProperties = {
    background: 'transparent',
    border: 'none',
    padding: 0,
    ...style,
  };

  switch (normalized) {
    case 'UNCLASSIFIED':
      return (
        <span
          className={cn(
            'staff-badge inline-flex items-center font-semibold text-[#717171] select-none tracking-wide',
            sizeClasses[size],
            className,
          )}
          style={baseStyle}
          title="Tài liệu không phân loại mật (Cấp 1)"
          aria-label={`Mức mật: Không mật (Unclassified)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <ShieldCheck
            className={cn(iconSizes[size], 'shrink-0')}
            strokeWidth={1.75}
            aria-hidden="true"
          />
          <span>KHÔNG MẬT</span>
          {showRank && <span className="opacity-70 font-bold text-[10px]">· R1</span>}
        </span>
      );

    case 'RESTRICTED':
      return (
        <span
          className={cn(
            'staff-badge inline-flex items-center font-semibold text-[#008489] select-none tracking-wide',
            sizeClasses[size],
            className,
          )}
          style={baseStyle}
          title="Tài liệu hạn chế lưu hành nội bộ (Cấp 2)"
          aria-label={`Mức mật: Nội bộ (Restricted)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <ShieldAlert
            className={cn(iconSizes[size], 'shrink-0')}
            strokeWidth={1.75}
            aria-hidden="true"
          />
          <span>NỘI BỘ</span>
          {showRank && <span className="opacity-75 font-bold text-[10px]">· R2</span>}
        </span>
      );

    case 'CONFIDENTIAL':
      return (
        <span
          className={cn(
            'staff-badge inline-flex items-center font-bold text-[#0284c7] select-none tracking-wide',
            sizeClasses[size],
            className,
          )}
          style={baseStyle}
          title="Tài liệu mật theo quy định tổ chức (Cấp 3)"
          aria-label={`Mức mật: Mật (Confidential)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <Lock className={cn(iconSizes[size], 'shrink-0')} strokeWidth={1.75} aria-hidden="true" />
          <span>MẬT</span>
          {showRank && <span className="opacity-75 font-bold text-[10px]">· R3</span>}
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
          style={baseStyle}
          title="Tài liệu tối mật (Cấp 4)"
          aria-label={`Mức mật: Tối mật (Secret)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <AlertTriangle
            className={cn(iconSizes[size], 'shrink-0')}
            strokeWidth={1.75}
            aria-hidden="true"
          />
          <span>TỐI MẬT</span>
          {showRank && <span className="opacity-75 font-bold text-[10px]">· R4</span>}
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
          style={baseStyle}
          title="Tài liệu tuyệt mật mức cao nhất (Cấp 5)"
          aria-label={`Mức mật: Tuyệt mật (Top Secret)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <Flame
            className={cn(iconSizes[size], 'shrink-0 animate-pulse')}
            strokeWidth={1.75}
            aria-hidden="true"
          />
          <span>TUYỆT MẬT</span>
          {showRank && <span className="opacity-80 font-bold text-[10px]">· R5</span>}
        </span>
      );

    default:
      return (
        <span
          className={cn(
            'staff-badge inline-flex items-center text-xs font-semibold text-[#717171] select-none',
            className,
          )}
          style={baseStyle}
          {...props}
        >
          <span>{normalized || 'CHƯA PHÂN LOẠI'}</span>
        </span>
      );
  }
}

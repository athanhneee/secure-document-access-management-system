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
  ...props
}: ClassificationBadgeProps) {
  const normalized = (level ?? code ?? '').toUpperCase();

  const sizeClasses = {
    sm: 'text-[10px] px-1.5 py-0.5 gap-1',
    md: 'text-xs px-2 py-0.5 gap-1.5',
    lg: 'text-sm px-3 py-1 gap-2',
  };

  const iconSizes = {
    sm: 'h-3 w-3',
    md: 'h-3.5 w-3.5',
    lg: 'h-4 w-4',
  };

  switch (normalized) {
    case 'UNCLASSIFIED':
      return (
        <span
          className={cn(
            'inline-flex items-center rounded-md border border-slate-700 bg-slate-900/90 font-semibold text-slate-300 tracking-wide select-none',
            sizeClasses[size],
            className,
          )}
          title="Tài liệu không phân loại mật (Cấp 1)"
          aria-label={`Mức mật: Không mật (Unclassified)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <ShieldCheck
            className={cn(iconSizes[size], 'text-slate-400 shrink-0')}
            aria-hidden="true"
          />
          <span>KHÔNG MẬT</span>
          {showRank && <span className="opacity-70 font-mono text-[10px]">· R1</span>}
        </span>
      );

    case 'RESTRICTED':
      return (
        <span
          className={cn(
            'inline-flex items-center rounded-md border-2 border-double border-teal-500/50 bg-teal-950/40 font-semibold text-teal-300 tracking-wide select-none shadow-xs',
            sizeClasses[size],
            className,
          )}
          title="Tài liệu hạn chế lưu hành nội bộ (Cấp 2)"
          aria-label={`Mức mật: Nội bộ (Restricted)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <ShieldAlert
            className={cn(iconSizes[size], 'text-teal-400 shrink-0')}
            aria-hidden="true"
          />
          <span>NỘI BỘ</span>
          {showRank && <span className="opacity-75 font-mono text-[10px]">· R2</span>}
        </span>
      );

    case 'CONFIDENTIAL':
      return (
        <span
          className={cn(
            'inline-flex items-center rounded-md border-2 border-dashed border-blue-500/60 bg-blue-950/40 font-bold text-blue-300 tracking-wide select-none shadow-xs',
            sizeClasses[size],
            className,
          )}
          title="Tài liệu mật theo quy định tổ chức (Cấp 3)"
          aria-label={`Mức mật: Mật (Confidential)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <Lock className={cn(iconSizes[size], 'text-blue-400 shrink-0')} aria-hidden="true" />
          <span>MẬT</span>
          {showRank && <span className="opacity-75 font-mono text-[10px]">· R3</span>}
        </span>
      );

    case 'SECRET':
      return (
        <span
          className={cn(
            'inline-flex items-center rounded-md border-2 border-dotted border-amber-500/70 bg-amber-950/40 font-bold text-amber-300 tracking-wider select-none shadow-xs',
            sizeClasses[size],
            className,
          )}
          title="Tài liệu tối mật (Cấp 4)"
          aria-label={`Mức mật: Tối mật (Secret)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <AlertTriangle
            className={cn(iconSizes[size], 'text-amber-400 shrink-0')}
            aria-hidden="true"
          />
          <span>TỐI MẬT</span>
          {showRank && <span className="opacity-75 font-mono text-[10px]">· R4</span>}
        </span>
      );

    case 'TOP_SECRET':
      return (
        <span
          className={cn(
            'inline-flex items-center rounded-md border-2 border-red-500/80 bg-red-950/50 font-extrabold text-red-200 tracking-widest shadow-md select-none uppercase',
            sizeClasses[size],
            className,
          )}
          title="Tài liệu tuyệt mật mức cao nhất (Cấp 5)"
          aria-label={`Mức mật: Tuyệt mật (Top Secret)${rank !== undefined ? `, cấp ${rank}` : ''}`}
          {...props}
        >
          <Flame
            className={cn(iconSizes[size], 'text-red-400 shrink-0 animate-pulse')}
            aria-hidden="true"
          />
          <span>TUYỆT MẬT</span>
          {showRank && <span className="opacity-80 font-mono text-[10px]">· R5</span>}
        </span>
      );

    default:
      return (
        <span
          className={cn(
            'inline-flex items-center rounded-md border border-slate-700 bg-slate-900 px-2 py-0.5 text-xs font-medium text-slate-400 select-none',
            className,
          )}
          {...props}
        >
          <span>{normalized || 'CHƯA PHÂN LOẠI'}</span>
        </span>
      );
  }
}

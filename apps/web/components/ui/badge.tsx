import * as React from 'react';
import { cn } from '@/lib/utils';

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'secondary' | 'destructive' | 'outline' | 'success' | 'warning';
}

export function Badge({ className, variant = 'default', ...props }: BadgeProps) {
  const variants: Record<string, string> = {
    default: 'border-transparent bg-emerald-600 text-white',
    secondary: 'border-transparent bg-slate-800 text-slate-200',
    destructive: 'border-transparent bg-red-600 text-white',
    outline: 'text-slate-300 border-slate-700',
    success: 'border-emerald-600/40 bg-emerald-950/40 text-emerald-300',
    warning: 'border-amber-600/40 bg-amber-950/40 text-amber-300',
  };

  return (
    <div
      className={cn(
        'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:ring-offset-2',
        variants[variant],
        className,
      )}
      {...props}
    />
  );
}

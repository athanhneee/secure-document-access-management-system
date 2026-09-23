import * as React from 'react';
import { cn } from '@/lib/utils';

export interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'destructive' | 'success' | 'warning' | 'info';
}

export function Alert({ className, variant = 'default', role = 'alert', ...props }: AlertProps) {
  const variants: Record<string, string> = {
    default: 'bg-slate-900 text-slate-100 border-slate-800',
    destructive: 'border-red-900/60 bg-red-950/40 text-red-300 [&>svg]:text-red-400',
    success: 'border-emerald-900/60 bg-emerald-950/40 text-emerald-300 [&>svg]:text-emerald-400',
    warning: 'border-amber-900/60 bg-amber-950/40 text-amber-300 [&>svg]:text-amber-400',
    info: 'border-sky-900/60 bg-sky-950/40 text-sky-300 [&>svg]:text-sky-400',
  };

  return (
    <div
      role={role}
      className={cn(
        'relative w-full rounded-lg border p-4 text-xs [&>svg~*]:pl-7 [&>svg]:absolute [&>svg]:left-4 [&>svg]:top-4',
        variants[variant],
        className,
      )}
      {...props}
    />
  );
}

export function AlertTitle({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h5
      className={cn('mb-1 font-semibold leading-none tracking-tight text-slate-100', className)}
      {...props}
    >
      {children}
    </h5>
  );
}

export function AlertDescription({
  className,
  ...props
}: React.HTMLAttributes<HTMLParagraphElement>) {
  return <div className={cn('text-xs [&_p]:leading-relaxed opacity-90', className)} {...props} />;
}

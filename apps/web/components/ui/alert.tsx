import * as React from 'react';
import { cn } from '@/lib/utils';

export interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'destructive' | 'success' | 'warning' | 'info';
}

export function Alert({ className, variant = 'default', role = 'alert', ...props }: AlertProps) {
  const variants: Record<string, string> = {
    default: 'bg-[#ffffff] text-[#222222] border-[#ebebeb] shadow-xs',
    destructive: 'border-[#C13515]/30 bg-[#C13515]/10 text-[#C13515] [&>svg]:text-[#C13515]',
    success: 'border-[#008A05]/30 bg-[#008A05]/10 text-[#008A05] [&>svg]:text-[#008A05]',
    warning: 'border-[#E07912]/30 bg-[#E07912]/10 text-[#E07912] [&>svg]:text-[#E07912]',
    info: 'border-[#008489]/30 bg-[#008489]/10 text-[#008489] [&>svg]:text-[#008489]',
  };

  return (
    <div
      role={role}
      className={cn(
        'relative w-full rounded-[20px] border p-4 text-xs [&>svg~*]:pl-7 [&>svg]:absolute [&>svg]:left-4 [&>svg]:top-4 animate-fade-in-down',
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
      className={cn('mb-1 font-bold leading-none tracking-tight text-[#222222]', className)}
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

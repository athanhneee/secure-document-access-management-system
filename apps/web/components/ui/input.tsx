import * as React from 'react';
import { cn } from '@/lib/utils';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  error?: string;
  helperText?: string;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, error, helperText, id, ...props }, ref) => {
    const errorId = id && error ? `${id}-error` : undefined;
    const helperId = id && helperText ? `${id}-helper` : undefined;
    const describedBy = [errorId, helperId].filter(Boolean).join(' ') || undefined;

    return (
      <div className="w-full">
        <input
          id={id}
          type={type}
          className={cn(
            'flex h-11 w-full rounded-full border border-[#dddddd] bg-[#ffffff] px-4 py-2 text-xs text-[#222222] shadow-2xs transition-all placeholder:text-[#b0b0b0] focus-visible:outline-none focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/25 disabled:cursor-not-allowed disabled:opacity-50',
            error &&
              'border-[#C13515] focus-visible:border-[#C13515] focus-visible:ring-[#C13515]/20',
            className,
          )}
          ref={ref}
          aria-invalid={error ? 'true' : undefined}
          aria-describedby={describedBy}
          {...props}
        />
        {helperText && !error && (
          <p id={helperId} className="mt-1 text-[11px] text-[#717171]">
            {helperText}
          </p>
        )}
        {error && (
          <p id={errorId} className="mt-1 text-[11px] text-[#C13515] font-medium">
            {error}
          </p>
        )}
      </div>
    );
  },
);
Input.displayName = 'Input';

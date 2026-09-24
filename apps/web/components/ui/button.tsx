import * as React from 'react';
import { ArrowRight, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  InteractiveHoverButton,
  type InteractiveHoverButtonProps,
} from './interactive-hover-button';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?:
    | 'default'
    | 'primary'
    | 'success'
    | 'destructive'
    | 'outline'
    | 'secondary'
    | 'ghost'
    | 'link'
    | 'interactive';
  size?: 'default' | 'sm' | 'lg' | 'icon';
  isLoading?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant = 'default',
      size = 'default',
      isLoading = false,
      disabled,
      children,
      ...props
    },
    ref,
  ) => {
    const variants: Record<string, string> = {
      default:
        'bg-[#FF385C] text-white shadow-xs hover:bg-[#E0285F] active:scale-[0.98] border-none',
      primary:
        'bg-[#FF385C] text-white shadow-xs hover:bg-[#E0285F] active:scale-[0.98] border-none',
      success:
        'bg-[#008A05] text-white shadow-xs hover:bg-[#007004] active:scale-[0.98] border-none',
      destructive:
        'bg-[#C13515] text-white shadow-xs hover:bg-[#A32B0F] active:scale-[0.98] border-none',
      outline:
        'border border-[#dddddd] bg-transparent text-[#222222] hover:bg-[#f7f7f7] active:scale-[0.98]',
      secondary:
        'bg-[#f7f7f7] text-[#222222] border border-[#ebebeb] hover:bg-[#eeeeee] active:scale-[0.98]',
      ghost: 'text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222]',
      link: 'text-[#FF385C] underline-offset-4 hover:underline p-0 h-auto',
    };

    const sizes: Record<string, string> = {
      default: 'h-9 px-5 py-2 text-xs font-semibold',
      sm: 'h-8 px-3.5 text-xs font-medium',
      lg: 'h-10 px-6 text-sm font-semibold',
      icon: 'h-9 w-9 p-0',
    };

    if (variant === 'interactive') {
      const buttonText = typeof children === 'string' ? children : 'Button';
      return (
        <button
          ref={ref}
          disabled={disabled || isLoading}
          aria-busy={isLoading || undefined}
          className={cn(
            'group relative min-w-[8rem] w-auto inline-flex items-center justify-center cursor-pointer overflow-hidden rounded-full border border-transparent bg-[#FF385C] hover:bg-[#E0294C] px-5 py-2 text-center text-xs font-semibold text-white shadow-2xs transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] select-none disabled:pointer-events-none disabled:opacity-50 active:scale-[0.98]',
            className,
          )}
          {...props}
        >
          {isLoading ? (
            <span className="flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin text-current" strokeWidth={2} />
              <span>Đang xử lý…</span>
            </span>
          ) : (
            <span className="inline-flex items-center justify-center gap-2">
              <span className="truncate">{children || buttonText}</span>
              <ArrowRight
                size={16}
                strokeWidth={2}
                className="shrink-0 transition-transform duration-200 ease-out group-hover:translate-x-1"
                aria-hidden="true"
              />
            </span>
          )}
        </button>
      );
    }

    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        aria-busy={isLoading || undefined}
        className={cn(
          'inline-flex items-center justify-center whitespace-nowrap rounded-[40px] transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-[#FF385C] focus-visible:ring-offset-white disabled:pointer-events-none disabled:opacity-50 cursor-pointer select-none',
          variants[variant],
          sizes[size],
          className,
        )}
        {...props}
      >
        {isLoading ? (
          <span className="flex items-center gap-2">
            <Loader2 className="h-4 w-4 animate-spin text-current" strokeWidth={2} />
            {children}
          </span>
        ) : (
          children
        )}
      </button>
    );
  },
);
Button.displayName = 'Button';

export { InteractiveHoverButton, type InteractiveHoverButtonProps };

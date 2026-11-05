'use client';
// CONFLICT-RESOLVED: Khai báo ranh giới Client Component tường minh để các Server Component (như trang chủ) import được Button có dùng React Hooks phản hồi tức thì khi chạy next build.

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

/**
 * Thuật toán: Nhận diện Phản hồi Bất đồng bộ Tức thì Dưới 100ms (`isPromiseLike`)
 * Mục đích: Phát hiện trình xử lý `onClick` trả về `Promise` trong `O(1)` để kích hoạt ngay trạng thái chờ `aria-busy` và con quay `Loader2` trong cùng chu kỳ sự kiện nhấn chuột (`< 1ms`), đồng thời khóa nhấn đúp tự động.
 */
function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    'then' in value &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant = 'default',
      size = 'default',
      isLoading = false,
      disabled,
      onClick,
      children,
      ...props
    },
    ref,
  ) => {
    const [autoPending, setAutoPending] = React.useState(false);
    const mountedRef = React.useRef(true);

    React.useEffect(() => {
      mountedRef.current = true;
      return () => {
        mountedRef.current = false;
      };
    }, []);

    const effectiveLoading = isLoading || autoPending;

    const handleInstantClick = React.useCallback(
      (event: React.MouseEvent<HTMLButtonElement>) => {
        if (disabled || effectiveLoading || !onClick) {
          return;
        }
        const outcome: unknown = onClick(event);
        if (isPromiseLike(outcome)) {
          setAutoPending(true);
          const clearPending = () => {
            if (mountedRef.current) {
              setAutoPending(false);
            }
          };
          outcome.then(clearPending, clearPending);
        }
      },
      [disabled, effectiveLoading, onClick],
    );

    // CONFLICT-RESOLVED: Chuẩn hóa toàn bộ trạng thái hover về đúng bảng màu chuẩn trong rules/ui-design-system.md (#E31C5F, brightness-90/95, #dddddd).
    const variants: Record<string, string> = {
      default:
        'bg-[#FF385C] text-white shadow-xs hover:bg-[#E31C5F] active:scale-[0.98] border-none',
      primary:
        'bg-[#FF385C] text-white shadow-xs hover:bg-[#E31C5F] active:scale-[0.98] border-none',
      success:
        'bg-[#008A05] text-white shadow-xs hover:brightness-90 active:scale-[0.98] border-none',
      destructive:
        'bg-[#C13515] text-white shadow-xs hover:brightness-90 active:scale-[0.98] border-none',
      outline:
        'border border-[#dddddd] bg-transparent text-[#222222] hover:bg-[#f7f7f7] active:scale-[0.98]',
      secondary:
        'bg-[#f7f7f7] text-[#222222] border border-[#ebebeb] hover:border-[#dddddd] hover:brightness-95 active:scale-[0.98]',
      ghost: 'text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] active:scale-[0.98]',
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
          disabled={disabled || effectiveLoading}
          aria-busy={effectiveLoading || undefined}
          onClick={onClick ? handleInstantClick : undefined}
          className={cn(
            'group relative min-w-[8rem] w-auto inline-flex items-center justify-center cursor-pointer overflow-hidden rounded-full border border-transparent bg-[#FF385C] hover:bg-[#E31C5F] px-5 py-2 text-center text-xs font-semibold text-white shadow-2xs transition-all duration-100 ease-[cubic-bezier(0.16,1,0.3,1)] select-none disabled:pointer-events-none disabled:opacity-50 active:scale-[0.98]',
            className,
          )}
          {...props}
        >
          {effectiveLoading ? (
            <span className="flex items-center gap-2">
              <Loader2
                size={16}
                strokeWidth={2}
                className="animate-spin text-current"
                aria-hidden="true"
              />
              <span>Đang xử lý…</span>
            </span>
          ) : (
            <span className="inline-flex items-center justify-center gap-2">
              <span className="truncate">{children || buttonText}</span>
              <ArrowRight
                size={16}
                strokeWidth={2}
                className="shrink-0 transition-transform duration-100 ease-out group-hover:translate-x-1"
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
        disabled={disabled || effectiveLoading}
        aria-busy={effectiveLoading || undefined}
        onClick={onClick ? handleInstantClick : undefined}
        className={cn(
          'inline-flex items-center justify-center whitespace-nowrap rounded-[40px] transition-all duration-100 ease-[cubic-bezier(0.16,1,0.3,1)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-[#FF385C] focus-visible:ring-offset-white disabled:pointer-events-none disabled:opacity-50 cursor-pointer select-none',
          variants[variant],
          sizes[size],
          className,
        )}
        {...props}
      >
        {effectiveLoading ? (
          <span className="flex items-center gap-2">
            <Loader2
              size={16}
              strokeWidth={2}
              className="animate-spin text-current"
              aria-hidden="true"
            />
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

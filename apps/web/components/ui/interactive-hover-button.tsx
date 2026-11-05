import * as React from 'react';
import Link from 'next/link';
import { ArrowRight, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

export type InteractiveButtonVariant =
  | 'primary'
  | 'secondary'
  | 'danger'
  | 'ghost'
  | 'destructive'
  | 'outline'
  | 'default'
  | 'solid'
  | 'solid-primary';

export interface InteractiveHoverButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  text?: string;
  variant?: InteractiveButtonVariant;
  size?: 'sm' | 'md' | 'lg';
  icon?: React.ReactNode;
  href?: string;
  isLoading?: boolean;
}

interface VariantStyle {
  base: string;
  hover: string;
  text: string;
  border: string;
}

// CONFLICT-RESOLVED: Chuẩn hóa các lớp hover về đúng bảng màu chuẩn (#E31C5F cho nút nhấn thương hiệu #FF385C và brightness-90 cho #C13515) theo rules/ui-design-system.md.
const variantStyles: Record<InteractiveButtonVariant, VariantStyle> = {
  primary: {
    base: 'bg-[#FF385C]',
    hover: 'hover:bg-[#E31C5F]',
    text: 'text-white',
    border: 'border-transparent',
  },
  solid: {
    base: 'bg-[#FF385C]',
    hover: 'hover:bg-[#E31C5F]',
    text: 'text-white',
    border: 'border-transparent',
  },
  'solid-primary': {
    base: 'bg-[#FF385C]',
    hover: 'hover:bg-[#E31C5F]',
    text: 'text-white',
    border: 'border-transparent',
  },
  default: {
    base: 'bg-[#FF385C]',
    hover: 'hover:bg-[#E31C5F]',
    text: 'text-white',
    border: 'border-transparent',
  },
  secondary: {
    base: 'bg-[#ffffff]',
    hover: 'hover:bg-[#f7f7f7] hover:border-[#222222]',
    text: 'text-[#222222]',
    border: 'border-[#dddddd]',
  },
  outline: {
    base: 'bg-[#ffffff]',
    hover: 'hover:bg-[#f7f7f7] hover:border-[#222222]',
    text: 'text-[#222222]',
    border: 'border-[#dddddd]',
  },
  danger: {
    base: 'bg-[#C13515]',
    hover: 'hover:brightness-90',
    text: 'text-white',
    border: 'border-transparent',
  },
  destructive: {
    base: 'bg-[#C13515]',
    hover: 'hover:brightness-90',
    text: 'text-white',
    border: 'border-transparent',
  },
  ghost: {
    base: 'bg-transparent',
    hover: 'hover:bg-[#f7f7f7] hover:text-[#222222]',
    text: 'text-[#717171]',
    border: 'border-transparent',
  },
};

const sizeStyles: Record<'sm' | 'md' | 'lg', string> = {
  sm: 'h-8 px-4 text-xs font-semibold min-w-[5.5rem]',
  md: 'h-9.5 px-5 text-xs font-semibold min-w-[7rem]',
  lg: 'h-11 px-6 text-sm font-semibold min-w-[8.5rem]',
};

/**
 * Thuật toán: Nhận diện Lời gọi Bất đồng bộ Tức thì cho Nút Viên Thuốc (`isPromiseLike`)
 * Mục đích: Tự động bật con quay `Loader2` và khóa nhấn đúp ngay dưới `1ms` khi `onClick` trả về `Promise`, đảm bảo phản hồi thị giác `< 0,1s` cho mọi thao tác mạng.
 */
function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    'then' in value &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}

const InteractiveHoverButton = React.forwardRef<HTMLButtonElement, InteractiveHoverButtonProps>(
  (
    {
      text,
      className,
      children,
      href,
      variant = 'primary',
      size = 'md',
      isLoading = false,
      icon,
      disabled,
      onClick,
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

    const buttonText =
      text || (typeof children === 'string' && children.trim() ? children : 'Button');
    const variantStyle: VariantStyle = variantStyles[variant] ?? variantStyles.primary;
    const sizeClass = sizeStyles[size] || sizeStyles.md;
    const iconElement = icon || <ArrowRight size={16} strokeWidth={2} aria-hidden="true" />;

    const innerContent = (
      <>
        {effectiveLoading ? (
          <span className="inline-flex items-center justify-center gap-2">
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
            <span className="truncate">{buttonText}</span>
            <span
              className="shrink-0 transition-transform duration-100 ease-out group-hover:translate-x-1"
              aria-hidden="true"
            >
              {iconElement}
            </span>
          </span>
        )}
      </>
    );

    const baseClasses = cn(
      'group ihb-button rounded-full border text-center shadow-2xs select-none disabled:pointer-events-none disabled:opacity-50',
      variantStyle.base,
      variantStyle.hover,
      variantStyle.text,
      variantStyle.border,
      sizeClass,
      className,
    );

    if (href && !disabled && !effectiveLoading) {
      return (
        <Link href={href} className={baseClasses}>
          {innerContent}
        </Link>
      );
    }

    return (
      <button
        ref={ref}
        disabled={disabled || effectiveLoading}
        aria-busy={effectiveLoading || undefined}
        onClick={onClick ? handleInstantClick : undefined}
        className={baseClasses}
        {...props}
      >
        {innerContent}
      </button>
    );
  },
);

InteractiveHoverButton.displayName = 'InteractiveHoverButton';

export { InteractiveHoverButton };

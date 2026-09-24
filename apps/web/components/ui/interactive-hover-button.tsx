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

const variantStyles: Record<InteractiveButtonVariant, VariantStyle> = {
  primary: {
    base: 'bg-[#FF385C]',
    hover: 'hover:bg-[#E0294C]',
    text: 'text-white',
    border: 'border-transparent',
  },
  solid: {
    base: 'bg-[#FF385C]',
    hover: 'hover:bg-[#E0294C]',
    text: 'text-white',
    border: 'border-transparent',
  },
  'solid-primary': {
    base: 'bg-[#FF385C]',
    hover: 'hover:bg-[#E0294C]',
    text: 'text-white',
    border: 'border-transparent',
  },
  default: {
    base: 'bg-[#FF385C]',
    hover: 'hover:bg-[#E0294C]',
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
    hover: 'hover:bg-[#A32B0F]',
    text: 'text-white',
    border: 'border-transparent',
  },
  destructive: {
    base: 'bg-[#C13515]',
    hover: 'hover:bg-[#A32B0F]',
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
      ...props
    },
    ref,
  ) => {
    const buttonText =
      text || (typeof children === 'string' && children.trim() ? children : 'Button');
    const style: VariantStyle = variantStyles[variant] ?? variantStyles.primary;
    const sizeClass = sizeStyles[size] || sizeStyles.md;
    const iconElement = icon || <ArrowRight size={16} strokeWidth={2} />;

    const innerContent = (
      <>
        {isLoading ? (
          <span className="inline-flex items-center justify-center gap-2">
            <Loader2 size={16} strokeWidth={2} className="animate-spin text-current" />
            <span>Đang xử lý…</span>
          </span>
        ) : (
          <span className="inline-flex items-center justify-center gap-2">
            <span className="truncate">{buttonText}</span>
            <span
              className="shrink-0 transition-transform duration-200 ease-out group-hover:translate-x-1"
              aria-hidden="true"
            >
              {iconElement}
            </span>
          </span>
        )}
      </>
    );

    const baseClasses = cn(
      'group ihb-button border text-center shadow-2xs select-none disabled:pointer-events-none disabled:opacity-50',
      style.base,
      style.hover,
      style.text,
      style.border,
      sizeClass,
      className,
    );

    if (href && !disabled && !isLoading) {
      return (
        <Link href={href} className={baseClasses}>
          {innerContent}
        </Link>
      );
    }

    return (
      <button ref={ref} disabled={disabled || isLoading} className={baseClasses} {...props}>
        {innerContent}
      </button>
    );
  },
);

InteractiveHoverButton.displayName = 'InteractiveHoverButton';

export { InteractiveHoverButton };

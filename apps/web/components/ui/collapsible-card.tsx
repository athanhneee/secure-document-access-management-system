'use client';

/**
 * Thuật toán: Thẻ Thu Gọn Mặc Định Với Mũi Tên Xoay Mượt `>` -> `v` (`CollapsibleCard`)
 * Mục đích:
 *   - Đóng gọn các khu vực nhiều nội dung theo mặc định để màn hình thoáng, chỉ mở xuống khi người dùng nhấn vào thanh tiêu đề hoặc mũi tên `>`.
 *   - Chuyển đổi chiều cao mượt qua CSS Grid (`grid-rows-[0fr]` -> `grid-rows-[1fr]`), khóa tương tác bàn phím bằng `inert` khi đang đóng và tăng bộ đếm `revealKey` mỗi lần mở để kích hoạt lại hiệu ứng viết tay sạch không nháy khung hình.
 */
import { useId, useState, type ReactNode } from 'react';
import { ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Card } from './card';

export interface CollapsibleCardRenderState {
  isOpen: boolean;
  revealKey: number;
}

export interface CollapsibleCardProps {
  id?: string | undefined;
  icon: ReactNode;
  title: string;
  badge?: ReactNode | undefined;
  defaultOpen?: boolean | undefined;
  open?: boolean | undefined;
  onOpenChange?: ((open: boolean) => void) | undefined;
  className?: string | undefined;
  contentClassName?: string | undefined;
  children: (state: CollapsibleCardRenderState) => ReactNode;
}

export function CollapsibleCard({
  id,
  icon,
  title,
  badge,
  defaultOpen = false,
  open,
  onOpenChange,
  className,
  contentClassName,
  children,
}: CollapsibleCardProps) {
  const panelId = useId();
  const [uncontrolledOpen, setUncontrolledOpen] = useState(defaultOpen);
  const [revealKey, setRevealKey] = useState(defaultOpen ? 1 : 0);

  const isControlled = open !== undefined;
  const isOpen = isControlled ? open : uncontrolledOpen;

  function handleToggle() {
    const next = !isOpen;
    if (next) {
      setRevealKey((prev) => prev + 1);
    }
    if (!isControlled) {
      setUncontrolledOpen(next);
    }
    onOpenChange?.(next);
  }

  return (
    <Card id={id} className={className}>
      <button
        type="button"
        onClick={handleToggle}
        aria-expanded={isOpen}
        aria-controls={panelId}
        className="group w-full min-h-11 flex items-center justify-between gap-3 p-4 sm:p-5 text-left transition-colors hover:bg-[#f7f7f7]/70 cursor-pointer"
      >
        <div className="flex-1 flex flex-wrap items-center justify-between gap-x-3 gap-y-1.5 min-w-0">
          <div className="flex items-center gap-2 min-w-0">
            {icon}
            <h3 className="text-sm font-bold leading-snug tracking-tight text-[#222222]">
              {title}
            </h3>
          </div>
          {badge && <div className="shrink-0">{badge}</div>}
        </div>

        <span
          className={cn(
            'inline-flex h-7 w-7 items-center justify-center rounded-full text-[#717171] transition-colors duration-200 group-hover:bg-[#ebebeb]/80 group-hover:text-[#222222] shrink-0',
            isOpen && 'bg-[#f7f7f7] text-[#222222]',
          )}
          aria-hidden="true"
        >
          <ChevronRight
            size={16}
            strokeWidth={2}
            className={cn(
              'transition-transform duration-300 ease-[cubic-bezier(0.16,1,0.3,1)]',
              isOpen && 'rotate-90',
            )}
          />
        </span>
      </button>

      <section
        id={panelId}
        aria-label={title}
        aria-hidden={!isOpen}
        inert={!isOpen}
        className={cn(
          'grid transition-[grid-template-rows,opacity] duration-300 ease-[cubic-bezier(0.16,1,0.3,1)]',
          isOpen ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0',
        )}
      >
        <div className="overflow-hidden">
          <div className={cn('px-4 sm:px-5 pb-4 sm:pb-5 pt-0', contentClassName)}>
            {children({ isOpen, revealKey })}
          </div>
        </div>
      </section>
    </Card>
  );
}

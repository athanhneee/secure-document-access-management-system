import * as React from 'react';
import { ChevronDown } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  wrapperClassName?: string | undefined;
}

/**
 * Thuật toán: Trường Chọn Thả Xuống Chuẩn Hóa Đa Nền Tảng Với Mũi Tên Lucide Cố Định (`Select`)
 * Mục đích: Loại bỏ mũi tên mặc định sát mép của trình duyệt di động bằng `appearance-none`, gắn biểu tượng `ChevronDown` cân đối và đồng bộ kích thước/bo góc với `Input` trên màn hình `375px` lẫn máy tính.
 */
export const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  ({ className, wrapperClassName, children, ...props }, ref) => {
    return (
      <div className={cn('relative w-full min-w-0', wrapperClassName)}>
        <select
          ref={ref}
          className={cn(
            'h-11 sm:h-9 w-full appearance-none truncate rounded-[12px] sm:rounded-full border border-[#dddddd] bg-[#ffffff] pl-3.5 pr-9 py-2 text-xs text-[#222222] shadow-2xs transition-colors focus-visible:outline-none focus-visible:border-[#222222] focus-visible:ring-2 focus-visible:ring-[#222222]/15 disabled:cursor-not-allowed disabled:opacity-50 cursor-pointer',
            className,
          )}
          {...props}
        >
          {children}
        </select>
        <ChevronDown
          size={16}
          strokeWidth={1.75}
          className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-[#717171]"
          aria-hidden="true"
        />
      </div>
    );
  },
);
Select.displayName = 'Select';

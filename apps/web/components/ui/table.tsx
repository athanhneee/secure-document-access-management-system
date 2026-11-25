import * as React from 'react';
import { cn } from '@/lib/utils';

/**
 * Thuật toán: Bảng Dữ Liệu Doanh Nghiệp Cuộn Hai Chiều Có Giới Hạn Chiều Cao & Ghim Tiêu Đề Cột (`Table`, `TableHeader`, `TableBody`, `TableRow`, `TableHead`, `TableCell`)
 * Mục đích:
 *   - Bọc phần tử `<table>` trong khung cuộn hai chiều (`overflow-x-auto overflow-y-auto`) có trần chiều cao thích ứng (`max-h-[56dvh] sm:max-h-[450px] xl:max-h-[calc(100dvh-21.5rem)]`) để danh sách nhật ký dài luôn có thanh cuộn riêng, không đẩy văng thanh phân trang hay làm xô lệch bố cục trang.
 *   - Ghim cố định hàng tiêu đề (`sticky top-0 z-10`) kèm đường kẻ âm (`shadow-[inset_0_-1px_0_#ebebeb]`) không bị mất nét khi cuộn trên cả màn hình desktop và di động `375px`.
 */
export interface TableProps extends React.HTMLAttributes<HTMLTableElement> {
  containerClassName?: string | undefined;
  containerRef?: React.Ref<HTMLDivElement> | undefined;
}

export function Table({ className, containerClassName, containerRef, ...props }: TableProps) {
  return (
    <div
      ref={containerRef}
      className={cn(
        'sda-table-scroll relative w-full min-h-[200px] max-h-[52dvh] lg:max-h-[calc(100dvh-21rem)] overflow-x-auto overflow-y-auto overscroll-contain rounded-[16px] border border-[#ebebeb] bg-[#ffffff] [[data-card-body]_&]:rounded-none [[data-card-body]_&]:border-0',
        containerClassName,
      )}
    >
      <table className={cn('w-full caption-bottom text-xs', className)} {...props} />
    </div>
  );
}

export function TableHeader({
  className,
  ...props
}: React.HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <thead
      className={cn(
        'sticky top-0 z-10 bg-[#f7f7f7] shadow-[inset_0_-1px_0_#ebebeb] [&_tr]:border-b-0',
        className,
      )}
      {...props}
    />
  );
}

export function TableBody({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) {
  return <tbody className={cn('[&_tr:last-child]:border-0', className)} {...props} />;
}

export function TableRow({ className, ...props }: React.HTMLAttributes<HTMLTableRowElement>) {
  return (
    <tr
      className={cn(
        'border-b border-[#ebebeb] transition-colors duration-150 ease-[cubic-bezier(0.16,1,0.3,1)] hover:bg-[#f7f7f7]/80 data-[state=selected]:bg-[#f7f7f7]',
        className,
      )}
      {...props}
    />
  );
}

export function TableHead({ className, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      className={cn(
        'h-9 px-3.5 text-left align-middle text-xs font-semibold uppercase tracking-wider text-[#717171] whitespace-nowrap [&:has([role=checkbox])]:pr-0 select-none',
        className,
      )}
      {...props}
    />
  );
}

export function TableCell({ className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td
      className={cn(
        'px-3.5 py-2.5 align-middle text-xs text-[#222222] [&:has([role=checkbox])]:pr-0',
        className,
      )}
      {...props}
    />
  );
}

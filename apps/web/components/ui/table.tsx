import * as React from 'react';
import { cn } from '@/lib/utils';

/**
 * Thuật toán: Bảng Dữ Liệu Doanh Nghiệp Cuộn Ngang Mượt Trên Màn Hình Nhỏ (`Table`, `TableHeader`, `TableBody`, `TableRow`, `TableHead`, `TableCell`)
 * Mục đích: Bọc phần tử `<table>` trong khung `overflow-x-auto` tự khử viền kép khi đặt trong `CardContent`, giữ tiêu đề cột trên một dòng (`whitespace-nowrap`) và không gây vỡ trang trên thiết bị `375px`.
 */
export function Table({ className, ...props }: React.HTMLAttributes<HTMLTableElement>) {
  return (
    <div className="relative w-full overflow-x-auto rounded-[16px] border border-[#ebebeb] bg-[#ffffff] [[data-card-body]_&]:rounded-none [[data-card-body]_&]:border-0">
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
      className={cn('bg-[#f7f7f7] border-b border-[#ebebeb] [&_tr]:border-b-0', className)}
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
        'h-9 px-3.5 text-left align-middle text-[11px] font-semibold uppercase tracking-wider text-[#717171] whitespace-nowrap [&:has([role=checkbox])]:pr-0 select-none',
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

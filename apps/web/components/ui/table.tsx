import * as React from 'react';
import { cn } from '@/lib/utils';

export function Table({ className, ...props }: React.HTMLAttributes<HTMLTableElement>) {
  return (
    <div className="relative w-full overflow-x-auto rounded-[28px] border border-[#ebebeb] bg-[#ffffff] shadow-xs">
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

export function TableFooter({
  className,
  ...props
}: React.HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <tfoot
      className={cn(
        'border-t border-[#ebebeb] bg-[#f7f7f7] font-medium [&>tr]:last:border-b-0',
        className,
      )}
      {...props}
    />
  );
}

export function TableRow({ className, ...props }: React.HTMLAttributes<HTMLTableRowElement>) {
  return (
    <tr
      className={cn(
        'border-b border-[#ebebeb] transition-colors duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] hover:bg-[#f7f7f7] data-[state=selected]:bg-[#f7f7f7]',
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
        'h-10 px-4 text-left align-middle text-[11px] font-semibold uppercase tracking-wider text-[#717171] [&:has([role=checkbox])]:pr-0 select-none',
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
        'px-4 py-3 align-middle text-xs text-[#222222] [&:has([role=checkbox])]:pr-0',
        className,
      )}
      {...props}
    />
  );
}

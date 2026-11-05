'use client';

import * as React from 'react';
import { cn } from '@/lib/utils';

interface TabsContextValue {
  baseId: string;
  value: string;
  onValueChange: (value: string) => void;
}

const TabsContext = React.createContext<TabsContextValue | undefined>(undefined);

export interface TabsProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string;
  onValueChange: (value: string) => void;
}

export function Tabs({ value, onValueChange, className, ...props }: TabsProps) {
  const baseId = React.useId();

  return (
    <TabsContext.Provider value={{ baseId, value, onValueChange }}>
      <div className={cn('w-full', className)} {...props} />
    </TabsContext.Provider>
  );
}

/**
 * Thuật toán: Điều Hướng Phím Mũi Tên Ngang Có Quay Vòng Theo Chuẩn WAI-ARIA Tabs (`handleTabsKeyDown`)
 * Mục đích: Hỗ trợ người dùng bàn phím di chuyển liền mạch qua các thẻ đang bật bằng `ArrowRight`, `ArrowLeft`, `Home` và `End`.
 * Cơ chế hoạt động:
 *   - Truy vấn danh sách `[role="tab"]:not([disabled])` bên trong `tablist` hiện tại `O(K)`, xác định vị trí tiêu điểm hiện thời và tính chỉ số đích quay vòng modulo `(idx ± 1 + K) % K` trước khi đặt focus và kích hoạt thẻ.
 */
function handleTabsKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
  if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft' && e.key !== 'Home' && e.key !== 'End') {
    return;
  }

  const tabs = Array.from(
    e.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]:not([disabled])'),
  );
  if (tabs.length === 0) return;

  const currentIndex = tabs.indexOf(document.activeElement as HTMLButtonElement);
  let nextIndex = 0;

  if (e.key === 'Home') {
    nextIndex = 0;
  } else if (e.key === 'End') {
    nextIndex = tabs.length - 1;
  } else if (e.key === 'ArrowRight') {
    nextIndex = currentIndex >= 0 ? (currentIndex + 1) % tabs.length : 0;
  } else {
    nextIndex =
      currentIndex >= 0 ? (currentIndex - 1 + tabs.length) % tabs.length : tabs.length - 1;
  }

  const targetTab = tabs[nextIndex];
  if (targetTab) {
    e.preventDefault();
    targetTab.focus();
    targetTab.click();
  }
}

export function TabsList({ className, onKeyDown, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      role="tablist"
      aria-orientation="horizontal"
      tabIndex={-1}
      onKeyDown={(e) => {
        handleTabsKeyDown(e);
        onKeyDown?.(e);
      }}
      className={cn(
        'inline-flex h-11 items-center justify-center rounded-full bg-[#f7f7f7] p-1 text-[#717171] border border-[#ebebeb]',
        className,
      )}
      {...props}
    />
  );
}

export interface TabsTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  value: string;
}

export function TabsTrigger({ id, className, value, children, ...props }: TabsTriggerProps) {
  const context = React.useContext(TabsContext);
  if (!context) throw new Error('TabsTrigger must be used within Tabs');

  const isSelected = context.value === value;
  const tabId = id ?? `${context.baseId}-tab-${value}`;
  const panelId = `${context.baseId}-panel-${value}`;

  return (
    <button
      id={tabId}
      type="button"
      role="tab"
      aria-selected={isSelected}
      aria-controls={panelId}
      tabIndex={isSelected ? 0 : -1}
      onClick={() => context.onValueChange(value)}
      className={cn(
        'inline-flex items-center justify-center whitespace-nowrap rounded-full px-4 py-1.5 text-xs font-medium transition-all duration-100 ease-[cubic-bezier(0.16,1,0.3,1)] active:scale-[0.98] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF385C] disabled:pointer-events-none disabled:opacity-50 cursor-pointer',
        isSelected
          ? 'bg-[#ffffff] text-[#222222] shadow-xs font-semibold'
          : 'text-[#717171] hover:text-[#222222] hover:bg-[#ffffff]/80',
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}

export interface TabsContentProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string;
}

export function TabsContent({ id, className, value, children, ...props }: TabsContentProps) {
  const context = React.useContext(TabsContext);
  if (!context) throw new Error('TabsContent must be used within Tabs');

  if (context.value !== value) return null;

  const panelId = id ?? `${context.baseId}-panel-${value}`;
  const tabId = `${context.baseId}-tab-${value}`;

  return (
    <div
      id={panelId}
      role="tabpanel"
      aria-labelledby={tabId}
      tabIndex={0}
      className={cn(
        'mt-2 ring-offset-background focus-visible:outline-none animate-tab-enter',
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
}

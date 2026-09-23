'use client';

import * as React from 'react';
import { cn } from '@/lib/utils';

export interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: React.ReactNode;
}

const DialogContext = React.createContext<{ open: boolean; onOpenChange: (open: boolean) => void }>(
  {
    open: false,
    onOpenChange: () => {},
  },
);

export function Dialog({ open, onOpenChange, children }: DialogProps) {
  React.useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape' && open) {
        onOpenChange(false);
      }
    }
    if (open) {
      document.body.style.overflow = 'hidden';
      window.addEventListener('keydown', handleKeyDown);
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [open, onOpenChange]);

  if (!open) return null;

  return (
    <DialogContext.Provider value={{ open, onOpenChange }}>
      <dialog
        open
        aria-modal="true"
        className="fixed inset-0 z-50 m-0 flex h-full w-full max-h-none max-w-none items-center justify-center bg-transparent p-4 overflow-y-auto"
      >
        <button
          type="button"
          tabIndex={-1}
          aria-label="Đóng cửa sổ thoại"
          className="fixed inset-0 z-0 h-full w-full bg-black/70 backdrop-blur-sm cursor-default border-none outline-none"
          onClick={() => onOpenChange(false)}
        />
        <div className="relative z-10 w-full max-w-lg">{children}</div>
      </dialog>
    </DialogContext.Provider>
  );
}

export function DialogContent({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'relative w-full rounded-xl border border-slate-800 bg-slate-900 p-6 text-slate-100 shadow-2xl animate-in fade-in-0 zoom-in-95 duration-150',
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export function DialogHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('flex flex-col space-y-1.5 text-left mb-4', className)} {...props} />;
}

export function DialogTitle({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h2
      className={cn('text-lg font-semibold leading-none tracking-tight text-slate-100', className)}
      {...props}
    >
      {children}
    </h2>
  );
}

export function DialogDescription({
  className,
  ...props
}: React.HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn('text-xs text-slate-400 mt-1 leading-relaxed', className)} {...props} />;
}

export function DialogFooter({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'flex flex-col-reverse sm:flex-row sm:justify-end sm:space-x-2 mt-6 gap-2',
        className,
      )}
      {...props}
    />
  );
}

'use client';

import * as React from 'react';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: React.ReactNode;
}

const DialogContext = React.createContext<{
  open: boolean;
  onOpenChange: (open: boolean) => void;
}>({
  open: false,
  onOpenChange: () => {},
});

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
        className="fixed inset-0 z-50 m-0 flex h-full w-full max-h-none max-w-none items-center justify-center bg-transparent p-3 sm:p-4 overflow-y-auto"
      >
        <button
          type="button"
          tabIndex={-1}
          aria-label="Đóng cửa sổ thoại"
          className="fixed inset-0 z-0 h-full w-full bg-[#222222]/40 backdrop-blur-xs cursor-default border-none outline-none animate-fade-in"
          onClick={() => onOpenChange(false)}
        />
        <div className="relative z-10 w-full max-w-lg my-auto">{children}</div>
      </dialog>
    </DialogContext.Provider>
  );
}

export function DialogContent({
  className,
  children,
  showClose = true,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { showClose?: boolean }) {
  const { onOpenChange } = React.useContext(DialogContext);
  return (
    <div
      className={cn(
        'relative w-full rounded-[28px] border border-[#ebebeb] bg-[#ffffff] p-5 sm:p-7 text-[#222222] shadow-[0_20px_60px_rgba(0,0,0,0.12)] backdrop-blur-md animate-scale-in max-h-[88vh] overflow-y-auto',
        className,
      )}
      {...props}
    >
      {showClose && (
        <button
          type="button"
          onClick={() => onOpenChange(false)}
          className="absolute right-4 top-4 rounded-full p-1.5 text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF385C]"
          aria-label="Đóng"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      )}
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
      className={cn('text-lg font-semibold leading-none tracking-tight text-[#222222]', className)}
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
  return <p className={cn('text-xs text-[#717171] mt-1 leading-relaxed', className)} {...props} />;
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

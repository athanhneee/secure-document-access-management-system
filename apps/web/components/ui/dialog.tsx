'use client';

import * as React from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Alert, AlertDescription } from './alert';
import {
  DialogErrorContext,
  DialogErrorProvider,
  type DialogErrorContextValue,
} from './dialog-error-context';
import { getVisibleFocusables } from './dialog-focus';
import {
  DialogContext,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from './dialog-parts';

export {
  DialogDescription,
  DialogErrorContext,
  DialogErrorProvider,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  type DialogErrorContextValue,
};

export interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: React.ReactNode;
}

/**
 * Thuật toán: Quản lý Vòng đời Hộp thoại Phương thức `<dialog>` Top-Layer & Bẫy Tiêu điểm WAI-ARIA (`Dialog`)
 * Mục đích: Mở bằng `.showModal()` ở tầng Top-Layer, hiển thị trực tiếp lỗi qua `DialogErrorContext`, đóng an toàn bằng `Escape` hoặc nhấp nền mờ và giam vòng lặp phím `Tab`.
 */
export function Dialog({ open, onOpenChange, children }: DialogProps) {
  const dialogRef = React.useRef<HTMLDialogElement | null>(null);
  const previousFocusRef = React.useRef<HTMLElement | null>(null);
  const onOpenChangeRef = React.useRef(onOpenChange);

  React.useEffect(() => {
    onOpenChangeRef.current = onOpenChange;
  }, [onOpenChange]);

  const titleId = React.useId();
  const descriptionId = React.useId();
  const [hasDescription, setHasDescription] = React.useState(false);

  React.useEffect(() => {
    if (!open) return;

    const dialogEl = dialogRef.current;
    previousFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    document.body.style.overflow = 'hidden';

    if (dialogEl && !dialogEl.open) {
      if (typeof dialogEl.showModal === 'function') {
        try {
          dialogEl.showModal();
        } catch {
          dialogEl.setAttribute('open', '');
        }
      } else {
        dialogEl.setAttribute('open', '');
      }
    }

    if (dialogEl && !dialogEl.contains(document.activeElement)) {
      const candidates = getVisibleFocusables(dialogEl);
      const preferred =
        candidates.find((el) => el.getAttribute('data-dialog-close') !== 'true') ??
        candidates[0] ??
        dialogEl;
      preferred.focus();
    }

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        onOpenChangeRef.current(false);
        return;
      }
      if (e.key !== 'Tab' || !dialogEl) return;

      const focusables = getVisibleFocusables(dialogEl);
      if (focusables.length === 0) {
        e.preventDefault();
        dialogEl.focus();
        return;
      }

      const first = focusables[0]!;
      const last = focusables[focusables.length - 1]!;
      const active = document.activeElement;
      if (e.shiftKey && (active === first || !dialogEl.contains(active))) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (active === last || !dialogEl.contains(active))) {
        e.preventDefault();
        first.focus();
      }
    }

    function handleBackdropClick(e: MouseEvent) {
      if (!dialogEl) return;
      const contentEl = dialogEl.querySelector('[data-dialog-content="true"]');
      if (contentEl && !contentEl.contains(e.target as Node)) {
        onOpenChangeRef.current(false);
      }
    }

    dialogEl?.addEventListener('keydown', handleKeyDown);
    dialogEl?.addEventListener('click', handleBackdropClick);

    return () => {
      dialogEl?.removeEventListener('keydown', handleKeyDown);
      dialogEl?.removeEventListener('click', handleBackdropClick);
      document.body.style.overflow = '';
      if (dialogEl?.open && typeof dialogEl.close === 'function') {
        try {
          dialogEl.close();
        } catch {
          dialogEl.removeAttribute('open');
        }
      }
      const prev = previousFocusRef.current;
      if (prev && typeof prev.focus === 'function' && document.contains(prev)) prev.focus();
    };
  }, [open]);

  if (!open) return null;

  return (
    <DialogContext.Provider
      value={{ open, onOpenChange, titleId, descriptionId, hasDescription, setHasDescription }}
    >
      <dialog
        ref={dialogRef}
        tabIndex={-1}
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={hasDescription ? descriptionId : undefined}
        onCancel={(e) => {
          e.preventDefault();
          onOpenChange(false);
        }}
        className="fixed inset-0 z-50 m-0 flex h-full w-full max-h-none max-w-none items-center justify-center border-none bg-[#222222]/40 p-3 sm:p-4 overflow-y-auto backdrop-blur-xs outline-none"
      >
        <div className="relative z-10 flex w-full justify-center my-auto">{children}</div>
      </dialog>
    </DialogContext.Provider>
  );
}

export function DialogContent({
  className,
  children,
  showClose = true,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { showClose?: boolean | undefined }) {
  const { open, onOpenChange } = React.useContext(DialogContext);
  const { errorMessage, onDismiss } = React.useContext(DialogErrorContext);

  return (
    <div
      data-dialog-content="true"
      className={cn(
        'relative w-full max-w-lg rounded-[24px] border border-[#ebebeb] bg-[#ffffff] p-5 sm:p-6 text-[#222222] shadow-[0_20px_60px_rgba(0,0,0,0.12)] backdrop-blur-md animate-modal-enter max-h-[90dvh] overflow-y-auto',
        className,
      )}
      {...props}
    >
      {showClose && (
        <button
          type="button"
          data-dialog-close="true"
          onClick={() => onOpenChange(false)}
          className="absolute right-3 top-3 z-20 flex h-11 w-11 sm:h-9 sm:w-9 items-center justify-center rounded-full text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF385C] cursor-pointer"
          aria-label="Đóng hộp thoại"
        >
          <X size={16} strokeWidth={2} aria-hidden="true" />
        </button>
      )}
      {open && errorMessage && (
        <Alert variant="destructive" className="mb-4 pr-12">
          <AlertTriangle size={16} strokeWidth={1.75} aria-hidden="true" />
          <div className="flex items-start justify-between gap-2">
            <AlertDescription className="font-medium">{errorMessage}</AlertDescription>
            {onDismiss && (
              <button
                type="button"
                onClick={onDismiss}
                className="shrink-0 flex min-h-11 min-w-11 sm:min-h-8 sm:min-w-8 items-center justify-center rounded-full text-[#C13515] hover:bg-[#C13515]/10 cursor-pointer"
                aria-label="Đóng thông báo lỗi"
              >
                <X size={16} strokeWidth={2} aria-hidden="true" />
              </button>
            )}
          </div>
        </Alert>
      )}
      {children}
    </div>
  );
}

'use client';

import * as React from 'react';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: React.ReactNode;
}

interface DialogContextValue {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  titleId: string;
  descriptionId: string;
  hasDescription: boolean;
  setHasDescription: (present: boolean) => void;
}

const DialogContext = React.createContext<DialogContextValue>({
  open: false,
  onOpenChange: () => {},
  titleId: '',
  descriptionId: '',
  hasDescription: false,
  setHasDescription: () => {},
});

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'textarea:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(', ');

/**
 * Thuật toán: Quản lý Vòng đời Hộp thoại Phương thức `<dialog>` Native & Bẫy Tiêu điểm Bàn phím WAI-ARIA (`Dialog`)
 * Mục đích: Đảm bảo mọi hộp thoại mở ở tầng Top-Layer phương thức thực sự (`.showModal()`), khóa nền cuộn, đóng an toàn bằng phím `Escape` hoặc nhấp nền mờ, đồng thời giam vòng lặp phím `Tab` / `Shift+Tab` và hoàn trả tiêu điểm cho phần tử kích hoạt ban đầu khi đóng.
 * Cơ chế hoạt động:
 *   1. Khi `open === true`, lưu `document.activeElement` vào `previousFocusRef`, gọi `dialogEl.showModal()` (có nhánh dự phòng `setAttribute('open', '')` cho môi trường kiểm thử không trình duyệt) và chuyển tiêu điểm vào phần tử tương tác đầu tiên bên trong hộp thoại.
 *   2. Lắng nghe sự kiện chuẩn `onCancel` của `<dialog>` để chặn hành vi đóng cứng của DOM (`e.preventDefault()`) và đồng bộ ngược qua `onOpenChange(false)`.
 *   3. Khi người dùng nhấn `Tab` / `Shift+Tab`, thu thập danh sách phần tử khả dụng theo `FOCUSABLE_SELECTOR` và quay vòng đầu-cuối (`O(K)` với `K` là số phần tử tương tác trong hộp thoại).
 */
export function Dialog({ open, onOpenChange, children }: DialogProps) {
  // CONFLICT-RESOLVED: Chuyển từ thẻ dialog phi phương thức sang gọi .showModal() kèm bẫy tiêu điểm bàn phím, xử lý sự kiện cancel (Escape) và hoàn trả focus chuẩn WCAG 2.1 AA.
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
      const candidates = Array.from(
        dialogEl.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
      ).filter(
        (el) =>
          !el.hasAttribute('disabled') &&
          el.getAttribute('aria-hidden') !== 'true' &&
          window.getComputedStyle(el).display !== 'none' &&
          window.getComputedStyle(el).visibility !== 'hidden',
      );
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

      const focusables = Array.from(
        dialogEl.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
      ).filter(
        (el) =>
          !el.hasAttribute('disabled') &&
          el.getAttribute('aria-hidden') !== 'true' &&
          window.getComputedStyle(el).display !== 'none' &&
          window.getComputedStyle(el).visibility !== 'hidden',
      );

      if (focusables.length === 0) {
        e.preventDefault();
        dialogEl.focus();
        return;
      }

      const first = focusables[0]!;
      const last = focusables[focusables.length - 1]!;
      const active = document.activeElement;

      if (e.shiftKey) {
        if (active === first || !dialogEl.contains(active)) {
          e.preventDefault();
          last.focus();
        }
      } else if (active === last || !dialogEl.contains(active)) {
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
      if (prev && typeof prev.focus === 'function' && document.contains(prev)) {
        prev.focus();
      }
    };
  }, [open]);

  if (!open) return null;

  return (
    <DialogContext.Provider
      value={{
        open,
        onOpenChange,
        titleId,
        descriptionId,
        hasDescription,
        setHasDescription,
      }}
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
}: React.HTMLAttributes<HTMLDivElement> & { showClose?: boolean }) {
  const { onOpenChange } = React.useContext(DialogContext);
  return (
    <div
      data-dialog-content="true"
      className={cn(
        'relative w-full max-w-lg rounded-[28px] border border-[#ebebeb] bg-[#ffffff] p-5 sm:p-7 text-[#222222] shadow-[0_20px_60px_rgba(0,0,0,0.12)] backdrop-blur-md animate-modal-enter max-h-[88vh] overflow-y-auto',
        className,
      )}
      {...props}
    >
      {showClose && (
        <button
          type="button"
          data-dialog-close="true"
          onClick={() => onOpenChange(false)}
          className="absolute right-4 top-4 rounded-full p-1.5 text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF385C] cursor-pointer"
          aria-label="Đóng hộp thoại"
        >
          <X size={16} strokeWidth={2} aria-hidden="true" />
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
  id,
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLHeadingElement>) {
  const { titleId } = React.useContext(DialogContext);
  return (
    <h2
      id={id ?? titleId}
      className={cn('text-lg font-semibold leading-none tracking-tight text-[#222222]', className)}
      {...props}
    >
      {children}
    </h2>
  );
}

export function DialogDescription({
  id,
  className,
  ...props
}: React.HTMLAttributes<HTMLParagraphElement>) {
  const { descriptionId, setHasDescription } = React.useContext(DialogContext);

  React.useEffect(() => {
    setHasDescription(true);
    return () => setHasDescription(false);
  }, [setHasDescription]);

  return (
    <p
      id={id ?? descriptionId}
      className={cn('text-xs text-[#717171] mt-1 leading-relaxed', className)}
      {...props}
    />
  );
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

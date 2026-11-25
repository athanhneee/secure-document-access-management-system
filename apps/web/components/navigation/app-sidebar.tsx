'use client';

/**
 * Thuật toán: Thanh Điều Hướng Song Chế Độ — `<aside>` Cố Định Trên Desktop & `<dialog>.showModal()` Trên Mobile (`AppSidebar`)
 * Mục đích:
 *   - Giữ thanh điều hướng `<aside>` hiển thị tức thì trên màn hình lớn (`lg:flex`) không tốn chi phí dựng lại.
 *   - Khi mở trên màn hình nhỏ (`isOpen === true`), kích hoạt phần tử `<dialog>` Top-Layer chuẩn HTML5 qua `.showModal()`, giam tiêu điểm bàn phím `Tab` / `Shift+Tab`, xử lý phím `Escape` (`onCancel`) và nhấp vùng nền mờ, đồng thời hoàn trả tiêu điểm về nút mở khi đóng.
 */
import { useEffect, useId, useRef } from 'react';
import { usePathname } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import { getVisibleFocusables } from '@/components/ui/dialog-focus';
import { SidebarDirectory } from './sidebar-directory';

interface AppSidebarProps {
  isOpen?: boolean | undefined;
  onClose?: (() => void) | undefined;
}

export function AppSidebar({ isOpen = false, onClose }: AppSidebarProps) {
  const pathname = usePathname();
  const { user } = useAuth();
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const onCloseRef = useRef(onClose);
  const mobileHeadingId = useId();

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!isOpen) return;

    const dialogEl = dialogRef.current;
    previousFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    document.body.style.overflow = 'hidden';

    if (dialogEl && !dialogEl.open && typeof dialogEl.showModal === 'function') {
      try {
        dialogEl.showModal();
      } catch {
        // Bỏ qua nếu hộp thoại đã ở trạng thái mở
      }
    }

    if (dialogEl && !dialogEl.contains(document.activeElement)) {
      const candidates = getVisibleFocusables(dialogEl);
      const preferred =
        candidates.find((el) => el.getAttribute('data-drawer-close') !== 'true') ??
        candidates[0] ??
        dialogEl;
      preferred.focus();
    }

    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        onCloseRef.current?.();
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
      const panelEl = dialogEl.querySelector('[data-drawer-panel="true"]');
      if (panelEl && !panelEl.contains(e.target as Node)) {
        onCloseRef.current?.();
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
          // Bỏ qua nếu hộp thoại đã đóng
        }
      }
      const prev = previousFocusRef.current;
      if (prev && typeof prev.focus === 'function' && document.contains(prev)) {
        prev.focus();
      }
    };
  }, [isOpen]);

  return (
    <>
      <aside
        className="hidden lg:flex w-60 shrink-0 flex-col border-r border-[#ebebeb] bg-[#ffffff] p-3"
        aria-label="Thanh điều hướng phân hệ"
      >
        <SidebarDirectory pathname={pathname} user={user} userRoles={user?.roles} />
      </aside>

      {isOpen && (
        <dialog
          ref={dialogRef}
          tabIndex={-1}
          aria-modal="true"
          aria-labelledby={mobileHeadingId}
          onCancel={(e) => {
            e.preventDefault();
            onClose?.();
          }}
          className="fixed inset-0 z-50 m-0 flex h-full w-full max-h-none max-w-none items-stretch justify-start border-none bg-transparent p-0 outline-none lg:hidden"
        >
          <aside
            data-drawer-panel="true"
            className="flex h-full w-72 max-w-[calc(100vw-2.5rem)] flex-col border-r border-[#ebebeb] bg-[#ffffff] p-3.5 shadow-xl animate-modal-enter"
            aria-label="Thanh điều hướng phân hệ di động"
          >
            <SidebarDirectory
              pathname={pathname}
              user={user}
              userRoles={user?.roles}
              onNavigate={onClose}
              headingId={mobileHeadingId}
              onCloseButton={() => onClose?.()}
            />
          </aside>
        </dialog>
      )}
    </>
  );
}

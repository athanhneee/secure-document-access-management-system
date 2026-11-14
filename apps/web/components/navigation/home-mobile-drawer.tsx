'use client';

import { useEffect, useId, useRef } from 'react';
import Link from 'next/link';
import {
  FileText,
  Lock,
  CheckCircle2,
  ArrowRight,
  Eye,
  ShieldAlert,
  ClipboardCheck,
  Settings,
  X,
} from 'lucide-react';
import { getVisibleFocusables } from '@/components/ui/dialog-focus';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

const QUICK_ROLES = [
  { name: 'Chủ sở hữu', href: '/owner', icon: FileText, color: 'text-[#008489]' },
  { name: 'Người đọc', href: '/reader', icon: Eye, color: 'text-[#008A05]' },
  { name: 'Sĩ quan SOC', href: '/security', icon: ShieldAlert, color: 'text-[#C13515]' },
  { name: 'Kiểm toán viên', href: '/auditor', icon: ClipboardCheck, color: 'text-[#008489]' },
  { name: 'Quản trị viên', href: '/admin', icon: Settings, color: 'text-[#E31C5F]' },
] as const;

interface HomeMobileDrawerProps {
  onClose: () => void;
}

/**
 * Thuật toán: Ngăn Kéo Điều Hướng Di Động Phương Thức `<dialog>.showModal()` Trên Màn Hình `375px` (`HomeMobileDrawer`)
 * Mục đích:
 *   - Nâng cấp ngăn kéo điều hướng trang chủ lên phần tử `<dialog>` chuẩn HTML5 Top-Layer kích hoạt qua `.showModal()`, bẫy vòng lặp phím `Tab` / `Shift+Tab`, đóng khi nhấn `Escape` (`onCancel`) hoặc nhấp nền mờ `::backdrop` và hoàn trả tiêu điểm về nút mở khi đóng.
 *   - Đảm bảo mọi mục điều hướng đạt vùng chạm tối thiểu `44x44px` và độ tương phản chuẩn WCAG 2.1 AA.
 */
export function HomeMobileDrawer({ onClose }: HomeMobileDrawerProps) {
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const onCloseRef = useRef(onClose);
  const titleId = useId();

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    const dialogEl = dialogRef.current;
    previousFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    document.body.style.overflow = 'hidden';

    if (dialogEl && !dialogEl.open && typeof dialogEl.showModal === 'function') {
      try {
        dialogEl.showModal();
      } catch {
        // Bỏ qua nếu trình duyệt đã mở hộp thoại trong cùng chu kỳ render
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
        onCloseRef.current();
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
        onCloseRef.current();
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
  }, []);

  return (
    <dialog
      ref={dialogRef}
      tabIndex={-1}
      aria-modal="true"
      aria-labelledby={titleId}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      className="fixed inset-0 z-50 m-0 flex h-full w-full max-h-none max-w-none flex-col justify-start border-none bg-[#222222]/40 p-0 outline-none backdrop-blur-xs md:hidden"
    >
      <nav
        data-drawer-panel="true"
        className="relative w-full border-b border-[#ebebeb] bg-[#ffffff] p-4 shadow-xl animate-modal-enter max-h-[90dvh] overflow-y-auto"
        aria-label="Điều hướng di động"
      >
        <div className="mb-3 flex items-center justify-between border-b border-[#ebebeb] pb-2.5">
          <h2
            id={titleId}
            className="px-2 text-xs font-bold uppercase tracking-wider text-[#222222]"
          >
            Menu điều hướng
          </h2>
          <button
            type="button"
            data-drawer-close="true"
            onClick={onClose}
            aria-label="Đóng menu điều hướng"
            className="flex h-11 w-11 items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors cursor-pointer"
          >
            <X size={20} strokeWidth={2} aria-hidden="true" />
          </button>
        </div>

        <div className="space-y-1">
          <div className="px-2 pb-1.5 text-xs font-semibold uppercase tracking-wider text-[#717171]">
            Nội dung hệ thống
          </div>
          <a
            href="#vai-tro"
            onClick={onClose}
            className="flex min-h-11 items-center justify-between rounded-full px-3.5 py-2.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] active:bg-[#f7f7f7] transition-colors"
          >
            <span className="flex items-center gap-2.5">
              <FileText
                size={16}
                strokeWidth={1.75}
                className="text-[#008489]"
                aria-hidden="true"
              />
              <span>Không gian làm việc theo vai trò</span>
            </span>
            <ArrowRight
              size={16}
              strokeWidth={1.75}
              className="text-[#717171]"
              aria-hidden="true"
            />
          </a>

          <a
            href="#kien-truc"
            onClick={onClose}
            className="flex min-h-11 items-center justify-between rounded-full px-3.5 py-2.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] active:bg-[#f7f7f7] transition-colors"
          >
            <span className="flex items-center gap-2.5">
              <Lock size={16} strokeWidth={1.75} className="text-[#E31C5F]" aria-hidden="true" />
              <span>Kiến trúc an ninh đa tầng</span>
            </span>
            <ArrowRight
              size={16}
              strokeWidth={1.75}
              className="text-[#717171]"
              aria-hidden="true"
            />
          </a>

          <a
            href="#tieu-chuan"
            onClick={onClose}
            className="flex min-h-11 items-center justify-between rounded-full px-3.5 py-2.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] active:bg-[#f7f7f7] transition-colors"
          >
            <span className="flex items-center gap-2.5">
              <CheckCircle2
                size={16}
                strokeWidth={1.75}
                className="text-[#008A05]"
                aria-hidden="true"
              />
              <span>Tiêu chuẩn tuân thủ &amp; pháp lý</span>
            </span>
            <ArrowRight
              size={16}
              strokeWidth={1.75}
              className="text-[#717171]"
              aria-hidden="true"
            />
          </a>
        </div>

        <div className="mt-4 pt-4 border-t border-[#ebebeb]">
          <div className="px-2 pb-2 text-xs font-semibold uppercase tracking-wider text-[#717171]">
            Cổng truy cập vai trò
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {QUICK_ROLES.map((role) => {
              const Icon = role.icon;
              return (
                <Link
                  key={role.name}
                  href={role.href}
                  onClick={onClose}
                  className="flex min-h-11 items-center gap-2 rounded-full border border-[#ebebeb] bg-[#ffffff] px-3.5 py-2.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] active:bg-[#f7f7f7] transition-colors"
                >
                  <Icon size={16} strokeWidth={1.75} className={role.color} aria-hidden="true" />
                  <span className="truncate">{role.name}</span>
                </Link>
              );
            })}
          </div>
        </div>

        <div className="mt-5 pt-4 border-t border-[#ebebeb] space-y-3">
          <div className="flex items-center justify-between px-1 text-xs text-[#717171]">
            <span>Trạng thái kiến trúc:</span>
            <span className="staff-badge bg-transparent border-0 p-0 inline-flex items-center gap-1.5 font-semibold text-[#008A05]">
              <span className="dot dot-success animate-pulse" aria-hidden="true" />
              <span>Zero-Trust Active</span>
            </span>
          </div>

          <InteractiveHoverButton
            href="/login"
            variant="solid"
            text="Bắt đầu phiên làm việc"
            className="w-full min-h-11 text-xs"
            onClick={onClose}
          />
        </div>
      </nav>
    </dialog>
  );
}

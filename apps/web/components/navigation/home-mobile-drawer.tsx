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
  LogOut,
  X,
} from 'lucide-react';
import { resolveDefaultPortalForRoles, useAuth, type RoleType } from '@/lib/auth-context';
import { getVisibleFocusables } from '@/components/ui/dialog-focus';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

const QUICK_ROLES: ReadonlyArray<{
  role: RoleType;
  name: string;
  href: string;
  icon: typeof FileText;
  color: string;
}> = [
  {
    role: 'DOCUMENT_OWNER',
    name: 'Chủ sở hữu tài liệu',
    href: '/owner',
    icon: FileText,
    color: 'text-[#008489]',
  },
  {
    role: 'DOCUMENT_READER',
    name: 'Người đọc tài liệu',
    href: '/reader',
    icon: Eye,
    color: 'text-[#008A05]',
  },
  {
    role: 'SECURITY_OFFICER',
    name: 'An ninh thông tin',
    href: '/security',
    icon: ShieldAlert,
    color: 'text-[#C13515]',
  },
  {
    role: 'AUDITOR',
    name: 'Kiểm toán độc lập',
    href: '/auditor',
    icon: ClipboardCheck,
    color: 'text-[#008489]',
  },
  {
    role: 'SYSTEM_ADMIN',
    name: 'Quản trị hệ thống',
    href: '/admin',
    icon: Settings,
    color: 'text-[#E31C5F]',
  },
];

interface HomeMobileDrawerProps {
  onClose: () => void;
}

/**
 * Thuật toán: Ngăn Kéo Điều Hướng Di Động Phương Thức `<dialog>.showModal()` Có Lọc Quyền RBAC (`HomeMobileDrawer`)
 * Mục đích:
 *   - Kích hoạt `<dialog>` chuẩn HTML5 Top-Layer qua `.showModal()`, bẫy vòng lặp phím `Tab` / `Shift+Tab`, đóng khi nhấn `Escape` hoặc nhấp `::backdrop` và hoàn trả tiêu điểm.
 *   - Khi người dùng đã đăng nhập, chỉ hiển thị các lối tắt phân hệ khớp với `user.roles` và nút vào phân hệ/đăng xuất, tuyệt đối không hiển thị phân hệ không có quyền.
 */
export function HomeMobileDrawer({ onClose }: HomeMobileDrawerProps) {
  const { isAuthenticated, user, logout, canAccessPortal } = useAuth();
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const skipRestoreFocusRef = useRef(false);
  const onCloseRef = useRef(onClose);
  const titleId = useId();

  function handleAnchorClose() {
    skipRestoreFocusRef.current = true;
    onClose();
  }

  const visibleRoles =
    isAuthenticated && user
      ? QUICK_ROLES.filter((item) => canAccessPortal(item.role))
      : QUICK_ROLES;
  const workspaceHref = resolveDefaultPortalForRoles(user);

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
      if (
        !skipRestoreFocusRef.current &&
        prev &&
        typeof prev.focus === 'function' &&
        document.contains(prev)
      ) {
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
      className="fixed inset-0 z-50 m-0 flex h-full w-full max-h-none max-w-none flex-col justify-start border-none bg-transparent p-0 outline-none md:hidden"
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
            onClick={handleAnchorClose}
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
            onClick={handleAnchorClose}
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
            onClick={handleAnchorClose}
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

        {visibleRoles.length > 0 && (
          <div className="mt-4 pt-4 border-t border-[#ebebeb]">
            <div className="px-2 pb-2 text-xs font-semibold uppercase tracking-wider text-[#717171]">
              {isAuthenticated ? 'Phân hệ được cấp' : 'Cổng truy cập vai trò'}
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {visibleRoles.map((role) => {
                const Icon = role.icon;
                return (
                  <Link
                    key={role.role}
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
        )}

        <div className="mt-5 pt-4 border-t border-[#ebebeb] space-y-2.5">
          {isAuthenticated && user ? (
            <div className="space-y-2">
              <InteractiveHoverButton
                href={workspaceHref}
                variant="solid"
                text="Vào phân hệ làm việc"
                className="w-full min-h-11 text-xs"
                onClick={onClose}
              />
              <InteractiveHoverButton
                type="button"
                variant="secondary"
                text="Đăng xuất"
                icon={<LogOut size={16} strokeWidth={1.75} aria-hidden="true" />}
                className="w-full min-h-11 text-xs"
                onClick={() => {
                  onClose();
                  void logout();
                }}
              />
            </div>
          ) : (
            <InteractiveHoverButton
              href="/login"
              variant="solid"
              text="Bắt đầu phiên làm việc"
              className="w-full min-h-11 text-xs"
              onClick={onClose}
            />
          )}
        </div>
      </nav>
    </dialog>
  );
}

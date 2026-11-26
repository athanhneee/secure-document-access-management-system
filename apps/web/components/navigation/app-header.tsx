'use client';

import React, { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  ShieldCheck,
  Menu,
  X,
  LogOut,
  Laptop,
  User,
  Sliders,
  FolderLock,
  BookOpen,
  AlertOctagon,
  FileCheck,
  ChevronDown,
} from 'lucide-react';
import { useAuth, ROLE_LABELS, type RoleType } from '@/lib/auth-context';
import { ClassificationBadge } from '@/components/classification-badge';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { NotificationBellDialog } from './notification-bell-dialog';

interface AppHeaderProps {
  onToggleSidebar?: (() => void) | undefined;
  isSidebarOpen?: boolean | undefined;
}

const ROLE_NAV_ITEMS: ReadonlyArray<{
  role: RoleType;
  label: string;
  href: string;
  icon: React.ElementType;
}> = [
  { role: 'SYSTEM_ADMIN', label: 'Quản trị hệ thống', href: '/admin', icon: Sliders },
  { role: 'DOCUMENT_OWNER', label: 'Chủ sở hữu tài liệu', href: '/owner', icon: FolderLock },
  { role: 'DOCUMENT_READER', label: 'Người đọc tài liệu', href: '/reader', icon: BookOpen },
  { role: 'SECURITY_OFFICER', label: 'An ninh thông tin', href: '/security', icon: AlertOctagon },
  { role: 'AUDITOR', label: 'Kiểm toán độc lập', href: '/auditor', icon: FileCheck },
];

/**
 * Thuật toán: Thanh Đầu Đề Điều Phối Góc Nhìn RBAC Đã Lọc Quyền, Chuông Nội Bộ Có Điều Kiện & Quản Lý Phiên `375px` (`AppHeader`)
 * Mục đích:
 *   - Chỉ hiển thị bộ chuyển đổi góc nhìn thả xuống khi tài khoản sở hữu từ 2 phân hệ trở lên; khi chỉ có 1 phân hệ thì dựng liên kết pill dẫn thẳng về phân hệ đó để người dùng quay về nhanh từ `/sessions` (`V-59`).
 *   - Hiển thị biểu tượng chuông thông báo (`NotificationBellDialog`) cho mọi người dùng đã xác thực (`@AllowAuthenticatedSelf` — `BUG-062`).
 *   - Hiển thị tên tài khoản kèm cấp thẩm quyền bảo mật (`clearanceCode`) trên màn hình rộng và trong ngăn kéo di động (`V-30`).
 */
export function AppHeader({ onToggleSidebar, isSidebarOpen }: AppHeaderProps) {
  const { user, activeRole, setActiveRole, logout, isAuthenticated, canAccessPortal } = useAuth();
  const [roleMenuOpen, setRoleMenuOpen] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setRoleMenuOpen(false);
      }
    }
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape' && roleMenuOpen) {
        setRoleMenuOpen(false);
      }
    }
    if (roleMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [roleMenuOpen]);

  async function handleLogoutClick() {
    if (isLoggingOut) return;
    setIsLoggingOut(true);
    try {
      await logout();
    } finally {
      setIsLoggingOut(false);
    }
  }

  const authorizedRoleItems = user
    ? ROLE_NAV_ITEMS.filter((item) => canAccessPortal(item.role))
    : [];
  const canViewNotifications = Boolean(isAuthenticated && user);
  const singleRoleItem = authorizedRoleItems.length === 1 ? authorizedRoleItems[0]! : null;
  const singleRoleLabel = singleRoleItem
    ? ROLE_LABELS[singleRoleItem.role]
    : activeRole
      ? ROLE_LABELS[activeRole]
      : null;

  return (
    <header className="sticky top-0 z-40 flex h-14 w-full items-center justify-between border-b border-[#ebebeb] bg-[#ffffff]/90 px-3 sm:px-6 backdrop-blur-md">
      <div className="flex items-center gap-1.5 sm:gap-3 min-w-0">
        {onToggleSidebar && (
          <button
            type="button"
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] lg:hidden cursor-pointer transition-colors"
            onClick={onToggleSidebar}
            aria-label={isSidebarOpen ? 'Đóng bảng điều hướng' : 'Mở bảng điều hướng'}
            aria-expanded={Boolean(isSidebarOpen)}
          >
            {isSidebarOpen ? (
              <X size={20} strokeWidth={2} aria-hidden="true" />
            ) : (
              <Menu size={20} strokeWidth={2} aria-hidden="true" />
            )}
          </button>
        )}

        <Link
          href={singleRoleItem ? singleRoleItem.href : '/'}
          className="flex items-center gap-2 shrink-0 transition-opacity hover:opacity-90"
          aria-label={
            singleRoleItem
              ? `Về phân hệ ${singleRoleLabel ?? 'làm việc'} SecureDocument`
              : 'Về trang chủ SecureDocument'
          }
        >
          <ShieldCheck size={20} strokeWidth={1.75} className="text-[#E31C5F]" aria-hidden="true" />
          <span className="hidden text-sm font-semibold tracking-tight text-[#222222] sm:inline-block">
            Secure<span className="font-light text-[#E31C5F]">Document</span>
          </span>
        </Link>

        {isAuthenticated && user && authorizedRoleItems.length > 1 && (
          <div className="relative ml-0.5 sm:ml-2 min-w-0" ref={menuRef}>
            <button
              type="button"
              onClick={() => setRoleMenuOpen(!roleMenuOpen)}
              className="flex min-h-11 sm:min-h-9 min-w-0 max-w-full items-center gap-1.5 sm:gap-2 rounded-full border border-[#ebebeb] bg-[#f7f7f7] sm:bg-[#ffffff] px-3 py-1 text-xs font-semibold sm:font-medium text-[#222222] transition-colors hover:border-[#dddddd] hover:bg-[#f7f7f7] cursor-pointer"
              aria-expanded={roleMenuOpen}
              aria-haspopup="true"
            >
              <span className="dot dot-success shrink-0" aria-hidden="true" />
              <span className="min-w-0 max-w-[110px] sm:max-w-none truncate">
                {activeRole ? ROLE_LABELS[activeRole] : 'Chuyển vai trò'}
              </span>
              <ChevronDown
                size={16}
                strokeWidth={1.75}
                className="shrink-0 text-[#717171]"
                aria-hidden="true"
              />
            </button>

            {roleMenuOpen && (
              <div
                className="absolute left-0 mt-2 w-60 max-w-[calc(100vw-2rem)] rounded-[24px] border border-[#ebebeb] bg-[#ffffff] p-2 shadow-[0_12px_36px_rgba(0,0,0,0.1)] backdrop-blur-xl z-50 animate-in fade-in zoom-in-95 duration-100"
                role="menu"
              >
                <div className="px-2.5 py-1 text-xs font-semibold uppercase tracking-wider text-[#717171]">
                  Chuyển phân hệ được cấp
                </div>
                {authorizedRoleItems.map((item) => {
                  const isCurrent = activeRole === item.role;
                  const Icon = item.icon;

                  return (
                    <button
                      key={item.role}
                      type="button"
                      onClick={() => {
                        setActiveRole(item.role);
                        setRoleMenuOpen(false);
                        router.push(item.href);
                      }}
                      className={`flex min-h-11 sm:min-h-9 w-full items-center justify-between rounded-full px-3 py-2 text-xs transition-colors cursor-pointer ${
                        isCurrent
                          ? 'bg-[#f7f7f7] font-semibold text-[#E31C5F] border border-[#ebebeb]'
                          : 'text-[#222222] hover:bg-[#f7f7f7]'
                      }`}
                      role="menuitem"
                    >
                      <div className="flex items-center gap-2">
                        <Icon size={16} strokeWidth={1.75} aria-hidden="true" />
                        <span>{item.label}</span>
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {isAuthenticated && user && singleRoleItem && singleRoleLabel && (
          <Link
            href={singleRoleItem.href}
            className="staff-badge bg-transparent border-0 p-0 ml-1 sm:ml-2 inline-flex min-h-11 sm:min-h-8 min-w-0 items-center gap-1.5 text-xs font-semibold text-[#222222] hover:text-[#E31C5F] transition-colors"
            title={`Quay về phân hệ ${singleRoleLabel}`}
          >
            <span className="dot dot-success shrink-0" aria-hidden="true" />
            <span className="min-w-0 max-w-[140px] sm:max-w-none truncate">{singleRoleLabel}</span>
          </Link>
        )}
      </div>

      <div className="flex items-center gap-1.5 sm:gap-2.5 shrink-0">
        {isAuthenticated && user ? (
          <>
            {canViewNotifications && (
              <NotificationBellDialog userId={user.id} canViewNotifications />
            )}

            <Link
              href="/sessions"
              aria-current={pathname === '/sessions' ? 'page' : undefined}
              className={`flex h-11 w-11 md:h-auto md:w-auto md:min-h-9 items-center justify-center gap-1.5 rounded-full border border-[#ebebeb] bg-[#ffffff] md:px-3 md:py-1 text-xs text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors shadow-2xs ${
                pathname === '/sessions'
                  ? 'border-[#222222] bg-[#f7f7f7] text-[#222222] font-semibold'
                  : ''
              }`}
              title="Quản lý phiên, mật khẩu và MFA"
              aria-label="Quản lý phiên và thiết bị"
            >
              <Laptop size={16} strokeWidth={1.75} aria-hidden="true" />
              <span className="hidden md:inline text-xs font-medium">Phiên &amp; thiết bị</span>
            </Link>

            <span className="staff-badge bg-transparent border-0 p-0 hidden lg:inline-flex items-center gap-1.5 text-xs font-semibold text-[#008489] select-none">
              <User size={16} strokeWidth={1.75} aria-hidden="true" />
              <span className="max-w-[160px] truncate">{user.fullName || user.username}</span>
            </span>

            {user.clearanceCode && (
              <span className="hidden xl:inline-flex items-center">
                <ClassificationBadge
                  code={user.clearanceCode}
                  rank={user.clearanceRank}
                  subject="user"
                  size="sm"
                />
              </span>
            )}

            <button
              type="button"
              disabled={isLoggingOut}
              onClick={() => void handleLogoutClick()}
              aria-label="Đăng xuất khỏi hệ thống"
              title="Đăng xuất"
              className="flex sm:hidden h-11 w-11 shrink-0 items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#222222] hover:bg-[#f7f7f7] transition-colors cursor-pointer shadow-2xs disabled:opacity-50"
            >
              <LogOut size={16} strokeWidth={1.75} aria-hidden="true" />
            </button>

            <span className="hidden sm:inline-flex">
              <InteractiveHoverButton
                variant="secondary"
                size="sm"
                text="Đăng xuất"
                isLoading={isLoggingOut}
                disabled={isLoggingOut}
                icon={<LogOut size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={handleLogoutClick}
                aria-label="Đăng xuất khỏi hệ thống"
                className="px-3"
              />
            </span>
          </>
        ) : (
          <InteractiveHoverButton href="/login" variant="primary" size="sm" text="Đăng nhập" />
        )}
      </div>
    </header>
  );
}

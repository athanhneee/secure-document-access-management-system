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
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

interface AppHeaderProps {
  onToggleSidebar?: (() => void) | undefined;
  isSidebarOpen?: boolean | undefined;
}

export function AppHeader({ onToggleSidebar, isSidebarOpen }: AppHeaderProps) {
  const { user, activeRole, setActiveRole, logout, isAuthenticated } = useAuth();
  const [roleMenuOpen, setRoleMenuOpen] = useState(false);
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

  const roleNavItems: Array<{
    role: RoleType;
    label: string;
    href: string;
    icon: React.ElementType;
  }> = [
    { role: 'SYSTEM_ADMIN', label: 'Quản trị viên', href: '/admin', icon: Sliders },
    { role: 'DOCUMENT_OWNER', label: 'Chủ sở hữu', href: '/owner', icon: FolderLock },
    { role: 'DOCUMENT_READER', label: 'Người đọc', href: '/reader', icon: BookOpen },
    { role: 'SECURITY_OFFICER', label: 'An ninh thông tin', href: '/security', icon: AlertOctagon },
    { role: 'AUDITOR', label: 'Kiểm toán viên', href: '/auditor', icon: FileCheck },
  ];

  return (
    <header className="sticky top-0 z-40 flex h-14 w-full items-center justify-between border-b border-[#ebebeb] bg-[#ffffff]/90 px-3 sm:px-6 backdrop-blur-md">
      <div className="flex items-center gap-2 sm:gap-3 min-w-0">
        {onToggleSidebar && (
          <button
            type="button"
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] lg:hidden cursor-pointer transition-colors"
            onClick={onToggleSidebar}
            aria-label={isSidebarOpen ? 'Đóng bảng điều hướng' : 'Mở bảng điều hướng'}
          >
            {isSidebarOpen ? (
              <X size={20} strokeWidth={2} aria-hidden="true" />
            ) : (
              <Menu size={20} strokeWidth={2} aria-hidden="true" />
            )}
          </button>
        )}

        <Link
          href="/"
          className="flex items-center gap-2 shrink-0 transition-opacity hover:opacity-90"
          aria-label="Về trang chủ Secure Document"
        >
          <ShieldCheck size={20} strokeWidth={1.75} className="text-[#E31C5F]" aria-hidden="true" />
          <span className="hidden text-sm font-semibold tracking-tight text-[#222222] sm:inline-block">
            Secure<span className="font-light text-[#E31C5F]">Document</span>
          </span>
        </Link>

        {isAuthenticated && user && (
          <div className="relative ml-1 sm:ml-2" ref={menuRef}>
            <button
              type="button"
              onClick={() => setRoleMenuOpen(!roleMenuOpen)}
              className="flex min-h-11 sm:min-h-9 items-center gap-1.5 sm:gap-2 rounded-full border border-[#ebebeb] bg-[#ffffff] px-2.5 py-1 sm:px-3 text-xs font-medium text-[#222222] transition-colors hover:border-[#dddddd] hover:bg-[#f7f7f7] cursor-pointer shadow-2xs"
              aria-expanded={roleMenuOpen}
              aria-haspopup="true"
            >
              <span className="dot dot-success" aria-hidden="true" />
              <span className="max-w-[84px] sm:max-w-none truncate">
                {activeRole ? ROLE_LABELS[activeRole] : 'Góc nhìn'}
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
                className="absolute left-0 mt-2 w-64 max-w-[calc(100vw-2rem)] rounded-[24px] border border-[#ebebeb] bg-[#ffffff] p-2 shadow-[0_12px_36px_rgba(0,0,0,0.1)] backdrop-blur-xl z-50 animate-in fade-in zoom-in-95 duration-100"
                role="menu"
              >
                <div className="px-2.5 py-1 text-[13px] font-semibold uppercase tracking-wider text-[#717171]">
                  Góc nhìn theo vai trò (RBAC)
                </div>
                {roleNavItems.map((item) => {
                  const hasAccess = user.roles.includes(item.role);
                  const isCurrent = activeRole === item.role;
                  const Icon = item.icon;

                  return (
                    <button
                      key={item.role}
                      type="button"
                      disabled={!hasAccess}
                      onClick={() => {
                        setActiveRole(item.role);
                        setRoleMenuOpen(false);
                        router.push(item.href);
                      }}
                      className={`flex min-h-11 sm:min-h-9 w-full items-center justify-between rounded-full px-3 py-2 text-xs transition-colors cursor-pointer ${
                        isCurrent
                          ? 'bg-[#FF385C]/10 font-semibold text-[#E31C5F] border border-[#E31C5F]/30'
                          : hasAccess
                            ? 'text-[#222222] hover:bg-[#f7f7f7]'
                            : 'cursor-not-allowed text-[#717171] opacity-75'
                      }`}
                      role="menuitem"
                    >
                      <div className="flex items-center gap-2">
                        <Icon size={16} strokeWidth={1.75} aria-hidden="true" />
                        <span>{item.label}</span>
                      </div>
                      {hasAccess ? (
                        <span className="text-[12px] text-[#008A05] font-bold">Được cấp</span>
                      ) : (
                        <span className="text-[12px] text-[#717171]">Khóa</span>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex items-center gap-1.5 sm:gap-3 shrink-0">
        {isAuthenticated && user ? (
          <>
            <Link
              href="/sessions"
              className={`flex min-h-11 sm:min-h-9 items-center justify-center gap-1.5 rounded-full border border-[#ebebeb] bg-[#ffffff] px-3 py-1 text-xs text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors shadow-2xs ${
                pathname === '/sessions' ? 'border-[#E31C5F]/40 bg-[#FF385C]/10 text-[#E31C5F]' : ''
              }`}
              title="Quản lý phiên đăng nhập thiết bị"
              aria-label="Quản lý phiên đăng nhập"
            >
              <Laptop size={16} strokeWidth={1.75} aria-hidden="true" />
              <span className="hidden md:inline text-xs font-medium">Phiên làm việc</span>
            </Link>

            <span className="staff-badge hidden sm:inline-flex items-center gap-1.5 text-xs font-semibold text-[#008489] select-none">
              <User size={16} strokeWidth={1.75} aria-hidden="true" />
              <span>{user.fullName || user.username}</span>
            </span>

            <InteractiveHoverButton
              variant="secondary"
              size="sm"
              text="Đăng xuất"
              icon={<LogOut size={16} strokeWidth={1.75} aria-hidden="true" />}
              onClick={() => void logout()}
              aria-label="Đăng xuất khỏi hệ thống"
            />
          </>
        ) : (
          <InteractiveHoverButton href="/login" variant="primary" size="sm" text="Đăng nhập" />
        )}
      </div>
    </header>
  );
}

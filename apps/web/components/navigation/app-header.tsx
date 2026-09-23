'use client';

import React, { useState } from 'react';
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
import { Button } from '@/components/ui/button';

interface AppHeaderProps {
  onToggleSidebar?: () => void;
  isSidebarOpen?: boolean;
}

export function AppHeader({ onToggleSidebar, isSidebarOpen }: AppHeaderProps) {
  const { user, activeRole, setActiveRole, logout, isAuthenticated } = useAuth();
  const [roleMenuOpen, setRoleMenuOpen] = useState(false);
  const router = useRouter();
  const pathname = usePathname();

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
    <header className="sticky top-0 z-40 flex h-16 w-full items-center justify-between border-b border-slate-800 bg-slate-950/85 px-4 sm:px-6 backdrop-blur-md">
      <div className="flex items-center gap-3">
        {onToggleSidebar && (
          <button
            type="button"
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-800 bg-slate-900 text-slate-400 hover:bg-slate-800 hover:text-slate-100 lg:hidden"
            onClick={onToggleSidebar}
            aria-label={isSidebarOpen ? 'Đóng bảng điều hướng' : 'Mở bảng điều hướng'}
          >
            {isSidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        )}

        <Link
          href="/"
          className="flex items-center gap-2.5 transition-opacity hover:opacity-90"
          aria-label="Về trang chủ Secure Document"
        >
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-950/90 border border-emerald-500/40 text-emerald-400 shadow-sm">
            <ShieldCheck className="h-5 w-5" aria-hidden="true" />
          </div>
          <span className="hidden text-base font-semibold tracking-tight text-slate-100 sm:inline-block">
            Secure<span className="font-light text-emerald-400">Document</span>
          </span>
        </Link>

        {isAuthenticated && user && (
          <div className="relative ml-2">
            <button
              type="button"
              onClick={() => setRoleMenuOpen(!roleMenuOpen)}
              className="flex items-center gap-2 rounded-md border border-slate-800 bg-slate-900/90 px-3 py-1.5 text-xs font-medium text-slate-300 transition-colors hover:border-slate-700 hover:bg-slate-800"
              aria-expanded={roleMenuOpen}
              aria-haspopup="true"
            >
              <span className="h-2 w-2 rounded-full bg-emerald-500" aria-hidden="true" />
              <span>{activeRole ? ROLE_LABELS[activeRole] : 'Chọn góc nhìn vai trò'}</span>
              <ChevronDown className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
            </button>

            {roleMenuOpen && (
              <div
                className="absolute left-0 mt-2 w-64 rounded-xl border border-slate-800 bg-slate-900 p-2 shadow-2xl backdrop-blur-xl z-50 animate-in fade-in zoom-in-95 duration-100"
                role="menu"
              >
                <div className="px-2 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  Góc nhìn theo vai trò
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
                      className={`flex w-full items-center justify-between rounded-lg px-2.5 py-2 text-xs transition-colors ${
                        isCurrent
                          ? 'bg-emerald-950/60 font-semibold text-emerald-300 border border-emerald-800/40'
                          : hasAccess
                            ? 'text-slate-300 hover:bg-slate-800 hover:text-slate-100'
                            : 'cursor-not-allowed text-slate-600'
                      }`}
                      role="menuitem"
                    >
                      <div className="flex items-center gap-2">
                        <Icon className="h-4 w-4" aria-hidden="true" />
                        <span>{item.label}</span>
                      </div>
                      {hasAccess ? (
                        <span className="text-[10px] text-emerald-500 font-mono">Được cấp</span>
                      ) : (
                        <span className="text-[10px] text-slate-600">Khóa</span>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex items-center gap-2 sm:gap-3">
        {isAuthenticated && user ? (
          <>
            <Link
              href="/sessions"
              className={`flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-300 hover:bg-slate-800 hover:text-slate-100 transition-colors ${
                pathname === '/sessions'
                  ? 'border-emerald-600/50 bg-emerald-950/30 text-emerald-300'
                  : ''
              }`}
              title="Quản lý phiên đăng nhập thiết bị"
              aria-label="Quản lý phiên đăng nhập"
            >
              <Laptop className="h-4 w-4" aria-hidden="true" />
              <span className="hidden md:inline">Phiên làm việc</span>
            </Link>

            <div className="hidden sm:flex items-center gap-2 rounded-lg border border-slate-800/80 bg-slate-900/60 px-3 py-1 text-xs text-slate-300">
              <User className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
              <span className="font-medium text-slate-200">{user.fullName || user.username}</span>
            </div>

            <Button
              variant="outline"
              size="sm"
              className="border-slate-800 bg-slate-900 text-slate-300 hover:border-red-900/50 hover:bg-red-950/40 hover:text-red-300"
              onClick={() => void logout()}
              aria-label="Đăng xuất khỏi hệ thống"
            >
              <LogOut className="h-3.5 w-3.5 sm:mr-1.5" aria-hidden="true" />
              <span className="hidden sm:inline">Đăng xuất</span>
            </Button>
          </>
        ) : (
          <Link href="/login">
            <Button size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-white">
              Đăng nhập
            </Button>
          </Link>
        )}
      </div>
    </header>
  );
}

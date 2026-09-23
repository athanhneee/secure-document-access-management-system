'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Sliders,
  FolderLock,
  BookOpen,
  AlertOctagon,
  FileCheck,
  Laptop,
  Shield,
  ExternalLink,
  Lock,
} from 'lucide-react';
import { useAuth, type RoleType } from '@/lib/auth-context';

interface AppSidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

interface NavItem {
  title: string;
  href: string;
  role: RoleType;
  icon: React.ElementType;
  description: string;
}

const NAV_ITEMS: NavItem[] = [
  {
    title: 'Quản trị hệ thống',
    href: '/admin',
    role: 'SYSTEM_ADMIN',
    icon: Sliders,
    description: 'Tài khoản, phòng ban, RBAC, ABAC & cấu hình dấu bản quyền',
  },
  {
    title: 'Chủ sở hữu tài liệu',
    href: '/owner',
    role: 'DOCUMENT_OWNER',
    icon: FolderLock,
    description: 'Tải lên, phân loại mật, phê duyệt yêu cầu & thu hồi quyền',
  },
  {
    title: 'Người đọc tài liệu',
    href: '/reader',
    role: 'DOCUMENT_READER',
    icon: BookOpen,
    description: 'Tìm kiếm, gửi yêu cầu, xem trước an toàn & tải về',
  },
  {
    title: 'An ninh thông tin',
    href: '/security',
    role: 'SECURITY_OFFICER',
    icon: AlertOctagon,
    description: 'Cảnh báo an ninh, điều tra watermark, báo cáo sự cố & luật phát hiện',
  },
  {
    title: 'Kiểm toán độc lập',
    href: '/auditor',
    role: 'AUDITOR',
    icon: FileCheck,
    description: 'Nhật ký kiểm toán, xác minh chuỗi băm HMAC & xuất báo cáo',
  },
];

export function AppSidebar({ isOpen = false, onClose }: AppSidebarProps) {
  const pathname = usePathname();
  const { user } = useAuth();

  return (
    <>
      {/* Mobile backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden transition-opacity"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      {/* Sidebar container */}
      <aside
        className={`fixed top-16 bottom-0 left-0 z-40 flex w-72 flex-col border-r border-slate-800 bg-slate-950/95 p-4 backdrop-blur-xl transition-transform duration-200 lg:static lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
        aria-label="Thanh điều hướng chính"
      >
        <div className="mb-4 px-2">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
            <Shield className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
            <span>Phân hệ theo vai trò</span>
          </div>
          <p className="mt-1 text-[11px] text-slate-400">
            Truy cập được kiểm soát chặt chẽ ở tầng máy chủ (Zero Trust)
          </p>
        </div>

        <nav className="flex-1 space-y-1.5 overflow-y-auto pr-1" aria-label="Danh sách phân hệ">
          {NAV_ITEMS.map((item) => {
            const isActive = pathname?.startsWith(item.href);
            const hasAccess = user?.roles.includes(item.role);
            const Icon = item.icon;

            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => onClose?.()}
                className={`group flex items-start gap-3 rounded-xl p-3 text-xs transition-all ${
                  isActive
                    ? 'border border-emerald-600/50 bg-emerald-950/40 text-emerald-200 shadow-sm'
                    : hasAccess
                      ? 'border border-transparent text-slate-300 hover:border-slate-800 hover:bg-slate-900 hover:text-slate-100'
                      : 'border border-transparent text-slate-400 hover:bg-slate-900/50'
                }`}
                aria-current={isActive ? 'page' : undefined}
              >
                <div
                  className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border ${
                    isActive
                      ? 'border-emerald-500/50 bg-emerald-900/60 text-emerald-300'
                      : hasAccess
                        ? 'border-slate-800 bg-slate-900 text-slate-400 group-hover:border-slate-700 group-hover:text-slate-200'
                        : 'border-slate-900 bg-slate-950 text-slate-600'
                  }`}
                >
                  <Icon className="h-4 w-4" aria-hidden="true" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold">{item.title}</span>
                    {!hasAccess && (
                      <span className="flex items-center gap-1 text-[10px] text-slate-400">
                        <Lock className="h-3 w-3" aria-hidden="true" />
                        <span>Chưa gán</span>
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                    {item.description}
                  </p>
                </div>
              </Link>
            );
          })}
        </nav>

        {/* Bottom utility links */}
        <div className="mt-4 border-t border-slate-800 pt-3 space-y-1">
          <Link
            href="/sessions"
            onClick={() => onClose?.()}
            className={`flex items-center justify-between rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
              pathname === '/sessions'
                ? 'bg-slate-800 text-slate-100'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <div className="flex items-center gap-2">
              <Laptop className="h-4 w-4" aria-hidden="true" />
              <span>Quản lý phiên & thiết bị</span>
            </div>
          </Link>

          <Link
            href="/"
            onClick={() => onClose?.()}
            className="flex items-center justify-between rounded-lg px-3 py-2 text-xs font-medium text-slate-400 hover:bg-slate-900 hover:text-slate-200 transition-colors"
          >
            <div className="flex items-center gap-2">
              <ExternalLink className="h-4 w-4" aria-hidden="true" />
              <span>Trang thông tin chung</span>
            </div>
          </Link>
        </div>
      </aside>
    </>
  );
}

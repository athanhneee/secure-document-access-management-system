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
          className="fixed inset-0 z-40 bg-[#222222]/40 backdrop-blur-xs lg:hidden transition-opacity"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      {/* Sidebar container */}
      <aside
        className={`fixed top-14 bottom-0 left-0 z-40 flex w-68 flex-col border-r border-[#ebebeb] bg-[#ffffff] p-3.5 backdrop-blur-xl transition-transform duration-200 lg:static lg:translate-x-0 shadow-xs lg:shadow-none ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
        aria-label="Thanh điều hướng phân hệ"
      >
        <div className="mb-3 px-2">
          <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-[#717171]">
            <Shield className="h-3.5 w-3.5 text-[#FF385C]" aria-hidden="true" />
            <span>Phân hệ theo vai trò</span>
          </div>
          <p className="mt-0.5 text-[11px] text-[#717171] leading-normal">
            Kiểm soát truy cập Zero Trust & RBAC
          </p>
        </div>

        <nav className="flex-1 space-y-1 overflow-y-auto pr-1" aria-label="Danh sách phân hệ">
          {NAV_ITEMS.map((item) => {
            const isActive = pathname?.startsWith(item.href);
            const hasAccess = user?.roles.includes(item.role);
            const Icon = item.icon;

            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => onClose?.()}
                className={`group flex items-start gap-2.5 rounded-xl p-2.5 text-xs transition-all ${
                  isActive
                    ? 'border border-[#FF385C]/40 bg-[#FF385C]/10 text-[#FF385C] shadow-2xs'
                    : hasAccess
                      ? 'border border-transparent text-[#717171] hover:border-[#ebebeb] hover:bg-[#f7f7f7] hover:text-[#222222]'
                      : 'border border-transparent text-[#b0b0b0] hover:bg-[#f7f7f7]'
                }`}
                aria-current={isActive ? 'page' : undefined}
              >
                <Icon
                  className={`mt-0.5 shrink-0 ${
                    isActive
                      ? 'text-[#FF385C]'
                      : hasAccess
                        ? 'text-[#717171] group-hover:text-[#222222]'
                        : 'text-[#b0b0b0]'
                  }`}
                  size={16}
                  strokeWidth={1.75}
                  aria-hidden="true"
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold truncate">{item.title}</span>
                    {!hasAccess && (
                      <span className="flex items-center gap-0.5 text-[10px] text-[#b0b0b0]">
                        <Lock className="h-2.5 w-2.5" aria-hidden="true" />
                        <span>Chưa gán</span>
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 text-[11px] text-[#717171] line-clamp-1 leading-normal">
                    {item.description}
                  </p>
                </div>
              </Link>
            );
          })}
        </nav>

        {/* Bottom utility links */}
        <div className="mt-3 border-t border-[#ebebeb] pt-2.5 space-y-0.5">
          <Link
            href="/sessions"
            onClick={() => onClose?.()}
            className={`flex items-center justify-between rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
              pathname === '/sessions'
                ? 'bg-[#f7f7f7] text-[#222222] font-semibold'
                : 'text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222]'
            }`}
          >
            <div className="flex items-center gap-2">
              <Laptop className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Quản lý phiên & thiết bị</span>
            </div>
          </Link>

          <Link
            href="/"
            onClick={() => onClose?.()}
            className="flex items-center justify-between rounded-full px-3 py-1.5 text-xs font-medium text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors"
          >
            <div className="flex items-center gap-2">
              <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Cổng giới thiệu hệ thống</span>
            </div>
          </Link>
        </div>
      </aside>
    </>
  );
}

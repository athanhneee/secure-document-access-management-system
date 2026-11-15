'use client';

/**
 * Thuật toán: Danh Mục Phân Hệ Theo Vai Trò RBAC Dùng Chung Cho `<aside>` Desktop & `<dialog>` Mobile (`SidebarDirectory`)
 * Mục đích: Đánh dấu tuyến đường đang hoạt động (`aria-current="page"`), hiển thị trạng thái phân quyền vai trò (`Chưa gán`) và cung cấp nút đóng `44x44px` khi hiển thị trong ngăn kéo di động.
 */
import type React from 'react';
import Link from 'next/link';
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
  X,
} from 'lucide-react';
import type { RoleType } from '@/lib/auth-context';

interface NavItem {
  title: string;
  href: string;
  role: RoleType;
  icon: React.ElementType;
  description: string;
}

const NAV_ITEMS: readonly NavItem[] = [
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

export interface SidebarDirectoryProps {
  pathname: string | null;
  userRoles: readonly string[] | undefined;
  onNavigate?: (() => void) | undefined;
  headingId?: string | undefined;
  onCloseButton?: (() => void) | undefined;
}

export function SidebarDirectory({
  pathname,
  userRoles,
  onNavigate,
  headingId,
  onCloseButton,
}: SidebarDirectoryProps) {
  return (
    <>
      <div className="mb-2 flex items-center justify-between gap-2 px-2.5">
        <div
          id={headingId}
          className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-[#717171]"
        >
          <Shield size={16} strokeWidth={1.75} className="text-[#E31C5F]" aria-hidden="true" />
          <span>Phân hệ vai trò</span>
        </div>
        {onCloseButton && (
          <button
            type="button"
            data-drawer-close="true"
            onClick={onCloseButton}
            aria-label="Đóng bảng điều hướng"
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors cursor-pointer"
          >
            <X size={20} strokeWidth={2} aria-hidden="true" />
          </button>
        )}
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto" aria-label="Danh sách phân hệ">
        {NAV_ITEMS.map((item) => {
          const isActive = pathname?.startsWith(item.href);
          const hasAccess = userRoles?.includes(item.role);
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              onClick={() => onNavigate?.()}
              title={item.description}
              className={`group flex min-h-11 sm:min-h-9 items-center justify-between gap-2 rounded-full px-3 py-2 text-xs transition-colors ${
                isActive
                  ? 'border border-[#E31C5F]/35 bg-[#FF385C]/10 font-semibold text-[#E31C5F]'
                  : hasAccess
                    ? 'border border-transparent font-medium text-[#222222] hover:bg-[#f7f7f7]'
                    : 'border border-transparent font-medium text-[#717171] hover:bg-[#f7f7f7]'
              }`}
              aria-current={isActive ? 'page' : undefined}
            >
              <span className="flex min-w-0 items-center gap-2.5">
                <Icon
                  className={`shrink-0 ${
                    isActive
                      ? 'text-[#E31C5F]'
                      : hasAccess
                        ? 'text-[#717171] group-hover:text-[#222222]'
                        : 'text-[#b0b0b0]'
                  }`}
                  size={16}
                  strokeWidth={1.75}
                  aria-hidden="true"
                />
                <span className="truncate">{item.title}</span>
              </span>
              {!hasAccess && (
                <Lock
                  size={16}
                  strokeWidth={1.75}
                  className="shrink-0 text-[#b0b0b0]"
                  aria-label="Chưa gán vai trò"
                />
              )}
            </Link>
          );
        })}
      </nav>

      <div className="mt-3 border-t border-[#ebebeb] pt-2.5 space-y-1">
        <Link
          href="/sessions"
          onClick={() => onNavigate?.()}
          className={`flex min-h-11 sm:min-h-9 items-center gap-2.5 rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
            pathname === '/sessions'
              ? 'bg-[#f7f7f7] text-[#222222] font-semibold'
              : 'text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222]'
          }`}
        >
          <Laptop size={16} strokeWidth={1.75} aria-hidden="true" />
          <span className="truncate">Phiên &amp; thiết bị</span>
        </Link>

        <Link
          href="/"
          onClick={() => onNavigate?.()}
          className="flex min-h-11 sm:min-h-9 items-center gap-2.5 rounded-full px-3 py-1.5 text-xs font-medium text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors"
        >
          <ExternalLink size={16} strokeWidth={1.75} aria-hidden="true" />
          <span className="truncate">Trang giới thiệu</span>
        </Link>
      </div>
    </>
  );
}

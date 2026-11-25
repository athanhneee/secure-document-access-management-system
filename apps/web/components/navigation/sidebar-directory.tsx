'use client';

/**
 * Thuật toán: Lọc Tối Thiểu Đặc Quyền Danh Mục Phân Hệ RBAC Dùng Chung Desktop & Mobile (`SidebarDirectory`)
 * Mục đích:
 *   - Chỉ dựng các liên kết phân hệ vai trò mà tài khoản hiện tại thực sự được cấp quyền qua `canAccessPortal`.
 *   - Hiển thị thẻ tóm tắt tài khoản (họ tên, phòng ban, cấp thẩm quyền bảo mật, trạng thái MFA) để người dùng di động (`<1024px`) luôn tra cứu được danh tính và thẩm quyền của mình (`V-30`, `V-59`).
 *   - Cung cấp liên kết tới `Phiên & thiết bị` (`/sessions`, tích hợp quản lý MFA/Passkey) và `Trang giới thiệu` (`/`), gán `aria-current="page"` thống nhất (`V-65`) và thay icon `ExternalLink` sai ngữ nghĩa bằng `Home` (`V-63`).
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
  Home,
  User,
  X,
} from 'lucide-react';
import type { AuthUser, RoleType } from '@/lib/auth-context';
import { canAccessPortal } from '@/lib/role-permissions';
import { ClassificationBadge } from '@/components/classification-badge';

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
    description: 'Tài khoản, phòng ban, phân quyền và cấu hình watermark bảo mật',
  },
  {
    title: 'Chủ sở hữu tài liệu',
    href: '/owner',
    role: 'DOCUMENT_OWNER',
    icon: FolderLock,
    description: 'Tải lên, phân loại mật, phê duyệt yêu cầu và quản lý quyền truy cập',
  },
  {
    title: 'Người đọc tài liệu',
    href: '/reader',
    role: 'DOCUMENT_READER',
    icon: BookOpen,
    description: 'Tra cứu tài liệu, gửi yêu cầu quyền truy cập, xem trước và tải về',
  },
  {
    title: 'An ninh thông tin',
    href: '/security',
    role: 'SECURITY_OFFICER',
    icon: AlertOctagon,
    description: 'Cảnh báo an ninh, truy vết watermark bảo mật, hồ sơ sự cố và quy tắc phát hiện',
  },
  {
    title: 'Kiểm toán độc lập',
    href: '/auditor',
    role: 'AUDITOR',
    icon: FileCheck,
    description: 'Nhật ký kiểm toán, kiểm tra tính toàn vẹn và xuất báo cáo tuân thủ',
  },
];

export interface SidebarDirectoryProps {
  pathname: string | null;
  user?: AuthUser | null | undefined;
  userRoles?: readonly string[] | undefined;
  onNavigate?: (() => void) | undefined;
  headingId?: string | undefined;
  onCloseButton?: (() => void) | undefined;
}

export function SidebarDirectory({
  pathname,
  user,
  userRoles,
  onNavigate,
  headingId,
  onCloseButton,
}: SidebarDirectoryProps) {
  const authorizedItems = NAV_ITEMS.filter((item) =>
    user ? canAccessPortal(user, item.role) : Boolean(userRoles?.includes(item.role)),
  );
  const isSessionsActive = pathname === '/sessions';

  return (
    <>
      <div className="mb-2 flex items-center justify-between gap-2 px-2.5">
        <div
          id={headingId}
          className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-[#717171]"
        >
          <Shield size={16} strokeWidth={1.75} className="text-[#E31C5F]" aria-hidden="true" />
          <span>Phân hệ được cấp</span>
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

      {user && (
        <div className="mb-3 rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5 text-xs">
          <div className="flex items-center gap-2 min-w-0">
            <User
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#008489]"
              aria-hidden="true"
            />
            <div className="min-w-0">
              <div className="font-semibold text-[#222222] truncate">
                {user.fullName || user.username}
              </div>
              {user.departmentName && (
                <div className="text-xs text-[#717171] truncate">{user.departmentName}</div>
              )}
            </div>
          </div>
          {user.clearanceCode && (
            <div className="pt-1 border-t border-[#ebebeb] flex items-center justify-between gap-2">
              <span className="text-[#717171]">Thẩm quyền</span>
              <ClassificationBadge
                code={user.clearanceCode}
                rank={user.clearanceRank}
                subject="user"
                size="sm"
              />
            </div>
          )}
        </div>
      )}

      {authorizedItems.length > 0 && (
        <nav className="flex-1 space-y-1 overflow-y-auto" aria-label="Danh sách phân hệ">
          {authorizedItems.map((item) => {
            const isActive = pathname?.startsWith(item.href);
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
                    : 'border border-transparent font-medium text-[#222222] hover:bg-[#f7f7f7]'
                }`}
                aria-current={isActive ? 'page' : undefined}
              >
                <span className="flex min-w-0 items-center gap-2.5">
                  <Icon
                    className={`shrink-0 ${
                      isActive ? 'text-[#E31C5F]' : 'text-[#717171] group-hover:text-[#222222]'
                    }`}
                    size={16}
                    strokeWidth={1.75}
                    aria-hidden="true"
                  />
                  <span className="truncate">{item.title}</span>
                </span>
              </Link>
            );
          })}
        </nav>
      )}

      <div className="mt-auto border-t border-[#ebebeb] pt-2.5 space-y-1">
        <Link
          href="/sessions"
          onClick={() => onNavigate?.()}
          aria-current={isSessionsActive ? 'page' : undefined}
          className={`flex min-h-11 sm:min-h-9 items-center gap-2.5 rounded-full px-3 py-1.5 text-xs transition-colors ${
            isSessionsActive
              ? 'border border-[#E31C5F]/35 bg-[#FF385C]/10 font-semibold text-[#E31C5F]'
              : 'border border-transparent font-medium text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222]'
          }`}
        >
          <Laptop size={16} strokeWidth={1.75} aria-hidden="true" />
          <span className="truncate">Phiên &amp; thiết bị</span>
        </Link>

        <Link
          href="/"
          onClick={() => onNavigate?.()}
          className="flex min-h-11 sm:min-h-9 items-center gap-2.5 rounded-full border border-transparent px-3 py-1.5 text-xs font-medium text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors"
        >
          <Home size={16} strokeWidth={1.75} aria-hidden="true" />
          <span className="truncate">Trang giới thiệu</span>
        </Link>
      </div>
    </>
  );
}

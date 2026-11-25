'use client';

/**
 * Thuật toán: Điều Hướng Phản Ứng Ngữ Cảnh Phiên Trên Trang 404 (`NotFoundActions`, V-49)
 * Mục đích: Đưa người dùng đã đăng nhập quay thẳng về phân hệ làm việc được cấp thay vì hiển thị nút "Đăng nhập hệ thống" thừa.
 */
import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';
import { resolveDefaultPortalForRoles, useAuth } from '@/lib/auth-context';

export function NotFoundActions() {
  const { isAuthenticated, user } = useAuth();
  const workspaceHref = isAuthenticated && user ? resolveDefaultPortalForRoles(user) : null;

  return (
    <div className="flex flex-col sm:flex-row items-center justify-center gap-2.5 pt-1">
      {workspaceHref && workspaceHref !== '/' ? (
        <>
          <Link
            href={workspaceHref}
            className="inline-flex min-h-11 w-full sm:w-auto items-center justify-center gap-1.5 rounded-full bg-[#FF385C] px-5 py-2 text-xs font-semibold text-[#ffffff] hover:bg-[#E31C5F] transition-colors shadow-2xs"
          >
            <ArrowLeft size={16} strokeWidth={2} aria-hidden="true" />
            <span>Về phân hệ làm việc</span>
          </Link>
          <Link
            href="/"
            className="inline-flex min-h-11 w-full sm:w-auto items-center justify-center rounded-full border border-[#dddddd] bg-[#ffffff] px-5 py-2 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] transition-colors"
          >
            Về trang chủ
          </Link>
        </>
      ) : (
        <>
          <Link
            href="/"
            className="inline-flex min-h-11 w-full sm:w-auto items-center justify-center gap-1.5 rounded-full bg-[#FF385C] px-5 py-2 text-xs font-semibold text-[#ffffff] hover:bg-[#E31C5F] transition-colors shadow-2xs"
          >
            <ArrowLeft size={16} strokeWidth={2} aria-hidden="true" />
            <span>Về trang chủ</span>
          </Link>
          {!isAuthenticated && (
            <Link
              href="/login"
              className="inline-flex min-h-11 w-full sm:w-auto items-center justify-center rounded-full border border-[#dddddd] bg-[#ffffff] px-5 py-2 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] transition-colors"
            >
              Đăng nhập hệ thống
            </Link>
          )}
        </>
      )}
    </div>
  );
}

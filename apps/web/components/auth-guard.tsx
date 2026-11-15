'use client';

import React, { useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { useAuth, type RoleType, ROLE_LABELS } from '@/lib/auth-context';
import { ArrowLeft, RefreshCw, Lock } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';

interface AuthGuardProps {
  children: React.ReactNode;
  requiredRole?: RoleType;
  requiredPermission?: string;
}

/**
 * Thuật toán: Cổng Kiểm Soát Truy Cập Tuyến Đường Theo Máy Trạng Thái RBAC (Client-Side Route Guard State Machine)
 * Mục đích: Chặn hiển thị trái phép các phân hệ nghiệp vụ khi phiên chưa xác thực hoặc tài khoản thiếu vai trò/quyền tối thiểu (Least Privilege).
 * Cơ chế hoạt động:
 *   - Pha 1 (`isLoading`): Dựng khung chờ xác thực phiên bất đồng bộ.
 *   - Pha 2 (`!isAuthenticated`): Tự động chuyển hướng sang `/login` kèm tham số `redirect` mã hóa URI của đường dẫn hiện tại.
 *   - Pha 3 (`Authorization Check`): Kiểm tra hội logic `isRoleAllowed && isPermissionAllowed`; nếu vi phạm thì chặn nội dung con và hiển thị cảnh báo kiểm toán HTTP 403.
 */
export function AuthGuard({ children, requiredRole, requiredPermission }: AuthGuardProps) {
  const { user, isLoading, isAuthenticated, hasRole, hasPermission, refreshUser } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      const redirectUrl = pathname ? `/login?redirect=${encodeURIComponent(pathname)}` : '/login';
      router.push(redirectUrl);
    }
  }, [isLoading, isAuthenticated, router, pathname]);

  if (isLoading) {
    // CONFLICT-RESOLVED: Loại bỏ hộp tròn nền/viền bao quanh icon RefreshCw theo quy tắc Icon System (rules/ui-design-system.md).
    return (
      <output
        className="flex min-h-[60vh] flex-col items-center justify-center space-y-4"
        aria-label="Đang kiểm tra quyền truy cập"
      >
        <RefreshCw
          size={24}
          strokeWidth={1.75}
          className="animate-spin text-[#FF385C]"
          aria-hidden="true"
        />
        <p className="text-sm font-medium text-[#717171]">Đang xác thực phiên làm việc…</p>
      </output>
    );
  }

  if (!isAuthenticated || !user) {
    return null; // Will redirect via useEffect
  }

  // Check required role
  const isRoleAllowed = requiredRole ? hasRole(requiredRole) : true;
  // Check required permission
  const isPermissionAllowed = requiredPermission ? hasPermission(requiredPermission) : true;

  if (!isRoleAllowed || !isPermissionAllowed) {
    return (
      <div className="mx-auto flex min-h-[65vh] max-w-lg flex-col items-center justify-center p-4">
        <Card className="w-full rounded-[24px] border border-[#C13515]/25 bg-[#ffffff] text-[#222222] shadow-[0_8px_30px_rgba(0,0,0,0.06)]">
          <CardHeader className="text-center pb-2">
            <div className="mx-auto mb-2 flex items-center justify-center text-[#C13515]">
              <Lock size={24} strokeWidth={1.75} aria-hidden="true" />
            </div>
            <CardTitle className="text-xl font-bold tracking-tight text-[#C13515]">
              403 · Truy cập bị từ chối
            </CardTitle>
            <CardDescription className="text-[#717171] text-xs mt-0.5">
              Tài khoản hiện tại không có thẩm quyền truy cập phân hệ này
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 pt-3 text-center">
            <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 text-left space-y-1.5 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[#717171]">Tài khoản</span>
                <span className="font-semibold text-[#222222]">{user.username}</span>
              </div>
              {requiredRole && (
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[#717171]">Vai trò yêu cầu</span>
                  <span className="font-semibold text-[#C13515]">{ROLE_LABELS[requiredRole]}</span>
                </div>
              )}
              {requiredPermission && (
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[#717171]">Quyền yêu cầu</span>
                  <span className="font-semibold text-[#C13515]">{requiredPermission}</span>
                </div>
              )}
              <div className="flex flex-wrap items-center justify-between gap-2 pt-1.5 border-t border-[#ebebeb]">
                <span className="text-[#717171]">Vai trò hiện có</span>
                <span className="text-[#222222]">
                  {user.roles.length > 0 ? user.roles.join(', ') : 'Chưa gán'}
                </span>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-2.5 pt-1">
              <InteractiveHoverButton
                variant="secondary"
                size="sm"
                text="Về trang chủ"
                icon={<ArrowLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={() => router.push('/')}
                className="w-full sm:w-auto"
              />
              <InteractiveHoverButton
                variant="primary"
                size="sm"
                text="Kiểm tra lại quyền"
                icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={() => void refreshUser()}
                className="w-full sm:w-auto"
              />
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return <>{children}</>;
}

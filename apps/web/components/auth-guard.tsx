'use client';

import React, { useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import {
  useAuth,
  type RoleType,
  ROLE_LABELS,
  resolveDefaultPortalForRoles,
} from '@/lib/auth-context';
import { ArrowLeft, RefreshCw, Lock } from 'lucide-react';
import { AppLayout } from '@/components/navigation/app-layout';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';

interface AuthGuardProps {
  children: React.ReactNode;
  requiredRole?: RoleType;
  requiredPermission?: string;
}

/**
 * Thuật toán: Cổng Kiểm Soát Truy Cập Tuyến Đường Theo Máy Trạng Thái RBAC Bảo Toàn Phiên (`AuthGuard`)
 * Mục đích:
 *   - Chặn thực thi và dựng giao diện trái phép (bao gồm các hook gọi API con) khi tài khoản chưa xác thực hoặc thiếu vai trò/quyền tối thiểu (Least Privilege).
 *   - Khi gặp `403` (truy cập trực tiếp URL chéo vai trò), giữ nguyên khung điều hướng `AppLayout` và phiên đăng nhập hiện tại, đồng thời điều hướng người dùng quay về đúng phân hệ được cấp (`resolveDefaultPortalForRoles`) thay vì đẩy ra màn hình đăng xuất.
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
    return null;
  }

  const isRoleAllowed = requiredRole ? hasRole(requiredRole) : true;
  const isPermissionAllowed = requiredPermission ? hasPermission(requiredPermission) : true;

  if (!isRoleAllowed || !isPermissionAllowed) {
    const fallbackWorkspace = resolveDefaultPortalForRoles(user.roles);
    const fallbackLabel = fallbackWorkspace === '/' ? 'Về trang chủ' : 'Về phân hệ làm việc';

    return (
      <AppLayout>
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
                Tài khoản hiện tại không có thẩm quyền truy cập phân hệ này. Phiên làm việc của bạn
                vẫn được giữ nguyên.
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
                    <span className="font-semibold text-[#C13515]">
                      {ROLE_LABELS[requiredRole]}
                    </span>
                  </div>
                )}
                {requiredPermission && (
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-[#717171]">Quyền yêu cầu</span>
                    <span className="font-semibold text-[#C13515]">{requiredPermission}</span>
                  </div>
                )}
                <div className="flex flex-wrap items-center justify-between gap-2 pt-1.5 border-t border-[#ebebeb]">
                  <span className="text-[#717171]">Vai trò được cấp</span>
                  <span className="text-[#222222]">
                    {user.roles.length > 0
                      ? user.roles.map((r) => ROLE_LABELS[r as RoleType] ?? r).join(', ')
                      : 'Chưa gán'}
                  </span>
                </div>
              </div>

              <div className="flex flex-col sm:flex-row items-center justify-center gap-2.5 pt-1">
                <InteractiveHoverButton
                  variant="primary"
                  size="sm"
                  text={fallbackLabel}
                  icon={<ArrowLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
                  onClick={() => router.push(fallbackWorkspace)}
                  className="w-full sm:w-auto"
                />
                <InteractiveHoverButton
                  variant="secondary"
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
      </AppLayout>
    );
  }

  return <>{children}</>;
}

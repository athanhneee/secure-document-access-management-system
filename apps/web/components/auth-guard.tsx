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
    return (
      <output
        className="flex min-h-[60vh] flex-col items-center justify-center space-y-4"
        aria-label="Đang kiểm tra quyền truy cập"
      >
        <div className="relative flex h-12 w-12 items-center justify-center">
          <div className="absolute h-12 w-12 animate-ping rounded-full border-2 border-[#FF385C]/30" />
          <RefreshCw className="h-6 w-6 animate-spin text-[#FF385C]" aria-hidden="true" />
        </div>
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
      <div className="mx-auto flex min-h-[70vh] max-w-2xl flex-col items-center justify-center p-6">
        <Card className="w-full rounded-[28px] border border-[#C13515]/20 bg-[#ffffff] text-[#222222] shadow-[0_12px_40px_rgba(0,0,0,0.08)]">
          <CardHeader className="text-center pb-2">
            <div className="mx-auto mb-3 flex items-center justify-center text-[#C13515]">
              <Lock size={24} strokeWidth={1.75} aria-hidden="true" />
            </div>
            <CardTitle className="text-2xl font-bold tracking-tight text-[#C13515]">
              403 · Truy cập bị từ chối
            </CardTitle>
            <CardDescription className="text-[#717171] text-sm mt-1">
              Quyền tối thiểu · Không đủ thẩm quyền truy cập không gian này
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6 pt-4 text-center">
            <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-4 text-left space-y-2 text-sm">
              <div className="flex items-center justify-between text-[#222222]">
                <span className="text-[#717171]">Tài khoản:</span>
                <span className="font-bold text-[#222222]">
                  {user.username} ({user.fullName})
                </span>
              </div>
              {requiredRole && (
                <div className="flex items-center justify-between text-[#222222]">
                  <span className="text-[#717171]">Vai trò yêu cầu:</span>
                  <span className="font-semibold text-[#E07912]">
                    {ROLE_LABELS[requiredRole]} ({requiredRole})
                  </span>
                </div>
              )}
              {requiredPermission && (
                <div className="flex items-center justify-between text-[#222222]">
                  <span className="text-[#717171]">Thẩm quyền yêu cầu:</span>
                  <span className="font-bold text-xs text-[#E07912]">{requiredPermission}</span>
                </div>
              )}
              <div className="flex items-center justify-between text-[#222222] pt-1 border-t border-[#ebebeb]">
                <span className="text-[#717171]">Vai trò hiện có:</span>
                <span className="text-xs text-[#222222]">
                  {user.roles.length > 0 ? user.roles.join(', ') : 'Chưa gán vai trò'}
                </span>
              </div>
            </div>

            <p className="text-xs text-[#717171] leading-relaxed">
              Mọi nỗ lực truy cập vượt thẩm quyền đều được ghi lại vào nhật ký kiểm toán hệ thống
              (Audit Trail) và chuỗi băm HMAC-SHA256 nhằm phục vụ quy trách nhiệm.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
              <InteractiveHoverButton
                variant="secondary"
                text="Về trang chủ"
                icon={<ArrowLeft size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={() => router.push('/')}
                className="w-full sm:w-auto"
              />
              <InteractiveHoverButton
                variant="primary"
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

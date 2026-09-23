'use client';

import React, { useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { useAuth, type RoleType, ROLE_LABELS } from '@/lib/auth-context';
import { ArrowLeft, RefreshCw, Lock } from 'lucide-react';
import { Button } from '@/components/ui/button';
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
          <div className="absolute h-12 w-12 animate-ping rounded-full border-2 border-emerald-500/30" />
          <RefreshCw className="h-6 w-6 animate-spin text-emerald-500" aria-hidden="true" />
        </div>
        <p className="text-sm font-medium text-slate-400">Đang xác thực phiên làm việc…</p>
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
        <Card className="w-full border-red-900/40 bg-slate-900/90 text-slate-100 shadow-2xl backdrop-blur-md">
          <CardHeader className="text-center pb-2">
            <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-red-950/80 border border-red-500/30 text-red-400">
              <Lock className="h-8 w-8" aria-hidden="true" />
            </div>
            <CardTitle className="text-2xl font-bold tracking-tight text-red-200">
              403 · Truy cập bị từ chối
            </CardTitle>
            <CardDescription className="text-slate-400 text-sm mt-1">
              Quyền tối thiểu · Không đủ thẩm quyền truy cập không gian này
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6 pt-4 text-center">
            <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 text-left space-y-2 text-sm">
              <div className="flex items-center justify-between text-slate-300">
                <span className="text-slate-400">Tài khoản:</span>
                <span className="font-mono font-medium text-slate-200">
                  {user.username} ({user.fullName})
                </span>
              </div>
              {requiredRole && (
                <div className="flex items-center justify-between text-slate-300">
                  <span className="text-slate-400">Vai trò yêu cầu:</span>
                  <span className="font-semibold text-amber-400">
                    {ROLE_LABELS[requiredRole]} ({requiredRole})
                  </span>
                </div>
              )}
              {requiredPermission && (
                <div className="flex items-center justify-between text-slate-300">
                  <span className="text-slate-400">Thẩm quyền yêu cầu:</span>
                  <span className="font-mono text-xs text-amber-400">{requiredPermission}</span>
                </div>
              )}
              <div className="flex items-center justify-between text-slate-300 pt-1 border-t border-slate-800">
                <span className="text-slate-400">Vai trò hiện có:</span>
                <span className="text-xs text-slate-300">
                  {user.roles.length > 0 ? user.roles.join(', ') : 'Chưa gán vai trò'}
                </span>
              </div>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Mọi nỗ lực truy cập vượt thẩm quyền đều được ghi lại vào nhật ký kiểm toán hệ thống
              (Audit Trail) và chuỗi băm HMAC-SHA256 nhằm phục vụ quy trách nhiệm.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
              <Button
                variant="outline"
                className="w-full sm:w-auto border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-200"
                onClick={() => router.push('/')}
              >
                <ArrowLeft className="mr-2 h-4 w-4" aria-hidden="true" />
                Về trang chủ
              </Button>
              <Button
                variant="default"
                className="w-full sm:w-auto bg-emerald-600 hover:bg-emerald-500 text-white"
                onClick={() => void refreshUser()}
              >
                <RefreshCw className="mr-2 h-4 w-4" aria-hidden="true" />
                Kiểm tra lại quyền
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return <>{children}</>;
}

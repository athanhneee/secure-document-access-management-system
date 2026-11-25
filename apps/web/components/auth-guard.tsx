'use client';

import React, { useEffect, useState } from 'react';
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
  requiredPortal?: RoleType;
  requiredRole?: RoleType;
  requiredPermission?: string;
}

/**
 * Thuật toán: Cổng Kiểm Soát Truy Cập Tuyến Đường Theo Quyền Thực Tế Bảo Toàn Phiên & Không Lộ Vai Trò Đặc Quyền (`AuthGuard`)
 * Mục đích:
 *   - Chặn thực thi và dựng giao diện trái phép (bao gồm các hook gọi API con) khi tài khoản chưa xác thực hoặc thiếu quyền.
 *   - Chuyển hướng chưa đăng nhập bằng `router.replace` tránh vòng lặp nút Quay lại (`V-47`).
 *   - Trên màn hình 403 không làm lộ tên vai trò/quyền đặc quyền yêu cầu (`V-20`), đồng thời phản hồi rõ ràng khi bấm `Kiểm tra lại quyền` (`V-47`).
 */
export function AuthGuard({
  children,
  requiredPortal,
  requiredRole,
  requiredPermission,
}: AuthGuardProps) {
  const { user, isLoading, isAuthenticated, hasRole, hasPermission, canAccessPortal, refreshUser } =
    useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const [isRechecking, setIsRechecking] = useState(false);
  const [recheckFeedback, setRecheckFeedback] = useState<string | null>(null);

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      const redirectUrl = pathname ? `/login?redirect=${encodeURIComponent(pathname)}` : '/login';
      router.replace(redirectUrl);
    }
  }, [isLoading, isAuthenticated, router, pathname]);

  async function handleRecheckAccess() {
    setIsRechecking(true);
    setRecheckFeedback(null);
    try {
      const refreshed = await refreshUser();
      if (!refreshed) {
        setRecheckFeedback('Không thể cập nhật thông tin quyền lúc này. Vui lòng thử lại.');
        return;
      }
      setRecheckFeedback(
        'Đã kiểm tra lại: tài khoản hiện vẫn chưa được cấp thẩm quyền truy cập trang này.',
      );
    } finally {
      setIsRechecking(false);
    }
  }

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

  const isPortalAllowed = requiredPortal ? canAccessPortal(requiredPortal) : true;
  const isRoleAllowed = requiredRole ? hasRole(requiredRole) : true;
  const isPermissionAllowed = requiredPermission ? hasPermission(requiredPermission) : true;

  if (!isPortalAllowed || !isRoleAllowed || !isPermissionAllowed) {
    const fallbackWorkspace = resolveDefaultPortalForRoles(user);
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
                Không có quyền truy cập
              </CardTitle>
              <CardDescription className="text-[#717171] text-xs mt-0.5">
                Tài khoản hiện tại không có thẩm quyền truy cập khu vực này. Phiên làm việc của bạn
                vẫn được giữ nguyên.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 pt-3 text-center">
              <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 text-left space-y-1.5 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[#717171]">Tài khoản</span>
                  <span className="font-semibold text-[#222222]">{user.username}</span>
                </div>
                <div className="flex flex-wrap items-center justify-between gap-2 pt-1.5 border-t border-[#ebebeb]">
                  <span className="text-[#717171]">Vai trò được cấp</span>
                  <span className="text-[#222222]">
                    {user.roles.length > 0
                      ? user.roles.map((r) => ROLE_LABELS[r as RoleType] ?? r).join(', ')
                      : 'Chưa gán'}
                  </span>
                </div>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[#717171]">Quyền hiệu lực</span>
                  <span className="text-[#222222]">
                    {user.permissions.length > 0
                      ? `${user.permissions.length} quyền`
                      : 'Chưa có quyền nào'}
                  </span>
                </div>
              </div>

              {recheckFeedback && (
                <output className="block rounded-[16px] border border-[#E07912]/30 bg-[#E07912]/10 px-3 py-2 text-xs text-[#222222]">
                  {recheckFeedback}
                </output>
              )}

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
                  isLoading={isRechecking}
                  disabled={isRechecking}
                  icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
                  onClick={handleRecheckAccess}
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

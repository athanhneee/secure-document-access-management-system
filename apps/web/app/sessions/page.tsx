'use client';

import { useState } from 'react';
import { Laptop, ShieldCheck, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { apiClient, ApiError } from '@/lib/api-client';
import { AppLayout } from '@/components/navigation/app-layout';
import { AuthGuard } from '@/components/auth-guard';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';

export default function SessionsPage() {
  const { user, logout } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  async function handleLogoutAll() {
    if (!confirm('Bạn có chắc chắn muốn đăng xuất khỏi tất cả các thiết bị khác không?')) {
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);

    try {
      await apiClient('/auth/logout-all', { method: 'POST' });
      setSuccessMessage('Đã hủy tất cả các phiên đăng nhập khác thành công.');
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Không thể đăng xuất tất cả phiên.');
      } else {
        setErrorMessage('Đã xảy ra lỗi khi hủy các phiên làm việc.');
      }
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <AuthGuard>
      <AppLayout>
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-[#222222]">
                Quản lý phiên làm việc & thiết bị
              </h1>
              <p className="text-xs text-[#717171] mt-1">
                Theo dõi các phiên đăng nhập đang hoạt động và thu hồi quyền truy cập khi có nghi
                ngờ rò rỉ
              </p>
            </div>

            <InteractiveHoverButton
              variant="destructive"
              onClick={() => void handleLogoutAll()}
              disabled={isLoading}
              isLoading={isLoading}
              text="Đăng xuất tất cả thiết bị khác"
              className="w-full sm:w-auto"
            />
          </div>

          {successMessage && (
            <Alert className="rounded-[20px] border border-[#008A05]/30 bg-[#008A05]/10 text-[#008A05] text-xs">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-[#008A05]" aria-hidden="true" />
              <AlertDescription className="ml-2">{successMessage}</AlertDescription>
            </Alert>
          )}

          {errorMessage && (
            <Alert
              variant="destructive"
              className="rounded-[20px] border border-[#C13515]/30 bg-[#C13515]/10 text-[#C13515] text-xs"
            >
              <AlertTriangle className="h-4 w-4 shrink-0 text-[#C13515]" aria-hidden="true" />
              <AlertDescription className="ml-2">{errorMessage}</AlertDescription>
            </Alert>
          )}

          <div className="grid gap-5 md:grid-cols-2">
            {/* Current session */}
            <Card className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <Laptop
                      size={20}
                      strokeWidth={1.75}
                      className="text-[#008A05] shrink-0"
                      aria-hidden="true"
                    />
                    <div>
                      <CardTitle className="text-sm font-bold text-[#222222]">
                        Phiên hiện tại (Thiết bị này)
                      </CardTitle>
                      <CardDescription className="text-xs text-[#008A05] font-medium">
                        Đang hoạt động · Được cấp quyền
                      </CardDescription>
                    </div>
                  </div>
                  <Badge variant="success">Active</Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-3 text-xs text-[#222222]">
                <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-4 space-y-2.5">
                  <div className="flex justify-between items-center">
                    <span className="text-[#717171]">Người dùng:</span>
                    <span className="font-semibold text-[#222222]">
                      {user?.fullName} ({user?.username})
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[#717171]">Bảo mật Cookie:</span>
                    <span className="font-bold text-[#008A05] text-[11px]">
                      HttpOnly · SameSite=Strict
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[#717171]">Phòng chống CSRF:</span>
                    <span className="font-bold text-[#008A05] text-[11px]">
                      Double-Submit Cookie (sda_csrf)
                    </span>
                  </div>
                </div>
              </CardContent>
              <CardFooter className="pt-2 border-t border-[#ebebeb] flex justify-end">
                <InteractiveHoverButton
                  variant="destructive"
                  onClick={() => void logout()}
                  text="Đăng xuất phiên này"
                  className="w-full sm:w-auto text-xs"
                />
              </CardFooter>
            </Card>

            {/* Security Policies for Sessions */}
            <Card className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2.5">
                  <ShieldCheck
                    size={20}
                    strokeWidth={1.75}
                    className="text-[#008A05] shrink-0"
                    aria-hidden="true"
                  />
                  <div>
                    <CardTitle className="text-sm font-bold text-[#222222]">
                      Chính sách an toàn phiên
                    </CardTitle>
                    <CardDescription className="text-xs text-[#717171]">
                      Tuân thủ tiêu chuẩn an toàn thông tin
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-3 text-xs text-[#717171] leading-relaxed">
                <div className="space-y-2.5">
                  <div className="flex items-start gap-2">
                    <span className="dot dot-success mt-1.5 shrink-0" aria-hidden="true" />
                    <p className="text-[#717171]">
                      <strong className="text-[#222222]">Hết hạn tự động:</strong> Phiên làm việc tự
                      động hết hạn sau khoảng thời gian không hoạt động.
                    </p>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="dot dot-success mt-1.5 shrink-0" aria-hidden="true" />
                    <p className="text-[#717171]">
                      <strong className="text-[#222222]">Thu hồi tức thì:</strong> Khi một giấy phép
                      truy cập (Access Grant) bị thu hồi, mọi phiên đọc/xem tài liệu liên quan đều
                      bị ngắt kết nối lập tức.
                    </p>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="dot dot-success mt-1.5 shrink-0" aria-hidden="true" />
                    <p className="text-[#717171]">
                      <strong className="text-[#222222]">Chống phát lại:</strong> Refresh token sử
                      dụng cơ chế xoay vòng (Rotation) với kiểm tra tái sử dụng nhằm phát hiện sớm
                      hành vi chiếm quyền điều khiển phiên.
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </AppLayout>
    </AuthGuard>
  );
}

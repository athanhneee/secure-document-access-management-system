'use client';

import { useState } from 'react';
import { Laptop, ShieldCheck, LogOut, AlertTriangle, RefreshCw, CheckCircle2 } from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { apiClient, ApiError } from '@/lib/api-client';
import { AppLayout } from '@/components/navigation/app-layout';
import { AuthGuard } from '@/components/auth-guard';
import { Button } from '@/components/ui/button';
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
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">
                Quản lý phiên làm việc & thiết bị
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                Theo dõi các phiên đăng nhập đang hoạt động và thu hồi quyền truy cập khi có nghi
                ngờ rò rỉ
              </p>
            </div>

            <Button
              variant="outline"
              onClick={() => void handleLogoutAll()}
              disabled={isLoading}
              className="border-red-900/50 bg-red-950/20 text-red-300 hover:bg-red-950/40 hover:text-red-200"
            >
              {isLoading ? (
                <RefreshCw className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
              ) : (
                <AlertTriangle className="mr-2 h-4 w-4 text-red-400" aria-hidden="true" />
              )}
              Đăng xuất tất cả thiết bị khác
            </Button>
          </div>

          {successMessage && (
            <Alert className="border-emerald-900/60 bg-emerald-950/40 text-emerald-300 text-xs">
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
              <AlertDescription className="ml-2">{successMessage}</AlertDescription>
            </Alert>
          )}

          {errorMessage && (
            <Alert
              variant="destructive"
              className="border-red-900/60 bg-red-950/40 text-red-300 text-xs"
            >
              <AlertTriangle className="h-4 w-4 shrink-0 text-red-400" aria-hidden="true" />
              <AlertDescription className="ml-2">{errorMessage}</AlertDescription>
            </Alert>
          )}

          <div className="grid gap-4 md:grid-cols-2">
            {/* Current session */}
            <Card className="border-emerald-800/40 bg-slate-900/90 shadow-xl">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-950 border border-emerald-500/30 text-emerald-400">
                      <Laptop className="h-5 w-5" aria-hidden="true" />
                    </div>
                    <div>
                      <CardTitle className="text-sm font-semibold text-slate-100">
                        Phiên hiện tại (Thiết bị này)
                      </CardTitle>
                      <CardDescription className="text-xs text-emerald-400">
                        Đang hoạt động · Được cấp quyền
                      </CardDescription>
                    </div>
                  </div>
                  <span className="rounded-full bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-0.5 text-[11px] font-medium text-emerald-400">
                    Active
                  </span>
                </div>
              </CardHeader>
              <CardContent className="space-y-3 text-xs text-slate-300">
                <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3 space-y-2">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Người dùng:</span>
                    <span className="font-medium text-slate-200">
                      {user?.fullName} ({user?.username})
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Bảo mật Cookie:</span>
                    <span className="font-mono text-emerald-400">HttpOnly · SameSite=Strict</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Phòng chống CSRF:</span>
                    <span className="font-mono text-emerald-400">
                      Double-Submit Cookie (sda_csrf)
                    </span>
                  </div>
                </div>
              </CardContent>
              <CardFooter className="pt-2 border-t border-slate-800 flex justify-end">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => void logout()}
                  className="border-slate-800 hover:bg-slate-800 text-slate-300"
                >
                  <LogOut className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                  Đăng xuất phiên này
                </Button>
              </CardFooter>
            </Card>

            {/* Security Policies for Sessions */}
            <Card className="border-slate-800 bg-slate-900/90 shadow-xl">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-800 border border-slate-700 text-slate-300">
                    <ShieldCheck className="h-5 w-5 text-emerald-400" aria-hidden="true" />
                  </div>
                  <div>
                    <CardTitle className="text-sm font-semibold text-slate-100">
                      Chính sách an toàn phiên
                    </CardTitle>
                    <CardDescription className="text-xs text-slate-400">
                      Tuân thủ tiêu chuẩn an toàn thông tin
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-3 text-xs text-slate-400 leading-relaxed">
                <div className="space-y-2">
                  <div className="flex items-start gap-2">
                    <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                    <p>
                      <strong>Hết hạn tự động:</strong> Phiên làm việc tự động hết hạn sau khoảng
                      thời gian không hoạt động.
                    </p>
                  </div>
                  <div className="flex items-start gap-2">
                    <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                    <p>
                      <strong>Thu hồi tức thì:</strong> Khi một giấy phép truy cập (Access Grant) bị
                      thu hồi, mọi phiên đọc/xem tài liệu liên quan đều bị ngắt kết nối lập tức.
                    </p>
                  </div>
                  <div className="flex items-start gap-2">
                    <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                    <p>
                      <strong>Chống phát lại:</strong> Refresh token sử dụng cơ chế xoay vòng
                      (Rotation) với kiểm tra tái sử dụng nhằm phát hiện sớm hành vi chiếm quyền
                      điều khiển phiên.
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

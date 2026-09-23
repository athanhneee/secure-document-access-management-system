'use client';

import { useState, Suspense, type FormEvent } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  KeyRound,
  Lock,
  Mail,
  ArrowLeft,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';

function ResetPasswordContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get('token');

  const [identifier, setIdentifier] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Forgot password request
  async function handleForgot(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    if (!identifier.trim()) {
      setErrorMessage('Vui lòng nhập tên đăng nhập hoặc email.');
      return;
    }

    setIsLoading(true);
    try {
      await apiClient<{ message: string }>('/auth/forgot-password', {
        method: 'POST',
        body: JSON.stringify({ identifier: identifier.trim() }),
      });
      setSuccessMessage(
        'Nếu tài khoản tồn tại trong hệ thống, hướng dẫn đặt lại mật khẩu đã được gửi đến email đăng ký của bạn.',
      );
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Yêu cầu không thành công.');
      } else {
        setErrorMessage('Không thể gửi yêu cầu đặt lại mật khẩu.');
      }
    } finally {
      setIsLoading(false);
    }
  }

  // Confirm reset password
  async function handleReset(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    if (!newPassword || newPassword.length < 15) {
      setErrorMessage(
        'Mật khẩu mới bắt buộc phải có độ dài từ 15 ký tự trở lên theo tiêu chuẩn bảo mật.',
      );
      return;
    }

    if (newPassword !== confirmPassword) {
      setErrorMessage('Mật khẩu xác nhận không khớp với mật khẩu mới.');
      return;
    }

    setIsLoading(true);
    try {
      await apiClient('/auth/reset-password', {
        method: 'POST',
        body: JSON.stringify({ token, newPassword }),
      });
      setSuccessMessage(
        'Mật khẩu đã được cập nhật thành công! Đang chuyển hướng về trang đăng nhập…',
      );
      setTimeout(() => {
        router.push('/login');
      }, 2500);
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message || 'Token đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.');
      } else {
        setErrorMessage('Không thể đặt lại mật khẩu. Vui lòng thử lại.');
      }
    } finally {
      setIsLoading(false);
    }
  }

  // Password strength check
  const hasMinLength = newPassword.length >= 15;
  const hasUpper = /[A-Z]/.test(newPassword);
  const hasLower = /[a-z]/.test(newPassword);
  const hasNumber = /[0-9]/.test(newPassword);
  const hasSpecial = /[^A-Za-z0-9]/.test(newPassword);
  const strengthScore = [hasMinLength, hasUpper, hasLower, hasNumber, hasSpecial].filter(
    Boolean,
  ).length;

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-slate-950 px-4 py-12 antialiased selection:bg-emerald-500/20 selection:text-emerald-300">
      <div className="w-full max-w-md space-y-6">
        <div className="flex flex-col items-center text-center space-y-2">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-900 border border-slate-700 text-slate-300 shadow-xl">
            <KeyRound className="h-7 w-7 text-emerald-400" aria-hidden="true" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            {token ? 'Đặt lại mật khẩu mới' : 'Khôi phục mật khẩu tài khoản'}
          </h1>
          <p className="text-xs text-slate-400 max-w-xs">
            {token
              ? 'Thiết lập mật khẩu an toàn theo tiêu chuẩn bảo vệ tài liệu mật'
              : 'Gửi yêu cầu qua kênh nội bộ bảo mật'}
          </p>
        </div>

        <Card className="border-slate-800 bg-slate-900/90 shadow-2xl backdrop-blur-xl">
          <CardHeader className="space-y-1 pb-4">
            <CardTitle className="text-base font-semibold text-slate-100">
              {token ? 'Thông tin mật khẩu mới' : 'Xác minh danh tính người dùng'}
            </CardTitle>
            <CardDescription className="text-xs text-slate-400">
              {token
                ? 'Mật khẩu phải đáp ứng độ dài tối thiểu 15 ký tự và bao gồm các lớp ký tự'
                : 'Nhập tên đăng nhập hoặc email để nhận mã liên kết khôi phục'}
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            {errorMessage && (
              <Alert
                variant="destructive"
                className="border-red-900/60 bg-red-950/40 text-red-300 text-xs"
              >
                <AlertCircle className="h-4 w-4 shrink-0 text-red-400" aria-hidden="true" />
                <AlertDescription className="ml-2 leading-relaxed">{errorMessage}</AlertDescription>
              </Alert>
            )}

            {successMessage && (
              <Alert className="border-emerald-900/60 bg-emerald-950/40 text-emerald-300 text-xs">
                <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
                <AlertDescription className="ml-2 leading-relaxed">
                  {successMessage}
                </AlertDescription>
              </Alert>
            )}

            {!token ? (
              // Step 1: Request reset link
              <form onSubmit={handleForgot} className="space-y-4">
                <div className="space-y-1.5">
                  <label htmlFor="identifier" className="block text-xs font-medium text-slate-300">
                    Tên đăng nhập hoặc Email
                  </label>
                  <div className="relative">
                    <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
                      <Mail className="h-4 w-4" aria-hidden="true" />
                    </div>
                    <Input
                      id="identifier"
                      name="identifier"
                      type="text"
                      disabled={isLoading || Boolean(successMessage)}
                      value={identifier}
                      onChange={(e) => setIdentifier(e.target.value)}
                      placeholder="nguyenvana hoặc email nội bộ"
                      className="pl-9 bg-slate-950/80 border-slate-800 text-slate-100 placeholder:text-slate-600 focus:border-emerald-500 focus:ring-emerald-500/20"
                    />
                  </div>
                </div>

                <Button
                  type="submit"
                  disabled={isLoading || Boolean(successMessage)}
                  className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2 rounded-lg transition-all shadow-lg shadow-emerald-950/40"
                >
                  {isLoading ? (
                    <>
                      <RefreshCw className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                      Đang gửi yêu cầu…
                    </>
                  ) : (
                    'Gửi liên kết khôi phục'
                  )}
                </Button>
              </form>
            ) : (
              // Step 2: Set new password
              <form onSubmit={handleReset} className="space-y-4">
                <div className="space-y-1.5">
                  <label
                    htmlFor="new-password"
                    className="block text-xs font-medium text-slate-300"
                  >
                    Mật khẩu mới (Tối thiểu 15 ký tự)
                  </label>
                  <div className="relative">
                    <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
                      <Lock className="h-4 w-4" aria-hidden="true" />
                    </div>
                    <Input
                      id="new-password"
                      name="newPassword"
                      type="password"
                      disabled={isLoading || Boolean(successMessage)}
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      placeholder="•••••••••••••••"
                      className="pl-9 bg-slate-950/80 border-slate-800 text-slate-100 placeholder:text-slate-600 focus:border-emerald-500 focus:ring-emerald-500/20"
                    />
                  </div>

                  {/* Password strength meter */}
                  {newPassword && (
                    <div className="space-y-1 pt-1">
                      <div className="flex h-1.5 w-full gap-1 overflow-hidden rounded-full bg-slate-800">
                        <div
                          className={`h-full transition-all ${
                            strengthScore <= 2
                              ? 'w-1/3 bg-red-500'
                              : strengthScore <= 4
                                ? 'w-2/3 bg-amber-500'
                                : 'w-full bg-emerald-500'
                          }`}
                        />
                      </div>
                      <p className="text-[10px] text-slate-400">
                        Độ mạnh:{' '}
                        {strengthScore <= 2
                          ? 'Yếu'
                          : strengthScore <= 4
                            ? 'Khá'
                            : 'Rất mạnh (Khuyến nghị)'}
                      </p>
                    </div>
                  )}
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor="confirm-password"
                    className="block text-xs font-medium text-slate-300"
                  >
                    Xác nhận mật khẩu mới
                  </label>
                  <div className="relative">
                    <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
                      <ShieldCheck className="h-4 w-4" aria-hidden="true" />
                    </div>
                    <Input
                      id="confirm-password"
                      name="confirmPassword"
                      type="password"
                      disabled={isLoading || Boolean(successMessage)}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="•••••••••••••••"
                      className="pl-9 bg-slate-950/80 border-slate-800 text-slate-100 placeholder:text-slate-600 focus:border-emerald-500 focus:ring-emerald-500/20"
                    />
                  </div>
                </div>

                <Button
                  type="submit"
                  disabled={isLoading || Boolean(successMessage)}
                  className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2 rounded-lg transition-all shadow-lg shadow-emerald-950/40"
                >
                  {isLoading ? (
                    <>
                      <RefreshCw className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                      Đang cập nhật mật khẩu…
                    </>
                  ) : (
                    'Cập nhật mật khẩu mới'
                  )}
                </Button>
              </form>
            )}
          </CardContent>

          <CardFooter className="pt-2 border-t border-slate-800/80 flex justify-center">
            <Link
              href="/login"
              className="text-xs text-slate-400 hover:text-slate-200 transition-colors flex items-center justify-center gap-1.5"
            >
              <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Quay về trang đăng nhập</span>
            </Link>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-slate-950 text-slate-400 text-xs">
          Đang tải trang đặt lại mật khẩu…
        </div>
      }
    >
      <ResetPasswordContent />
    </Suspense>
  );
}

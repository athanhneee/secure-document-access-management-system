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
  ShieldCheck,
} from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
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
    <div className="relative flex min-h-screen flex-col items-center justify-center bg-[#f7f7f7] px-4 py-12 antialiased selection:bg-[#FF385C]/15 selection:text-[#FF385C] overflow-hidden">
      {/* Ambient background aura */}
      <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden" aria-hidden="true">
        <div className="absolute -top-32 left-1/2 -translate-x-1/2 w-[600px] h-[400px] rounded-full bg-[#FF385C]/5 blur-3xl animate-float" />
        <div className="absolute -bottom-32 left-1/3 w-[500px] h-[400px] rounded-full bg-[#008489]/5 blur-3xl animate-float delay-200" />
      </div>

      <div className="relative z-10 w-full max-w-md space-y-6">
        <div className="flex flex-col items-center text-center space-y-2 animate-fade-in-down">
          <KeyRound size={24} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
          <h1 className="text-2xl font-bold tracking-tight text-[#222222]">
            {token ? 'Đặt lại mật khẩu mới' : 'Khôi phục mật khẩu tài khoản'}
          </h1>
          <p className="text-xs text-[#717171] max-w-xs leading-relaxed">
            {token
              ? 'Thiết lập mật khẩu an toàn theo tiêu chuẩn bảo vệ tài liệu mật'
              : 'Gửi yêu cầu qua kênh nội bộ bảo mật'}
          </p>
        </div>

        <Card className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] shadow-[0_12px_40px_rgba(0,0,0,0.06)] animate-fade-in-up delay-100">
          <CardHeader className="space-y-1 pb-4">
            <CardTitle className="text-base font-bold text-[#222222]">
              {token ? 'Thông tin mật khẩu mới' : 'Xác minh danh tính người dùng'}
            </CardTitle>
            <CardDescription className="text-xs text-[#717171]">
              {token
                ? 'Mật khẩu phải đáp ứng độ dài tối thiểu 15 ký tự và bao gồm các lớp ký tự'
                : 'Nhập tên đăng nhập hoặc email để nhận mã liên kết khôi phục'}
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            {errorMessage && (
              <Alert
                variant="destructive"
                className="rounded-[20px] border border-[#C13515]/30 bg-[#C13515]/10 text-[#C13515] text-xs"
              >
                <AlertCircle className="h-4 w-4 shrink-0 text-[#C13515]" aria-hidden="true" />
                <AlertDescription className="ml-2 leading-relaxed">{errorMessage}</AlertDescription>
              </Alert>
            )}

            {successMessage && (
              <Alert className="rounded-[20px] border border-[#008A05]/30 bg-[#008A05]/10 text-[#008A05] text-xs">
                <CheckCircle2 className="h-4 w-4 shrink-0 text-[#008A05]" aria-hidden="true" />
                <AlertDescription className="ml-2 leading-relaxed">
                  {successMessage}
                </AlertDescription>
              </Alert>
            )}

            {!token ? (
              // Step 1: Request reset link
              <form onSubmit={handleForgot} className="space-y-4">
                <div className="space-y-1.5">
                  <label
                    htmlFor="identifier"
                    className="block text-xs font-semibold text-[#222222]"
                  >
                    Tên đăng nhập hoặc Email
                  </label>
                  <div className="relative">
                    <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-[#717171]">
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
                      className="pl-10 bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
                    />
                  </div>
                </div>

                <InteractiveHoverButton
                  type="submit"
                  disabled={isLoading || Boolean(successMessage)}
                  isLoading={isLoading}
                  text="Gửi liên kết khôi phục"
                  className="w-full py-2.5 text-xs font-semibold"
                />
              </form>
            ) : (
              // Step 2: Set new password
              <form onSubmit={handleReset} className="space-y-4">
                <div className="space-y-1.5">
                  <label
                    htmlFor="new-password"
                    className="block text-xs font-semibold text-[#222222]"
                  >
                    Mật khẩu mới (Tối thiểu 15 ký tự)
                  </label>
                  <div className="relative">
                    <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-[#717171]">
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
                      className="pl-10 bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
                    />
                  </div>

                  {/* Password strength meter */}
                  {newPassword && (
                    <div className="space-y-1 pt-1">
                      <div className="flex h-1.5 w-full gap-1 overflow-hidden rounded-full bg-[#ebebeb]">
                        <div
                          className={`h-full transition-all ${
                            strengthScore <= 2
                              ? 'w-1/3 bg-[#C13515]'
                              : strengthScore <= 4
                                ? 'w-2/3 bg-[#E07912]'
                                : 'w-full bg-[#008A05]'
                          }`}
                        />
                      </div>
                      <p className="text-[10px] text-[#717171]">
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
                    className="block text-xs font-semibold text-[#222222]"
                  >
                    Xác nhận mật khẩu mới
                  </label>
                  <div className="relative">
                    <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-[#717171]">
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
                      className="pl-10 bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
                    />
                  </div>
                </div>

                <InteractiveHoverButton
                  type="submit"
                  disabled={isLoading || Boolean(successMessage)}
                  isLoading={isLoading}
                  text="Cập nhật mật khẩu mới"
                  className="w-full py-2.5 text-xs font-semibold"
                />
              </form>
            )}
          </CardContent>

          <CardFooter className="pt-2 border-t border-[#ebebeb] flex justify-center">
            <Link
              href="/login"
              className="text-xs text-[#717171] hover:text-[#222222] transition-colors flex items-center justify-center gap-1.5"
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
        <div className="flex min-h-screen items-center justify-center bg-[#f7f7f7] text-[#717171] text-xs">
          Đang tải trang đặt lại mật khẩu…
        </div>
      }
    >
      <ResetPasswordContent />
    </Suspense>
  );
}

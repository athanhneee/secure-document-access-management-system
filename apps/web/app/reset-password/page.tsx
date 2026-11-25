'use client';

/**
 * Thuật toán: Quy Trình Khôi Phục Mật Khẩu Hai Pha, Đồng Bộ Luật Mật Khẩu NIST & Khử Độc Token Trên URL (`ResetPasswordPage`, `ResetPasswordContent`)
 * Mục đích:
 *   - Chụp giữ mã khôi phục dùng một lần vào bộ nhớ trạng thái React rồi xóa sạch `?token=` trên thanh địa chỉ.
 *   - Đồng bộ mô tả chính sách mật khẩu khớp 1-1 với máy chủ (15–128 ký tự, `V-29`), không khóa vĩnh viễn biểu mẫu quên mật khẩu sau 1 lần gửi, dọn timer chuyển hướng khi unmount (`V-49`), chuẩn hóa chiều cao liên kết `44px` (`V-61`) và bỏ nền trang trí `blur-3xl` (`V-66`).
 */
import { useState, useEffect, useRef, Suspense, type FormEvent } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { KeyRound, ArrowLeft, CheckCircle2, AlertCircle } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { ForgotPasswordStepForm, ConfirmResetStepForm } from './reset-steps';

function ResetPasswordContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const queryToken = searchParams.get('token');
  const [initialToken] = useState<string | null>(() => queryToken);
  const token = queryToken ?? initialToken;
  const redirectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (queryToken && typeof window !== 'undefined' && window.location.search.includes('token=')) {
      window.history.replaceState(null, '', window.location.pathname);
    }
  }, [queryToken]);

  useEffect(() => {
    return () => {
      if (redirectTimerRef.current) {
        clearTimeout(redirectTimerRef.current);
      }
    };
  }, []);

  const [identifier, setIdentifier] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

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
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Yêu cầu không thành công.'
          : 'Không thể gửi yêu cầu đặt lại mật khẩu.',
      );
    } finally {
      setIsLoading(false);
    }
  }

  async function handleReset(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);
    if (!newPassword || newPassword.length < 15 || newPassword.length > 128) {
      setErrorMessage(
        'Mật khẩu mới bắt buộc phải có độ dài từ 15 đến 128 ký tự theo tiêu chuẩn bảo mật.',
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
      redirectTimerRef.current = setTimeout(() => router.replace('/login'), 2500);
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Liên kết đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.'
          : 'Không thể đặt lại mật khẩu. Vui lòng thử lại.',
      );
    } finally {
      setIsLoading(false);
    }
  }

  const resetFormDisabled = isLoading || Boolean(token && successMessage);

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-[#f7f7f7] px-4 py-12 antialiased selection:bg-[#FF385C]/15 selection:text-[#E31C5F]">
      <div className="w-full max-w-md space-y-6">
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
                ? 'Bắt buộc dài từ 15 đến 128 ký tự và không chứa tên đăng nhập hoặc email (khuyến nghị kết hợp chữ hoa, chữ thường, chữ số và ký tự đặc biệt).'
                : 'Nhập tên đăng nhập hoặc email để nhận liên kết khôi phục.'}
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            {errorMessage && (
              <Alert
                variant="destructive"
                className="rounded-[20px] border border-[#C13515]/30 bg-[#C13515]/10 text-[#C13515] text-xs"
              >
                <AlertCircle
                  size={16}
                  strokeWidth={1.75}
                  className="shrink-0 text-[#C13515]"
                  aria-hidden="true"
                />
                <AlertDescription className="ml-2 leading-relaxed">{errorMessage}</AlertDescription>
              </Alert>
            )}

            {successMessage && (
              <Alert variant="success" className="rounded-[20px] text-xs">
                <CheckCircle2
                  size={16}
                  strokeWidth={1.75}
                  className="shrink-0 text-[#008A05]"
                  aria-hidden="true"
                />
                <AlertDescription className="ml-2 leading-relaxed">
                  {successMessage}
                </AlertDescription>
              </Alert>
            )}

            {!token ? (
              <ForgotPasswordStepForm
                identifier={identifier}
                isLoading={isLoading}
                disabled={isLoading}
                onChangeIdentifier={setIdentifier}
                onSubmit={handleForgot}
              />
            ) : (
              <ConfirmResetStepForm
                newPassword={newPassword}
                confirmPassword={confirmPassword}
                isLoading={isLoading}
                disabled={resetFormDisabled}
                onChangeNewPassword={setNewPassword}
                onChangeConfirmPassword={setConfirmPassword}
                onSubmit={handleReset}
              />
            )}
          </CardContent>

          <CardFooter className="pt-2 border-t border-[#ebebeb] flex justify-center">
            <Link
              href="/login"
              className="min-h-11 sm:min-h-9 rounded-full px-3 py-1.5 text-xs text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors flex items-center justify-center gap-1.5"
            >
              <ArrowLeft size={16} strokeWidth={1.75} aria-hidden="true" />
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

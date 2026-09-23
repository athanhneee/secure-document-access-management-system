'use client';

import { useState, Suspense, type FormEvent } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldAlert, Key, RefreshCw, ArrowLeft, CheckCircle2, AlertCircle } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
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

function MfaContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectTarget = searchParams.get('redirect') ?? '/';
  const { refreshUser } = useAuth();

  const [isRecoveryMode, setIsRecoveryMode] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  async function handleVerify(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setErrorMessage(null);

    if (!isRecoveryMode && (!totpCode || totpCode.trim().length !== 6)) {
      setErrorMessage('Vui lòng nhập chính xác mã TOTP gồm 6 chữ số.');
      return;
    }

    if (isRecoveryMode && (!recoveryCode || recoveryCode.trim().length < 16)) {
      setErrorMessage('Mã khôi phục phải có độ dài ít nhất 16 ký tự.');
      return;
    }

    setIsLoading(true);

    try {
      const payload = isRecoveryMode
        ? { recoveryCode: recoveryCode.trim() }
        : { code: totpCode.trim() };

      await apiClient<{ authenticated: true }>('/auth/mfa/verify', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      // Verification successful, refresh user
      const user = await refreshUser();
      if (user && user.roles.length > 0) {
        if (redirectTarget && redirectTarget !== '/') {
          router.push(redirectTarget);
        } else {
          if (user.roles.includes('SYSTEM_ADMIN')) router.push('/admin');
          else if (user.roles.includes('DOCUMENT_OWNER')) router.push('/owner');
          else if (user.roles.includes('SECURITY_OFFICER')) router.push('/security');
          else if (user.roles.includes('AUDITOR')) router.push('/auditor');
          else router.push('/reader');
        }
      } else {
        router.push(redirectTarget);
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(
          err.message ||
            (isRecoveryMode
              ? 'Mã khôi phục không hợp lệ hoặc đã qua sử dụng.'
              : 'Mã TOTP không chính xác hoặc đã hết hạn.'),
        );
      } else {
        setErrorMessage('Không thể xác thực mã hai lớp. Vui lòng thử lại.');
      }
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-slate-950 px-4 py-12 antialiased selection:bg-emerald-500/20 selection:text-emerald-300">
      <div className="w-full max-w-md space-y-6">
        <div className="flex flex-col items-center text-center space-y-2">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-amber-950/80 border border-amber-500/40 text-amber-400 shadow-xl shadow-amber-950/30">
            <ShieldAlert className="h-7 w-7" aria-hidden="true" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Xác thực đa yếu tố (MFA)
          </h1>
          <p className="text-xs text-slate-400 max-w-xs">
            Bảo vệ cấp độ cao bắt buộc đối với truy cập tài liệu mật tổ chức
          </p>
        </div>

        <Card className="border-slate-800 bg-slate-900/90 shadow-2xl backdrop-blur-xl">
          <CardHeader className="space-y-1 pb-4">
            <CardTitle className="text-base font-semibold text-slate-100">
              {isRecoveryMode ? 'Sử dụng mã khôi phục khẩn cấp' : 'Nhập mã từ ứng dụng xác thực'}
            </CardTitle>
            <CardDescription className="text-xs text-slate-400">
              {isRecoveryMode
                ? 'Nhập 1 trong các mã phục hồi đã được cung cấp khi thiết lập tài khoản'
                : 'Mở ứng dụng Google Authenticator hoặc Microsoft Authenticator để lấy mã'}
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

            <form onSubmit={handleVerify} className="space-y-4">
              {!isRecoveryMode ? (
                <div className="space-y-2">
                  <label htmlFor="totp-code" className="block text-xs font-medium text-slate-300">
                    Mã xác thực 6 chữ số (TOTP)
                  </label>
                  <Input
                    id="totp-code"
                    name="code"
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={6}
                    autoComplete="one-time-code"
                    disabled={isLoading}
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="123456"
                    className="text-center font-mono text-xl tracking-[0.4em] bg-slate-950/80 border-slate-800 text-emerald-400 placeholder:text-slate-700 focus:border-emerald-500 focus:ring-emerald-500/20"
                    aria-label="Mã xác thực 6 chữ số"
                  />
                  <p className="text-[11px] text-slate-400 text-center">
                    Mã TOTP làm mới mỗi 30 giây theo thuật toán RFC 6238
                  </p>
                </div>
              ) : (
                <div className="space-y-2">
                  <label
                    htmlFor="recovery-code"
                    className="block text-xs font-medium text-slate-300"
                  >
                    Mã khôi phục khẩn cấp (Recovery Code)
                  </label>
                  <Input
                    id="recovery-code"
                    name="recoveryCode"
                    type="text"
                    autoComplete="off"
                    disabled={isLoading}
                    value={recoveryCode}
                    onChange={(e) => setRecoveryCode(e.target.value.toUpperCase())}
                    placeholder="ABCD-EFGH-IJKL-MNOP"
                    className="text-center font-mono text-sm tracking-wider bg-slate-950/80 border-slate-800 text-amber-300 placeholder:text-slate-700 focus:border-amber-500 focus:ring-amber-500/20"
                    aria-label="Mã khôi phục khẩn cấp"
                  />
                  <p className="text-[11px] text-amber-400/80 text-center">
                    Lưu ý: Mỗi mã khôi phục chỉ sử dụng được duy nhất một lần
                  </p>
                </div>
              )}

              <Button
                type="submit"
                disabled={isLoading}
                className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2 rounded-lg transition-all shadow-lg shadow-emerald-950/40"
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                    Đang kiểm tra mã…
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="mr-2 h-4 w-4" aria-hidden="true" />
                    Xác nhận mã bảo mật
                  </>
                )}
              </Button>
            </form>
          </CardContent>

          <CardFooter className="flex flex-col space-y-3 pt-2 border-t border-slate-800/80">
            <button
              type="button"
              disabled={isLoading}
              onClick={() => {
                setIsRecoveryMode(!isRecoveryMode);
                setErrorMessage(null);
              }}
              className="text-xs text-emerald-400 hover:text-emerald-300 transition-colors flex items-center justify-center gap-1.5"
            >
              <Key className="h-3.5 w-3.5" aria-hidden="true" />
              <span>
                {isRecoveryMode
                  ? 'Quay lại nhập mã TOTP từ ứng dụng'
                  : 'Không có thiết bị xác thực? Dùng mã khôi phục'}
              </span>
            </button>

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

export default function MfaPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-slate-950 text-slate-400 text-xs">
          Đang tải trang xác thực…
        </div>
      }
    >
      <MfaContent />
    </Suspense>
  );
}

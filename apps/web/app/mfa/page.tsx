'use client';

import { useState, Suspense, type FormEvent } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldAlert, Key, ArrowLeft, AlertCircle, Fingerprint } from 'lucide-react';
import {
  browserSupportsWebAuthn,
  startAuthentication,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';
import { apiClient, ApiError } from '@/lib/api-client';
import { useAuth, type AuthUser } from '@/lib/auth-context';
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

function MfaContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectTarget = searchParams.get('redirect') ?? '/';
  const { refreshUser } = useAuth();

  const [isRecoveryMode, setIsRecoveryMode] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isWebAuthnLoading, setIsWebAuthnLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  function handlePostAuthRedirect(user: AuthUser | null) {
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
  }

  async function handleWebAuthnVerify() {
    setErrorMessage(null);

    if (!browserSupportsWebAuthn()) {
      setErrorMessage('Trình duyệt hiện tại chưa hỗ trợ xác thực khóa FIDO2 / WebAuthn.');
      return;
    }

    setIsWebAuthnLoading(true);

    try {
      // 1. Fetch challenge and authentication options from server
      const { options, challengeToken } = await apiClient<{
        options: PublicKeyCredentialRequestOptionsJSON;
        challengeToken: string;
      }>('/auth/mfa/webauthn/auth/options', {
        method: 'POST',
        body: JSON.stringify({}),
      });

      // 2. Trigger browser native security key / passkey prompt (YubiKey USB / Touch ID / Face ID)
      const authResponse = await startAuthentication({ optionsJSON: options });

      // 3. Verify assertion with server
      await apiClient<{ authenticated: true }>('/auth/mfa/webauthn/auth/verify', {
        method: 'POST',
        body: JSON.stringify({
          response: authResponse,
          challengeToken,
        }),
      });

      // 4. Verification successful, refresh auth context and redirect
      const user = await refreshUser();
      handlePostAuthRedirect(user);
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'NotAllowedError') {
        setErrorMessage('Yêu cầu xác thực khóa phần cứng đã bị hủy hoặc quá thời gian.');
      } else if (err instanceof ApiError) {
        setErrorMessage(
          err.message ||
            'Không tìm thấy khóa bảo mật FIDO2 khớp với tài khoản, hoặc xác thực thất bại.',
        );
      } else if (err instanceof Error) {
        setErrorMessage(
          err.message || 'Không thể xác thực qua FIDO2/Passkey. Vui lòng thử lại hoặc dùng TOTP.',
        );
      } else {
        setErrorMessage('Không thể xác thực qua FIDO2/Passkey. Vui lòng thử lại hoặc dùng TOTP.');
      }
    } finally {
      setIsWebAuthnLoading(false);
    }
  }

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
      handlePostAuthRedirect(user);
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
    <div className="relative flex min-h-screen flex-col items-center justify-center bg-[#f7f7f7] px-4 py-12 antialiased selection:bg-[#FF385C]/15 selection:text-[#FF385C] overflow-hidden">
      {/* Ambient background aura */}
      <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden" aria-hidden="true">
        <div className="absolute -top-32 left-1/2 -translate-x-1/2 w-[600px] h-[400px] rounded-full bg-[#E07912]/5 blur-3xl animate-float" />
        <div className="absolute -bottom-32 left-1/3 w-[500px] h-[400px] rounded-full bg-[#FF385C]/5 blur-3xl animate-float delay-200" />
      </div>

      <div className="relative z-10 w-full max-w-md space-y-6">
        <div className="flex flex-col items-center text-center space-y-2 animate-fade-in-down">
          <ShieldAlert size={24} strokeWidth={1.75} className="text-[#E07912]" aria-hidden="true" />
          <h1 className="text-2xl font-bold tracking-tight text-[#222222]">
            Xác thực đa yếu tố (MFA)
          </h1>
          <p className="text-xs text-[#717171] max-w-xs leading-relaxed">
            Bảo vệ cấp độ cao bắt buộc đối với truy cập tài liệu mật tổ chức
          </p>
        </div>

        <Card className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] shadow-[0_12px_40px_rgba(0,0,0,0.06)] animate-fade-in-up delay-100">
          <CardHeader className="space-y-1 pb-4">
            <CardTitle className="text-base font-bold text-[#222222]">
              {isRecoveryMode
                ? 'Sử dụng mã khôi phục khẩn cấp'
                : 'Xác nhận danh tính với FIDO2 hoặc TOTP'}
            </CardTitle>
            <CardDescription className="text-xs text-[#717171]">
              {isRecoveryMode
                ? 'Nhập 1 trong các mã phục hồi đã được cung cấp khi thiết lập tài khoản'
                : 'Sử dụng khóa bảo mật vật lý (YubiKey), sinh trắc học hoặc ứng dụng Authenticator'}
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-5">
            {errorMessage && (
              <Alert
                variant="destructive"
                className="rounded-[20px] border border-[#C13515]/30 bg-[#C13515]/10 text-[#C13515] text-xs"
              >
                <AlertCircle className="h-4 w-4 shrink-0 text-[#C13515]" aria-hidden="true" />
                <AlertDescription className="ml-2 leading-relaxed">{errorMessage}</AlertDescription>
              </Alert>
            )}

            {/* FIDO2 / WebAuthn Hardware Key Authentication Button */}
            {!isRecoveryMode && (
              <div className="space-y-3">
                <button
                  type="button"
                  onClick={handleWebAuthnVerify}
                  disabled={isLoading || isWebAuthnLoading}
                  className="w-full py-3 px-4 rounded-full border border-[#222222] bg-[#222222] text-[#ffffff] hover:bg-[#333333] transition-all flex items-center justify-center gap-2.5 text-xs font-semibold shadow-xs disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
                >
                  {isWebAuthnLoading ? (
                    <>
                      <div className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                      <span>Đang chạm khóa bảo mật FIDO2…</span>
                    </>
                  ) : (
                    <>
                      <Fingerprint size={16} strokeWidth={2} className="text-[#ffffff]" />
                      <span>Xác thực bằng Khóa FIDO2 / Passkey (YubiKey)</span>
                    </>
                  )}
                </button>

                <div className="relative flex py-1 items-center">
                  <div className="grow border-t border-[#ebebeb]"></div>
                  <span className="shrink mx-3 text-[11px] font-semibold text-[#717171] uppercase tracking-wider">
                    Hoặc nhập mã ứng dụng
                  </span>
                  <div className="grow border-t border-[#ebebeb]"></div>
                </div>
              </div>
            )}

            <form onSubmit={handleVerify} className="space-y-4">
              {!isRecoveryMode ? (
                <div className="space-y-2">
                  <label htmlFor="totp-code" className="block text-xs font-semibold text-[#222222]">
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
                    disabled={isLoading || isWebAuthnLoading}
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="123456"
                    className="text-center font-bold text-xl tracking-[0.4em] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
                    aria-label="Mã xác thực 6 chữ số"
                  />
                  <p className="text-[11px] text-[#717171] text-center">
                    Mã TOTP làm mới mỗi 30 giây từ Google/Microsoft Authenticator
                  </p>
                </div>
              ) : (
                <div className="space-y-2">
                  <label
                    htmlFor="recovery-code"
                    className="block text-xs font-semibold text-[#222222]"
                  >
                    Mã khôi phục khẩn cấp (Recovery Code)
                  </label>
                  <Input
                    id="recovery-code"
                    name="recoveryCode"
                    type="text"
                    autoComplete="off"
                    disabled={isLoading || isWebAuthnLoading}
                    value={recoveryCode}
                    onChange={(e) => setRecoveryCode(e.target.value.toUpperCase())}
                    placeholder="ABCD-EFGH-IJKL-MNOP"
                    className="text-center font-bold text-sm tracking-wider bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
                    aria-label="Mã khôi phục khẩn cấp"
                  />
                  <p className="text-[11px] text-[#E07912] text-center">
                    Lưu ý: Mỗi mã khôi phục chỉ sử dụng được duy nhất một lần
                  </p>
                </div>
              )}

              <InteractiveHoverButton
                type="submit"
                disabled={isLoading || isWebAuthnLoading}
                isLoading={isLoading}
                text="Xác nhận mã bảo mật"
                className="w-full py-2.5 text-xs font-semibold"
              />
            </form>
          </CardContent>

          <CardFooter className="flex flex-col space-y-3 pt-2 border-t border-[#ebebeb]">
            <button
              type="button"
              disabled={isLoading || isWebAuthnLoading}
              onClick={() => {
                setIsRecoveryMode(!isRecoveryMode);
                setErrorMessage(null);
              }}
              className="text-xs text-[#FF385C] hover:underline transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
            >
              <Key size={14} strokeWidth={1.75} aria-hidden="true" />
              <span>
                {isRecoveryMode
                  ? 'Quay lại phương thức xác thực FIDO2 / TOTP'
                  : 'Không có thiết bị xác thực? Dùng mã khôi phục'}
              </span>
            </button>

            <Link
              href="/login"
              className="text-xs text-[#717171] hover:text-[#222222] transition-colors flex items-center justify-center gap-1.5"
            >
              <ArrowLeft size={14} strokeWidth={1.75} aria-hidden="true" />
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
        <div className="flex min-h-screen items-center justify-center bg-[#f7f7f7] text-[#717171] text-xs">
          Đang tải trang xác thực…
        </div>
      }
    >
      <MfaContent />
    </Suspense>
  );
}

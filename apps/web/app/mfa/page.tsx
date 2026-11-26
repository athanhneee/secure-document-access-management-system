'use client';

/**
 * Thuật toán: Máy Trạng Thái Xác Thực Đa Yếu Tố, Kiểm Tra Ngữ Cảnh Phiên & Chống Chuyển Hướng Chéo Vai Trò (`MfaPage`, `MfaContent`)
 * Mục đích:
 *   - Điều phối xác thực yếu tố thứ hai qua FIDO2 WebAuthn, TOTP 6 chữ số hoặc mã khôi phục dùng một lần, hỗ trợ `?method=totp` khi điều hướng từ `/reader` hoặc `/sessions` (`V-09`).
 *   - Loại bỏ nền trang trí `blur-3xl` lệch hệ thống thiết kế (`V-66`), ngăn gọi mù `/auth/mfa/enroll` khi chưa đăng nhập (`V-21`) và điều chỉnh liên kết quay lại theo ngữ cảnh phiên (`V-49`).
 */
import { useState, Suspense, type FormEvent } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldAlert, AlertCircle } from 'lucide-react';
import { apiClient, ApiError, getCsrfToken, sanitizeRedirectPath } from '@/lib/api-client';
import {
  resolveAuthorizedRedirectPath,
  resolveDefaultPortalForRoles,
  useAuth,
  type AuthUser,
} from '@/lib/auth-context';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { executeWebAuthnAssertion, formatWebAuthnError } from './webauthn-binary';
import { MfaEnrollmentCard } from './mfa-enrollment-card';
import { MfaMethodCards } from './mfa-method-cards';

/**
 * Algorithm / Thuật toán: Máy Trạng Thái Xác Thực Đa Yếu Tố (Multi-Factor Authentication State Machine — FIDO2 WebAuthn & RFC 6238 TOTP)
 */
function MfaContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectTarget = sanitizeRedirectPath(searchParams.get('redirect'));
  const rawEnrollParam = searchParams.get('enroll');
  const enrollParam = rawEnrollParam === '1';
  const mfaEnrollBlocked = rawEnrollParam === '0';
  const defaultEnrollMethod = searchParams.get('method') === 'totp' ? 'totp' : 'webauthn';
  const {
    user,
    isAuthenticated,
    mfaPending,
    isLoading: isAuthLoading,
    hydrateUser,
    refreshUser,
  } = useAuth();
  const canShowFirstTimeEnroll = !mfaEnrollBlocked && !user?.mfaEnabled;

  const [isEnrollMode, setIsEnrollMode] = useState(enrollParam && !mfaEnrollBlocked);
  const [isRecoveryMode, setIsRecoveryMode] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isWebAuthnLoading, setIsWebAuthnLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const hasSessionCookie = typeof document !== 'undefined' ? Boolean(getCsrfToken()) : true;
  const isUnauthenticatedVisitor =
    !isAuthLoading && !isAuthenticated && !mfaPending && !hasSessionCookie;
  const backHref = isAuthenticated && user ? resolveDefaultPortalForRoles(user) : '/login';
  const backLabel =
    isAuthenticated && user ? 'Quay về phân hệ làm việc' : 'Quay về trang đăng nhập';

  function handlePostAuthRedirect(resolvedUser: AuthUser | null) {
    router.push(resolveAuthorizedRedirectPath(redirectTarget, resolvedUser));
  }

  async function completeAuthWithProfile(inlineUser?: AuthUser | null) {
    if (inlineUser) {
      hydrateUser(inlineUser);
      handlePostAuthRedirect(inlineUser);
      return;
    }
    const resolved = await refreshUser();
    handlePostAuthRedirect(resolved);
  }

  async function handleWebAuthnVerify() {
    setErrorMessage(null);
    setIsWebAuthnLoading(true);
    try {
      const inlineUser = await executeWebAuthnAssertion();
      await completeAuthWithProfile(inlineUser);
    } catch (err: unknown) {
      setErrorMessage(formatWebAuthnError(err));
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

    const trimmedRecoveryCode = recoveryCode.trim();
    if (isRecoveryMode && (trimmedRecoveryCode.length < 16 || trimmedRecoveryCode.length > 64)) {
      setErrorMessage(
        'Mã khôi phục phải có độ dài từ 16 đến 64 ký tự và phân biệt chữ HOA/thường.',
      );
      return;
    }

    setIsLoading(true);
    try {
      const payload = isRecoveryMode
        ? { recoveryCode: trimmedRecoveryCode }
        : { code: totpCode.trim() };

      const res = await apiClient<{ authenticated: true; user?: AuthUser }>('/auth/mfa/verify', {
        method: 'POST',
        body: JSON.stringify(payload),
      });

      await completeAuthWithProfile(res?.user ?? null);
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
    <div className="flex min-h-screen flex-col items-center justify-center bg-[#f7f7f7] px-4 py-12 antialiased selection:bg-[#FF385C]/15 selection:text-[#E31C5F]">
      <div className="w-full max-w-md space-y-6">
        <div className="flex flex-col items-center text-center space-y-2 animate-fade-in-down">
          <ShieldAlert size={24} strokeWidth={1.75} className="text-[#E07912]" aria-hidden="true" />
          <h1 className="text-2xl font-bold tracking-tight text-[#222222]">
            Xác thực đa yếu tố (MFA)
          </h1>
          <p className="text-xs text-[#717171] max-w-xs leading-relaxed">
            Bảo vệ cấp độ cao bắt buộc đối với truy cập tài liệu mật tổ chức
          </p>
        </div>

        {isEnrollMode && isUnauthenticatedVisitor ? (
          <div className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] p-6 shadow-[0_12px_40px_rgba(0,0,0,0.06)] space-y-4">
            <Alert variant="destructive" className="text-xs">
              <AlertCircle size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
              <AlertDescription className="ml-2 leading-relaxed">
                Bạn cần đăng nhập bằng tài khoản trước khi thiết lập xác thực đa yếu tố (MFA).
              </AlertDescription>
            </Alert>
            <InteractiveHoverButton
              href="/login"
              variant="primary"
              text="Đi tới trang đăng nhập"
              className="w-full text-xs"
            />
          </div>
        ) : isEnrollMode ? (
          <MfaEnrollmentCard
            defaultMethod={defaultEnrollMethod}
            backHref={backHref}
            backLabel={backLabel}
            onComplete={async (enrolledUser) => {
              await completeAuthWithProfile(enrolledUser);
            }}
            onSwitchToVerify={() => {
              setIsEnrollMode(false);
              setErrorMessage(null);
            }}
          />
        ) : (
          <MfaMethodCards
            isRecoveryMode={isRecoveryMode}
            totpCode={totpCode}
            recoveryCode={recoveryCode}
            isLoading={isLoading}
            isWebAuthnLoading={isWebAuthnLoading}
            errorMessage={errorMessage}
            unauthenticatedNotice={isUnauthenticatedVisitor}
            showFirstTimeEnroll={canShowFirstTimeEnroll}
            backHref={backHref}
            backLabel={backLabel}
            onChangeTotpCode={setTotpCode}
            onChangeRecoveryCode={setRecoveryCode}
            onToggleRecoveryMode={() => {
              setIsRecoveryMode(!isRecoveryMode);
              setErrorMessage(null);
            }}
            onStartEnrollment={() => {
              setIsEnrollMode(true);
              setErrorMessage(null);
            }}
            onWebAuthnVerify={handleWebAuthnVerify}
            onSubmitVerify={handleVerify}
          />
        )}
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

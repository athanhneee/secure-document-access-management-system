'use client';

import { useState, Suspense, type FormEvent } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldAlert } from 'lucide-react';
import { apiClient, ApiError, sanitizeRedirectPath } from '@/lib/api-client';
import { useAuth, type AuthUser } from '@/lib/auth-context';
import { executeWebAuthnAssertion, formatWebAuthnError } from './webauthn-binary';
import { MfaMethodCards } from './mfa-method-cards';

/**
 * Algorithm / Thuật toán: Máy Trạng Thái Xác Thực Đa Yếu Tố (Multi-Factor Authentication State Machine — FIDO2 WebAuthn & RFC 6238 TOTP)
 * Mục đích: Xác minh yếu tố bảo mật thứ hai sau bước đăng nhập mật khẩu thông qua khóa phần cứng FIDO2/Passkey, mã TOTP 6 chữ số hoặc mã khôi phục dùng một lần.
 * Cơ chế hoạt động:
 *   - Phối hợp 3 phương thức xác thực độc lập, quản lý khóa trạng thái bất đồng bộ chống gửi trùng yêu cầu, và điều hướng an toàn theo phân cấp vai trò RBAC sau khi phiên được nâng cấp cờ `mfa`.
 */
function MfaContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectTarget = sanitizeRedirectPath(searchParams.get('redirect'));
  const { refreshUser } = useAuth();

  const [isRecoveryMode, setIsRecoveryMode] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isWebAuthnLoading, setIsWebAuthnLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  /**
   * Algorithm / Thuật toán: Định Tuyến Ưu Tiên Theo Phân Cấp Vai Trò RBAC (Priority-Ordered RBAC Post-Auth Routing)
   * Mục đích: Đưa người dùng đến đúng phân hệ nghiệp vụ sau khi hoàn tất xác thực MFA mà vẫn ngăn chặn lỗ hổng Open Redirect.
   */
  function handlePostAuthRedirect(user: AuthUser | null) {
    if (user && user.roles.length > 0) {
      if (redirectTarget && redirectTarget !== '/') {
        router.push(redirectTarget);
      } else if (user.roles.includes('SYSTEM_ADMIN')) router.push('/admin');
      else if (user.roles.includes('DOCUMENT_OWNER')) router.push('/owner');
      else if (user.roles.includes('SECURITY_OFFICER')) router.push('/security');
      else if (user.roles.includes('AUDITOR')) router.push('/auditor');
      else router.push('/reader');
    } else {
      router.push(redirectTarget);
    }
  }

  async function handleWebAuthnVerify() {
    setErrorMessage(null);
    setIsWebAuthnLoading(true);
    try {
      await executeWebAuthnAssertion();
      const user = await refreshUser();
      handlePostAuthRedirect(user);
    } catch (err: unknown) {
      setErrorMessage(formatWebAuthnError(err));
    } finally {
      setIsWebAuthnLoading(false);
    }
  }

  /**
   * Algorithm / Thuật toán: Kiểm Tra Định Dạng & Xác Minh Mã TOTP (RFC 6238) / Mã Khôi Phục Dùng Một Lần
   * Cơ chế: Chế độ thường yêu cầu đúng 6 chữ số TOTP; chế độ khẩn cấp yêu cầu chuỗi mã khôi phục tối thiểu 16 ký tự chỉ tiêu thụ một lần.
   */
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

        <MfaMethodCards
          isRecoveryMode={isRecoveryMode}
          totpCode={totpCode}
          recoveryCode={recoveryCode}
          isLoading={isLoading}
          isWebAuthnLoading={isWebAuthnLoading}
          errorMessage={errorMessage}
          onChangeTotpCode={setTotpCode}
          onChangeRecoveryCode={setRecoveryCode}
          onToggleRecoveryMode={() => {
            setIsRecoveryMode(!isRecoveryMode);
            setErrorMessage(null);
          }}
          onWebAuthnVerify={handleWebAuthnVerify}
          onSubmitVerify={handleVerify}
        />
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

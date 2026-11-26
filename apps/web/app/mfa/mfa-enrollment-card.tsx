'use client';

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
} from 'react';
import Link from 'next/link';
import {
  AlertCircle,
  ArrowLeft,
  CheckCircle2,
  Fingerprint,
  KeyRound,
  RefreshCw,
  Smartphone,
} from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import type { AuthUser } from '@/lib/auth-context';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { MfaEnrollForm, type MfaEnrollResponse } from './mfa-enroll-form';
import { MfaRecoveryCodesCard } from './mfa-recovery-codes-card';
import { MfaWebAuthnEnrollPanel } from './mfa-webauthn-enroll-panel';
import { executeWebAuthnRegistration, formatWebAuthnError } from './webauthn-binary';

type EnrollMethod = 'webauthn' | 'totp';

interface MfaEnrollmentCardProps {
  defaultMethod?: EnrollMethod;
  backHref?: string;
  backLabel?: string;
  onComplete: (enrolledUser?: AuthUser | null) => Promise<void>;
  onSwitchToVerify: () => void;
}

/**
 * Thuật toán: Máy Trạng Thái Đăng Ký Nhân Tố MFA Song Chế Độ Chuẩn WAI-ARIA Tabs & Xử Lý Lỗi 409 TOTP Đã Kích Hoạt (`MfaEnrollmentCard`)
 * Mục đích:
 *   - Hỗ trợ chọn trước `defaultMethod` (`totp` / `webauthn`, `V-09`), liên kết đầy đủ `aria-controls` / `role="tabpanel"` / `aria-labelledby` và phím `ArrowLeft` / `ArrowRight` (`V-65`).
 *   - Khi máy chủ trả `409 Conflict` vì TOTP đã kích hoạt, hiển thị thông báo rõ ràng kèm nút chuyển sang nhập mã xác thực thay vì nút thử lại vô nghĩa (`V-45`).
 */
export function MfaEnrollmentCard({
  defaultMethod = 'webauthn',
  backHref = '/login',
  backLabel = 'Quay về trang đăng nhập',
  onComplete,
  onSwitchToVerify,
}: MfaEnrollmentCardProps) {
  const tabBaseId = useId();
  const webauthnTabRef = useRef<HTMLButtonElement | null>(null);
  const totpTabRef = useRef<HTMLButtonElement | null>(null);
  const [enrollMethod, setEnrollMethod] = useState<EnrollMethod>(defaultMethod);
  const [enrollData, setEnrollData] = useState<MfaEnrollResponse | null>(null);
  const [totpAlreadyActive, setTotpAlreadyActive] = useState(false);
  const [isInitializing, setIsInitializing] = useState(false);
  const [verificationCode, setVerificationCode] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [deviceLabel, setDeviceLabel] = useState('');
  const [isRegisteringWebAuthn, setIsRegisteringWebAuthn] = useState(false);
  const [isRedirecting, setIsRedirecting] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [enrolledUser, setEnrolledUser] = useState<AuthUser | null>(null);
  const [copiedField, setCopiedField] = useState<'secret' | 'uri' | 'recovery' | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const startTotpEnrollment = useCallback(async () => {
    setIsInitializing(true);
    setErrorMessage(null);
    setTotpAlreadyActive(false);
    try {
      const res = await apiClient<MfaEnrollResponse>('/auth/mfa/enroll', {
        method: 'POST',
        body: JSON.stringify({ label: 'Authenticator' }),
      });
      setEnrollData(res);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setTotpAlreadyActive(true);
        setErrorMessage(null);
      } else {
        setErrorMessage(
          err instanceof ApiError
            ? err.message || 'Không thể khởi tạo khóa thiết lập MFA.'
            : 'Không thể kết nối đến máy chủ để thiết lập MFA.',
        );
      }
    } finally {
      setIsInitializing(false);
    }
  }, []);

  useEffect(() => {
    if (enrollMethod !== 'totp' || enrollData || totpAlreadyActive) return;
    let ignore = false;
    void Promise.resolve().then(() => {
      if (!ignore) void startTotpEnrollment();
    });
    return () => {
      ignore = true;
    };
  }, [enrollMethod, enrollData, totpAlreadyActive, startTotpEnrollment]);

  function handleTabKeyDown(e: KeyboardEvent<HTMLButtonElement>) {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      const next: EnrollMethod = enrollMethod === 'webauthn' ? 'totp' : 'webauthn';
      setEnrollMethod(next);
      setErrorMessage(null);
      if (next === 'webauthn') {
        webauthnTabRef.current?.focus();
      } else {
        totpTabRef.current?.focus();
      }
    }
  }

  async function handleCopyText(value: string, field: 'secret' | 'uri' | 'recovery') {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedField(field);
      setTimeout(() => setCopiedField((prev) => (prev === field ? null : prev)), 2000);
    } catch {
      setErrorMessage('Không thể sao chép tự động. Vui lòng chọn và sao chép thủ công.');
    }
  }

  async function handleVerifyTotpEnrollment(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setErrorMessage(null);
    if (verificationCode.trim().length !== 6) {
      setErrorMessage('Vui lòng nhập chính xác mã TOTP gồm 6 chữ số từ ứng dụng Authenticator.');
      return;
    }
    setIsVerifying(true);
    try {
      const res = await apiClient<{ recoveryCodes: string[]; user?: AuthUser }>(
        '/auth/mfa/enroll/verify',
        {
          method: 'POST',
          body: JSON.stringify({ code: verificationCode.trim() }),
        },
      );
      const codes = Array.isArray(res.recoveryCodes) ? res.recoveryCodes : [];
      setEnrolledUser(res.user ?? null);
      if (codes.length > 0) {
        setRecoveryCodes(codes);
      } else {
        await onComplete(res.user ?? null);
      }
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Mã xác nhận TOTP không hợp lệ hoặc đã hết hạn.'
          : 'Không thể hoàn tất kích hoạt MFA. Vui lòng thử lại.',
      );
    } finally {
      setIsVerifying(false);
    }
  }

  async function handleRegisterWebAuthn(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setErrorMessage(null);
    setIsRegisteringWebAuthn(true);
    try {
      const res = await executeWebAuthnRegistration(deviceLabel);
      const codes = Array.isArray(res.recoveryCodes) ? res.recoveryCodes : [];
      setEnrolledUser(res.user ?? null);
      if (codes.length > 0) {
        setRecoveryCodes(codes);
      } else {
        await onComplete(res.user ?? null);
      }
    } catch (err: unknown) {
      setErrorMessage(formatWebAuthnError(err));
    } finally {
      setIsRegisteringWebAuthn(false);
    }
  }

  async function handleConfirmSavedCodes() {
    setIsRedirecting(true);
    try {
      await onComplete(enrolledUser);
    } finally {
      setIsRedirecting(false);
    }
  }

  if (recoveryCodes && recoveryCodes.length > 0) {
    return (
      <MfaRecoveryCodesCard
        recoveryCodes={recoveryCodes}
        copied={copiedField === 'recovery'}
        isRedirecting={isRedirecting}
        onCopyAll={() => void handleCopyText(recoveryCodes.join('\n'), 'recovery')}
        onConfirmSaved={() => void handleConfirmSavedCodes()}
      />
    );
  }

  const webauthnTabId = `${tabBaseId}-tab-webauthn`;
  const totpTabId = `${tabBaseId}-tab-totp`;
  const webauthnPanelId = `${tabBaseId}-panel-webauthn`;
  const totpPanelId = `${tabBaseId}-panel-totp`;

  return (
    <Card className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] shadow-[0_12px_40px_rgba(0,0,0,0.06)]">
      <CardHeader className="space-y-1 pb-3">
        <CardTitle className="text-base font-bold text-[#222222]">
          Thiết lập xác thực đa yếu tố (MFA)
        </CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Chọn đăng ký khóa bảo mật / Passkey hoặc quét mã QR bằng ứng dụng xác thực.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div
          role="tablist"
          aria-label="Phương thức thiết lập MFA"
          className="grid grid-cols-2 gap-1 rounded-full border border-[#ebebeb] bg-[#f7f7f7] p-1"
        >
          <button
            ref={webauthnTabRef}
            id={webauthnTabId}
            type="button"
            role="tab"
            aria-selected={enrollMethod === 'webauthn'}
            aria-controls={webauthnPanelId}
            tabIndex={enrollMethod === 'webauthn' ? 0 : -1}
            onKeyDown={handleTabKeyDown}
            onClick={() => {
              setEnrollMethod('webauthn');
              setErrorMessage(null);
            }}
            className={`min-h-11 sm:min-h-10 rounded-full px-3 py-1.5 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer ${
              enrollMethod === 'webauthn'
                ? 'bg-[#ffffff] text-[#222222] shadow-xs border border-[#ebebeb]'
                : 'text-[#717171] hover:text-[#222222]'
            }`}
          >
            <Fingerprint size={16} strokeWidth={1.75} aria-hidden="true" />
            <span className="truncate">Khóa bảo mật / Passkey</span>
          </button>
          <button
            ref={totpTabRef}
            id={totpTabId}
            type="button"
            role="tab"
            aria-selected={enrollMethod === 'totp'}
            aria-controls={totpPanelId}
            tabIndex={enrollMethod === 'totp' ? 0 : -1}
            onKeyDown={handleTabKeyDown}
            onClick={() => {
              setEnrollMethod('totp');
              setErrorMessage(null);
            }}
            className={`min-h-11 sm:min-h-10 rounded-full px-3 py-1.5 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer ${
              enrollMethod === 'totp'
                ? 'bg-[#ffffff] text-[#222222] shadow-xs border border-[#ebebeb]'
                : 'text-[#717171] hover:text-[#222222]'
            }`}
          >
            <Smartphone size={16} strokeWidth={1.75} aria-hidden="true" />
            <span className="truncate">Mã ứng dụng (6 số)</span>
          </button>
        </div>

        {errorMessage && (
          <Alert variant="destructive" className="rounded-[20px] text-xs">
            <AlertCircle
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#C13515]"
              aria-hidden="true"
            />
            <AlertDescription className="ml-2 leading-relaxed">{errorMessage}</AlertDescription>
          </Alert>
        )}

        {enrollMethod === 'webauthn' ? (
          <div id={webauthnPanelId} role="tabpanel" aria-labelledby={webauthnTabId}>
            <MfaWebAuthnEnrollPanel
              deviceLabel={deviceLabel}
              isRegistering={isRegisteringWebAuthn}
              onChangeLabel={setDeviceLabel}
              onSubmit={handleRegisterWebAuthn}
            />
          </div>
        ) : (
          <div id={totpPanelId} role="tabpanel" aria-labelledby={totpTabId}>
            {isInitializing ? (
              <div className="py-8 text-center text-xs text-[#717171]">
                Đang khởi tạo khóa bí mật TOTP…
              </div>
            ) : totpAlreadyActive ? (
              <div className="space-y-3">
                <Alert variant="success" className="text-xs">
                  <CheckCircle2
                    size={16}
                    strokeWidth={1.75}
                    className="shrink-0 text-[#008A05]"
                    aria-hidden="true"
                  />
                  <AlertDescription className="ml-2 leading-relaxed">
                    Tài khoản này đã kích hoạt ứng dụng xác thực TOTP từ trước. Vui lòng chuyển sang
                    bước nhập mã 6 chữ số hoặc quản lý tại trang Phiên &amp; thiết bị.
                  </AlertDescription>
                </Alert>
                <InteractiveHoverButton
                  type="button"
                  variant="primary"
                  icon={<KeyRound size={16} strokeWidth={1.75} aria-hidden="true" />}
                  text="Chuyển sang nhập mã xác thực"
                  onClick={onSwitchToVerify}
                  className="w-full text-xs"
                />
              </div>
            ) : enrollData ? (
              <MfaEnrollForm
                enrollData={enrollData}
                copiedField={copiedField}
                verificationCode={verificationCode}
                isVerifying={isVerifying}
                onCopyText={(val, field) => void handleCopyText(val, field)}
                onChangeCode={setVerificationCode}
                onSubmit={handleVerifyTotpEnrollment}
              />
            ) : (
              <InteractiveHoverButton
                type="button"
                variant="secondary"
                icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
                text="Thử khởi tạo lại khóa TOTP"
                onClick={() => void startTotpEnrollment()}
                className="w-full text-xs"
              />
            )}
          </div>
        )}
      </CardContent>
      <CardFooter className="flex flex-col space-y-1.5 pt-2 border-t border-[#ebebeb]">
        <button
          type="button"
          onClick={onSwitchToVerify}
          className="min-h-11 sm:min-h-9 rounded-full px-3 py-1.5 text-xs font-medium text-[#E31C5F] hover:bg-[#f7f7f7] hover:underline flex items-center justify-center gap-1.5 cursor-pointer"
        >
          <KeyRound size={16} strokeWidth={1.75} aria-hidden="true" />
          <span>Đã thiết lập thiết bị xác thực? Chuyển sang nhập mã</span>
        </button>
        <Link
          href={backHref}
          className="min-h-11 sm:min-h-9 rounded-full px-3 py-1.5 text-xs text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] flex items-center justify-center gap-1.5"
        >
          <ArrowLeft size={16} strokeWidth={1.75} aria-hidden="true" />
          <span>{backLabel}</span>
        </Link>
      </CardFooter>
    </Card>
  );
}

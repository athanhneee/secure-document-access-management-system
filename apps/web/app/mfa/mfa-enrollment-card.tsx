'use client';

import { useCallback, useEffect, useState, type FormEvent } from 'react';
import Link from 'next/link';
import { AlertCircle, ArrowLeft, Fingerprint, KeyRound, RefreshCw, Smartphone } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
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

interface MfaEnrollmentCardProps {
  onComplete: () => Promise<void>;
  onSwitchToVerify: () => void;
}

type EnrollMethod = 'webauthn' | 'totp';

/**
 * Thuật toán: Máy Trạng Thái Đăng Ký Nhân Tố MFA Song Chế Độ (FIDO2/Passkey & TOTP RFC 6238) (`MfaEnrollmentCard`)
 * Mục đích:
 *   - Cho phép người dùng lựa chọn linh hoạt đăng ký khóa phần cứng FIDO2/Passkey (`startRegistration`) hoặc quét mã QR TOTP 6 chữ số.
 *   - Khởi tạo lười bí mật TOTP đúng lúc chuyển sang chế độ TOTP tránh gọi thừa API, đồng thời bắt buộc lưu 10 mã khôi phục dùng một lần sau khi kích hoạt thành công.
 */
export function MfaEnrollmentCard({ onComplete, onSwitchToVerify }: MfaEnrollmentCardProps) {
  const [enrollMethod, setEnrollMethod] = useState<EnrollMethod>('webauthn');
  const [enrollData, setEnrollData] = useState<MfaEnrollResponse | null>(null);
  const [isInitializing, setIsInitializing] = useState(false);
  const [verificationCode, setVerificationCode] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [deviceLabel, setDeviceLabel] = useState('');
  const [isRegisteringWebAuthn, setIsRegisteringWebAuthn] = useState(false);
  const [isRedirecting, setIsRedirecting] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [copiedField, setCopiedField] = useState<'secret' | 'uri' | 'recovery' | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const startTotpEnrollment = useCallback(async () => {
    setIsInitializing(true);
    setErrorMessage(null);
    try {
      const res = await apiClient<MfaEnrollResponse>('/auth/mfa/enroll', {
        method: 'POST',
        body: JSON.stringify({ label: 'Authenticator' }),
      });
      setEnrollData(res);
    } catch (err) {
      setErrorMessage(
        err instanceof ApiError
          ? err.message || 'Không thể khởi tạo khóa thiết lập MFA.'
          : 'Không thể kết nối đến máy chủ để thiết lập MFA.',
      );
    } finally {
      setIsInitializing(false);
    }
  }, []);

  useEffect(() => {
    if (enrollMethod !== 'totp' || enrollData) return;
    let ignore = false;
    void Promise.resolve().then(() => {
      if (!ignore) void startTotpEnrollment();
    });
    return () => {
      ignore = true;
    };
  }, [enrollMethod, enrollData, startTotpEnrollment]);

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
      const res = await apiClient<{ recoveryCodes: string[] }>('/auth/mfa/enroll/verify', {
        method: 'POST',
        body: JSON.stringify({ code: verificationCode.trim() }),
      });
      setRecoveryCodes(res.recoveryCodes || []);
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
      setRecoveryCodes(res.recoveryCodes);
    } catch (err: unknown) {
      setErrorMessage(formatWebAuthnError(err));
    } finally {
      setIsRegisteringWebAuthn(false);
    }
  }

  async function handleConfirmSavedCodes() {
    setIsRedirecting(true);
    try {
      await onComplete();
    } finally {
      setIsRedirecting(false);
    }
  }

  if (recoveryCodes) {
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

  return (
    <Card className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] shadow-[0_12px_40px_rgba(0,0,0,0.06)]">
      <CardHeader className="space-y-1 pb-3">
        <CardTitle className="text-base font-bold text-[#222222]">
          Thiết lập xác thực đa yếu tố (MFA)
        </CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Chọn đăng ký khóa bảo mật FIDO2 / Passkey hoặc quét mã QR với ứng dụng Authenticator
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div
          role="tablist"
          aria-label="Phương thức thiết lập MFA"
          className="grid grid-cols-2 gap-1 rounded-full border border-[#ebebeb] bg-[#f7f7f7] p-1"
        >
          <button
            type="button"
            role="tab"
            aria-selected={enrollMethod === 'webauthn'}
            onClick={() => {
              setEnrollMethod('webauthn');
              setErrorMessage(null);
            }}
            className={`min-h-10 rounded-full px-3 py-1.5 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer ${
              enrollMethod === 'webauthn'
                ? 'bg-[#ffffff] text-[#222222] shadow-xs border border-[#ebebeb]'
                : 'text-[#717171] hover:text-[#222222]'
            }`}
          >
            <Fingerprint size={16} strokeWidth={1.75} aria-hidden="true" />
            <span className="truncate">FIDO2 / Passkey</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={enrollMethod === 'totp'}
            onClick={() => {
              setEnrollMethod('totp');
              setErrorMessage(null);
            }}
            className={`min-h-10 rounded-full px-3 py-1.5 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer ${
              enrollMethod === 'totp'
                ? 'bg-[#ffffff] text-[#222222] shadow-xs border border-[#ebebeb]'
                : 'text-[#717171] hover:text-[#222222]'
            }`}
          >
            <Smartphone size={16} strokeWidth={1.75} aria-hidden="true" />
            <span className="truncate">Mã TOTP (6 số)</span>
          </button>
        </div>

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

        {enrollMethod === 'webauthn' ? (
          <MfaWebAuthnEnrollPanel
            deviceLabel={deviceLabel}
            isRegistering={isRegisteringWebAuthn}
            onChangeLabel={setDeviceLabel}
            onSubmit={handleRegisterWebAuthn}
          />
        ) : isInitializing ? (
          <div className="py-8 text-center text-xs text-[#717171]">
            Đang khởi tạo khóa bí mật TOTP…
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
          href="/login"
          className="min-h-11 sm:min-h-9 rounded-full px-3 py-1.5 text-xs text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] flex items-center justify-center gap-1.5"
        >
          <ArrowLeft size={16} strokeWidth={1.75} aria-hidden="true" />
          <span>Quay về trang đăng nhập</span>
        </Link>
      </CardFooter>
    </Card>
  );
}

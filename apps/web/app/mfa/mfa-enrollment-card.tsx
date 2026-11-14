'use client';

import { useCallback, useEffect, useState, type FormEvent } from 'react';
import Link from 'next/link';
import { AlertCircle, ArrowLeft, KeyRound, RefreshCw } from 'lucide-react';
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

interface MfaEnrollmentCardProps {
  onComplete: () => Promise<void>;
  onSwitchToVerify: () => void;
}

/**
 * Thuật toán: Máy Trạng Thái Đăng Ký Nhân Tố Xác Thực TOTP Lần Đầu & Phát Hành Mã Khôi Phục (`MfaEnrollmentCard`)
 * Mục đích: Khởi tạo bí mật RFC 6238 qua `/auth/mfa/enroll`, xác nhận đồng bộ đồng hồ 6 chữ số tại `/auth/mfa/enroll/verify` và buộc người dùng lưu 10 mã khôi phục dùng một lần trước khi nâng cấp phiên.
 */
export function MfaEnrollmentCard({ onComplete, onSwitchToVerify }: MfaEnrollmentCardProps) {
  const [enrollData, setEnrollData] = useState<MfaEnrollResponse | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);
  const [verificationCode, setVerificationCode] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [isRedirecting, setIsRedirecting] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [copiedField, setCopiedField] = useState<'secret' | 'uri' | 'recovery' | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const startEnrollment = useCallback(async () => {
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
    let ignore = false;
    void Promise.resolve().then(() => {
      if (!ignore) void startEnrollment();
    });
    return () => {
      ignore = true;
    };
  }, [startEnrollment]);

  async function handleCopyText(value: string, field: 'secret' | 'uri' | 'recovery') {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedField(field);
      setTimeout(() => setCopiedField((prev) => (prev === field ? null : prev)), 2000);
    } catch {
      setErrorMessage('Không thể sao chép tự động. Vui lòng chọn và sao chép thủ công.');
    }
  }

  async function handleVerifyEnrollment(e: FormEvent<HTMLFormElement>) {
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
          Thiết lập xác thực đa yếu tố lần đầu (TOTP)
        </CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          Quét mã QR hoặc nhập khóa Base32 vào Google / Microsoft Authenticator để kích hoạt bảo vệ
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

        {isInitializing ? (
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
            onSubmit={handleVerifyEnrollment}
          />
        ) : (
          <InteractiveHoverButton
            type="button"
            variant="secondary"
            icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
            text="Thử khởi tạo lại khóa MFA"
            onClick={() => void startEnrollment()}
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

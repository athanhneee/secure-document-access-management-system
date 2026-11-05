'use client';

import type { FormEvent } from 'react';
import Link from 'next/link';
import { Key, ArrowLeft, AlertCircle, Fingerprint, ShieldPlus } from 'lucide-react';
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

interface MfaMethodCardsProps {
  isRecoveryMode: boolean;
  totpCode: string;
  recoveryCode: string;
  isLoading: boolean;
  isWebAuthnLoading: boolean;
  errorMessage: string | null;
  onChangeTotpCode: (code: string) => void;
  onChangeRecoveryCode: (code: string) => void;
  onToggleRecoveryMode: () => void;
  onStartEnrollment: () => void;
  onWebAuthnVerify: () => void;
  onSubmitVerify: (e: FormEvent<HTMLFormElement>) => void;
}

export function MfaMethodCards({
  isRecoveryMode,
  totpCode,
  recoveryCode,
  isLoading,
  isWebAuthnLoading,
  errorMessage,
  onChangeTotpCode,
  onChangeRecoveryCode,
  onToggleRecoveryMode,
  onStartEnrollment,
  onWebAuthnVerify,
  onSubmitVerify,
}: MfaMethodCardsProps) {
  return (
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
            <AlertCircle
              size={16}
              strokeWidth={1.75}
              className="shrink-0 text-[#C13515]"
              aria-hidden="true"
            />
            <AlertDescription className="ml-2 leading-relaxed">{errorMessage}</AlertDescription>
          </Alert>
        )}

        {!isRecoveryMode && (
          <div className="space-y-3">
            <button
              type="button"
              onClick={onWebAuthnVerify}
              disabled={isLoading || isWebAuthnLoading}
              className="w-full py-3 px-4 rounded-full border border-[#222222] bg-[#222222] text-[#ffffff] hover:opacity-90 transition-all flex items-center justify-center gap-2.5 text-xs font-semibold shadow-xs disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {isWebAuthnLoading ? (
                <>
                  <div className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                  <span>Đang chạm khóa bảo mật FIDO2…</span>
                </>
              ) : (
                <>
                  <Fingerprint
                    size={16}
                    strokeWidth={2}
                    className="text-[#ffffff]"
                    aria-hidden="true"
                  />
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

        <form onSubmit={onSubmitVerify} className="space-y-4">
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
                onChange={(e) => onChangeTotpCode(e.target.value.replace(/\D/g, ''))}
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
              <label htmlFor="recovery-code" className="block text-xs font-semibold text-[#222222]">
                Mã khôi phục khẩn cấp (Recovery Code)
              </label>
              <Input
                id="recovery-code"
                name="recoveryCode"
                type="text"
                autoComplete="off"
                disabled={isLoading || isWebAuthnLoading}
                value={recoveryCode}
                onChange={(e) => onChangeRecoveryCode(e.target.value.toUpperCase())}
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
          onClick={onToggleRecoveryMode}
          className="rounded-full px-3 py-1 text-xs text-[#FF385C] hover:bg-[#f7f7f7] hover:underline transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
        >
          <Key size={16} strokeWidth={1.75} aria-hidden="true" />
          <span>
            {isRecoveryMode
              ? 'Quay lại phương thức xác thực FIDO2 / TOTP'
              : 'Không có thiết bị xác thực? Dùng mã khôi phục'}
          </span>
        </button>

        <button
          type="button"
          disabled={isLoading || isWebAuthnLoading}
          onClick={onStartEnrollment}
          className="rounded-full px-3 py-1 text-xs text-[#222222] hover:bg-[#f7f7f7] hover:underline transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
        >
          <ShieldPlus size={16} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
          <span>Thiết lập MFA lần đầu</span>
        </button>

        <Link
          href="/login"
          className="rounded-full px-3 py-1 text-xs text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors flex items-center justify-center gap-1.5"
        >
          <ArrowLeft size={16} strokeWidth={1.75} aria-hidden="true" />
          <span>Quay về trang đăng nhập</span>
        </Link>
      </CardFooter>
    </Card>
  );
}

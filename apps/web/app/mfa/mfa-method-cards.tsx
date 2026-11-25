'use client';

/**
 * Thuật toán: Giao Diện Đa Phương Thức Thử Thách MFA Chuẩn Hệ Thống Thiết Kế (`MfaMethodCards`, V-21, V-49, V-62)
 * Mục đích: Chuyển đổi liền mạch giữa xác thực phần cứng FIDO2/Passkey, mã ứng dụng TOTP 6 chữ số lọc số tức thời và mã khôi phục khẩn cấp dùng một lần, dùng `InteractiveHoverButton` đồng bộ thay nút đen đặc và con quay tự chế.
 */
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
  unauthenticatedNotice?: boolean;
  showFirstTimeEnroll?: boolean;
  backHref?: string;
  backLabel?: string;
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
  unauthenticatedNotice = false,
  showFirstTimeEnroll = true,
  backHref = '/login',
  backLabel = 'Quay về trang đăng nhập',
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
          {isRecoveryMode ? 'Sử dụng mã khôi phục khẩn cấp' : 'Xác nhận danh tính bước 2'}
        </CardTitle>
        <CardDescription className="text-xs text-[#717171]">
          {isRecoveryMode
            ? 'Nhập 1 trong các mã khôi phục đã được cấp khi thiết lập tài khoản.'
            : 'Sử dụng khóa bảo mật, sinh trắc học thiết bị hoặc ứng dụng xác thực.'}
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-5">
        {unauthenticatedNotice && !errorMessage && (
          <output className="block rounded-[16px] border border-[#E07912]/35 bg-[#E07912]/10 p-3 text-xs text-[#222222] leading-relaxed">
            Chưa phát hiện phiên chờ xác thực bước 2. Nếu bạn chưa đăng nhập mật khẩu, hãy{' '}
            <Link href="/login" className="font-semibold text-[#E31C5F] underline">
              đăng nhập tại đây
            </Link>{' '}
            trước khi nhập mã MFA.
          </output>
        )}

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
            <InteractiveHoverButton
              type="button"
              variant="secondary"
              onClick={onWebAuthnVerify}
              isLoading={isWebAuthnLoading}
              disabled={isLoading || isWebAuthnLoading}
              icon={<Fingerprint size={16} strokeWidth={1.75} aria-hidden="true" />}
              text="Xác thực bằng khóa bảo mật / Passkey"
              className="w-full py-2.5 text-xs font-semibold"
            />

            <div className="relative flex py-1 items-center">
              <div className="grow border-t border-[#ebebeb]"></div>
              <span className="shrink mx-3 text-xs font-semibold text-[#717171] uppercase tracking-wider">
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
                Mã xác thực 6 chữ số
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
                className="text-center font-bold text-xl tracking-[0.4em] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#717171] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
                aria-label="Mã xác thực 6 chữ số"
              />
              <p className="text-xs text-[#717171] text-center">
                Mã xác thực làm mới mỗi 30 giây từ ứng dụng Google hoặc Microsoft Authenticator.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              <label htmlFor="recovery-code" className="block text-xs font-semibold text-[#222222]">
                Mã khôi phục khẩn cấp
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
                className="text-center font-bold text-sm tracking-wider bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#717171] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
                aria-label="Mã khôi phục khẩn cấp"
              />
              <p className="text-xs text-[#C13515] font-medium text-center">
                Lưu ý: Mỗi mã khôi phục chỉ sử dụng được duy nhất một lần.
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

      <CardFooter className="flex flex-col space-y-1.5 pt-2 border-t border-[#ebebeb]">
        <button
          type="button"
          disabled={isLoading || isWebAuthnLoading}
          onClick={onToggleRecoveryMode}
          className="min-h-11 sm:min-h-9 rounded-full px-3 py-1.5 text-xs font-medium text-[#E31C5F] hover:bg-[#f7f7f7] hover:underline transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
        >
          <Key size={16} strokeWidth={1.75} aria-hidden="true" />
          <span>
            {isRecoveryMode
              ? 'Quay lại xác thực bằng khóa bảo mật hoặc mã ứng dụng'
              : 'Không có thiết bị xác thực? Dùng mã khôi phục'}
          </span>
        </button>

        {showFirstTimeEnroll && (
          <button
            type="button"
            disabled={isLoading || isWebAuthnLoading}
            onClick={onStartEnrollment}
            className="min-h-11 sm:min-h-9 rounded-full px-3 py-1.5 text-xs text-[#222222] hover:bg-[#f7f7f7] hover:underline transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
          >
            <ShieldPlus
              size={16}
              strokeWidth={1.75}
              className="text-[#E31C5F]"
              aria-hidden="true"
            />
            <span>Thiết lập MFA lần đầu</span>
          </button>
        )}

        <Link
          href={backHref}
          className="min-h-11 sm:min-h-9 rounded-full px-3 py-1.5 text-xs text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors flex items-center justify-center gap-1.5"
        >
          <ArrowLeft size={16} strokeWidth={1.75} aria-hidden="true" />
          <span>{backLabel}</span>
        </Link>
      </CardFooter>
    </Card>
  );
}

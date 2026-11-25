'use client';

import { useState, type FormEvent } from 'react';
import Image from 'next/image';
import { Check, Copy, Eye, EyeOff } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

export interface MfaEnrollResponse {
  secret: string;
  uri: string;
  qrCodeDataUrl?: string | undefined;
}

interface MfaEnrollFormProps {
  enrollData: MfaEnrollResponse;
  copiedField: 'secret' | 'uri' | 'recovery' | null;
  verificationCode: string;
  isVerifying: boolean;
  onCopyText: (value: string, field: 'secret' | 'uri') => void;
  onChangeCode: (code: string) => void;
  onSubmit: (e: FormEvent<HTMLFormElement>) => void;
}

/**
 * Thuật toán: Biểu Mẫu Quét Mã QR, Che Khóa Base32 / URI Mặc Định & Xác Thực Đồng Bộ TOTP (`MfaEnrollForm`, V-13)
 * Mục đích:
 *   - Che mặc định giá trị khóa bí mật Base32 và `otpauth://` URI bằng `type="password"` (kèm nút Hiện/Ẩn chuẩn WCAG) tránh lộ bí mật qua nhìn trộm màn hình (`V-13`).
 *   - Khóa nút kích hoạt khi chưa đủ đúng 6 chữ số TOTP.
 */
export function MfaEnrollForm({
  enrollData,
  copiedField,
  verificationCode,
  isVerifying,
  onCopyText,
  onChangeCode,
  onSubmit,
}: MfaEnrollFormProps) {
  const [revealed, setRevealed] = useState<{ secret: boolean; uri: boolean }>({
    secret: false,
    uri: false,
  });

  const copyItems: Array<{
    key: 'secret' | 'uri';
    id: string;
    label: string;
    aria: string;
    toggleAriaShow: string;
    toggleAriaHide: string;
    value: string;
  }> = [
    {
      key: 'secret',
      id: 'mfa-enroll-secret',
      label: 'Khóa thiết lập thủ công',
      aria: 'Sao chép khóa thiết lập thủ công',
      toggleAriaShow: 'Hiện khóa thiết lập thủ công',
      toggleAriaHide: 'Ẩn khóa thiết lập thủ công',
      value: enrollData.secret,
    },
    {
      key: 'uri',
      id: 'mfa-enroll-uri',
      label: 'Đường dẫn cấu hình ứng dụng xác thực',
      aria: 'Sao chép đường dẫn cấu hình ứng dụng xác thực',
      toggleAriaShow: 'Hiện đường dẫn cấu hình ứng dụng xác thực',
      toggleAriaHide: 'Ẩn đường dẫn cấu hình ứng dụng xác thực',
      value: enrollData.uri,
    },
  ];

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      {enrollData.qrCodeDataUrl && (
        <div className="flex justify-center rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-4">
          <Image
            src={enrollData.qrCodeDataUrl}
            alt="Mã QR thiết lập TOTP"
            width={176}
            height={176}
            unoptimized
            className="h-44 w-44 rounded-[12px] border border-[#ebebeb] bg-[#ffffff] p-1.5"
          />
        </div>
      )}

      {copyItems.map((item) => {
        const isShown = revealed[item.key];
        return (
          <div key={item.key} className="space-y-1.5">
            <label htmlFor={item.id} className="block text-xs font-semibold text-[#222222]">
              {item.label}
            </label>
            <div className="flex items-center gap-1.5">
              <div className="relative flex-1 min-w-0">
                <Input
                  id={item.id}
                  type={isShown ? 'text' : 'password'}
                  readOnly
                  value={item.value}
                  className="font-mono text-xs bg-[#f7f7f7] pr-11"
                />
                <button
                  type="button"
                  aria-label={isShown ? item.toggleAriaHide : item.toggleAriaShow}
                  onClick={() => setRevealed((prev) => ({ ...prev, [item.key]: !prev[item.key] }))}
                  className="absolute inset-y-0 right-0 flex w-11 items-center justify-center rounded-r-full text-[#717171] hover:text-[#222222] cursor-pointer"
                >
                  {isShown ? (
                    <EyeOff size={16} strokeWidth={1.75} aria-hidden="true" />
                  ) : (
                    <Eye size={16} strokeWidth={1.75} aria-hidden="true" />
                  )}
                </button>
              </div>
              <button
                type="button"
                aria-label={item.aria}
                onClick={() => onCopyText(item.value, item.key)}
                className="shrink-0 min-h-11 rounded-full border border-[#dddddd] bg-[#ffffff] hover:bg-[#f7f7f7] px-3 py-2 text-xs font-semibold text-[#222222] flex items-center gap-1 cursor-pointer"
              >
                {copiedField === item.key ? (
                  <Check size={16} strokeWidth={2} className="text-[#008A05]" aria-hidden="true" />
                ) : (
                  <Copy size={16} strokeWidth={1.75} aria-hidden="true" />
                )}
                <span>{copiedField === item.key ? 'Đã sao chép' : 'Sao chép'}</span>
              </button>
            </div>
          </div>
        );
      })}

      <div className="space-y-1.5">
        <label
          htmlFor="mfa-enroll-verify-code"
          className="block text-xs font-semibold text-[#222222]"
        >
          Nhập mã xác thực 6 chữ số để kích hoạt
        </label>
        <Input
          id="mfa-enroll-verify-code"
          type="text"
          inputMode="numeric"
          pattern="[0-9]*"
          maxLength={6}
          autoComplete="one-time-code"
          disabled={isVerifying}
          value={verificationCode}
          onChange={(e) => onChangeCode(e.target.value.replace(/\D/g, ''))}
          placeholder="123456"
          className="text-center font-bold text-xl tracking-[0.4em] bg-[#ffffff] border-[#dddddd] text-[#222222]"
        />
      </div>

      <InteractiveHoverButton
        type="submit"
        isLoading={isVerifying}
        disabled={isVerifying || verificationCode.trim().length !== 6}
        text="Kích hoạt MFA & nhận mã khôi phục"
        className="w-full py-2.5 text-xs font-semibold"
      />
    </form>
  );
}

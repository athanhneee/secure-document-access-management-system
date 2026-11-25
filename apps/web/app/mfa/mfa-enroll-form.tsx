'use client';

import type { FormEvent } from 'react';
import Image from 'next/image';
import { Check, Copy } from 'lucide-react';
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
 * Thuật toán: Biểu Mẫu Quét Mã QR, Sao Chép Khóa Base32 & Xác Thực Đồng Bộ TOTP (`MfaEnrollForm`)
 * Mục đích: Tách riêng giao diện hiển thị khóa bí mật RFC 6238 và xác nhận mã OTP 6 chữ số với vùng chạm tối thiểu `44x44px`.
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
  const copyItems: Array<{
    key: 'secret' | 'uri';
    id: string;
    label: string;
    aria: string;
    value: string;
  }> = [
    {
      key: 'secret',
      id: 'mfa-enroll-secret',
      label: 'Khóa thiết lập thủ công',
      aria: 'Sao chép khóa thiết lập thủ công',
      value: enrollData.secret,
    },
    {
      key: 'uri',
      id: 'mfa-enroll-uri',
      label: 'Đường dẫn cấu hình ứng dụng xác thực',
      aria: 'Sao chép đường dẫn cấu hình ứng dụng xác thực',
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

      {copyItems.map((item) => (
        <div key={item.key} className="space-y-1.5">
          <label htmlFor={item.id} className="block text-xs font-semibold text-[#222222]">
            {item.label}
          </label>
          <div className="flex items-center gap-2">
            <Input
              id={item.id}
              readOnly
              value={item.value}
              className="font-mono text-xs bg-[#f7f7f7]"
            />
            <button
              type="button"
              aria-label={item.aria}
              onClick={() => onCopyText(item.value, item.key)}
              className="shrink-0 min-h-11 rounded-full border border-[#dddddd] bg-[#ffffff] hover:bg-[#f7f7f7] px-3.5 py-2 text-xs font-semibold text-[#222222] flex items-center gap-1 cursor-pointer"
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
      ))}

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
        disabled={isVerifying}
        text="Kích hoạt MFA & nhận mã khôi phục"
        className="w-full py-2.5 text-xs font-semibold"
      />
    </form>
  );
}

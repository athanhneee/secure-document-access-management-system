'use client';

/**
 * Thuật toán: Biểu Mẫu Đăng Ký Khóa Bảo Mật FIDO2 / Passkey Lần Đầu Kèm Cảnh Báo Loopback (`MfaWebAuthnEnrollPanel`)
 * Mục đích: Thu thập nhãn gợi nhớ thiết bị (tối đa 80 ký tự), phát hiện địa chỉ IP `127.0.0.1` để nhắc chuyển sang `localhost` và kích hoạt luồng tạo cặp khóa công khai WebAuthn (`startRegistration`).
 */
import type { FormEvent } from 'react';
import { AlertTriangle, Fingerprint, ShieldCheck } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { useLocalhostSwitchUrl } from './webauthn-binary';

export interface MfaWebAuthnEnrollPanelProps {
  deviceLabel: string;
  isRegistering: boolean;
  onChangeLabel: (label: string) => void;
  onSubmit: (e: FormEvent<HTMLFormElement>) => void;
}

export function MfaWebAuthnEnrollPanel({
  deviceLabel,
  isRegistering,
  onChangeLabel,
  onSubmit,
}: MfaWebAuthnEnrollPanelProps) {
  const localhostUrl = useLocalhostSwitchUrl();

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-2 text-xs text-[#717171] leading-relaxed">
        <div className="flex items-center gap-2 font-semibold text-[#222222]">
          <ShieldCheck
            size={16}
            strokeWidth={1.75}
            className="text-[#008A05] shrink-0"
            aria-hidden="true"
          />
          <span>Chống giả mạo trang đăng nhập bằng khóa bảo mật</span>
        </div>
        <p>
          Hỗ trợ <strong className="text-[#222222]">Windows Hello</strong> (PIN / Vân tay / Khuôn
          mặt), <strong className="text-[#222222]">Touch ID</strong>,{' '}
          <strong className="text-[#222222]">Passkey điện thoại</strong> hoặc{' '}
          <strong className="text-[#222222]">khóa bảo mật USB</strong>.
        </p>
      </div>

      {localhostUrl && (
        <output className="block rounded-[16px] border border-[#E07912]/35 bg-[#E07912]/10 p-3 text-xs text-[#222222] space-y-1.5">
          <div className="flex items-center gap-1.5 font-semibold text-[#E07912]">
            <AlertTriangle size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
            <span>Cần mở bằng tên miền localhost để dùng Passkey</span>
          </div>
          <p className="text-[#717171] leading-relaxed">
            Trình duyệt chặn WebAuthn trên IP thô <code>127.0.0.1</code>. Hãy chuyển sang{' '}
            <a href={localhostUrl} className="font-semibold text-[#E31C5F] underline break-all">
              {localhostUrl}
            </a>{' '}
            rồi bấm đăng ký.
          </p>
        </output>
      )}

      <div className="space-y-1.5">
        <label htmlFor="mfa-webauthn-label" className="block text-xs font-semibold text-[#222222]">
          Tên gợi nhớ thiết bị / khóa bảo mật
        </label>
        <Input
          id="mfa-webauthn-label"
          name="label"
          type="text"
          maxLength={80}
          disabled={isRegistering}
          value={deviceLabel}
          onChange={(e) => onChangeLabel(e.target.value)}
          placeholder="VD: Windows Hello Laptop, khóa USB văn phòng…"
          className="bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20"
        />
      </div>

      <button
        type="submit"
        disabled={isRegistering}
        className="w-full min-h-11 py-3 px-4 rounded-full border border-[#222222] bg-[#222222] text-[#ffffff] hover:opacity-90 transition-all flex items-center justify-center gap-2 text-xs font-semibold shadow-xs disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
      >
        {isRegistering ? (
          <>
            <div className="h-4 w-4 rounded-full border-2 border-[#ffffff]/30 border-t-[#ffffff] animate-spin" />
            <span>Đang chờ xác nhận thiết bị…</span>
          </>
        ) : (
          <>
            <Fingerprint size={16} strokeWidth={2} className="text-[#ffffff]" aria-hidden="true" />
            <span>Đăng ký khóa bảo mật / Passkey</span>
          </>
        )}
      </button>
    </form>
  );
}

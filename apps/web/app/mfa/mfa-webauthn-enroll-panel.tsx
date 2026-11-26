'use client';

/**
 * Thuật toán: Biểu Mẫu Đăng Ký Khóa Bảo Mật FIDO2 / Passkey Lần Đầu Chuẩn Hệ Thống Thiết Kế (`MfaWebAuthnEnrollPanel`, V-62, #59)
 * Mục đích: Thu thập nhãn gợi nhớ thiết bị (tối đa 80 ký tự), phát hiện địa chỉ IP `127.0.0.1` để nhắc chuyển sang `localhost`, đảm bảo tương phản WCAG 2.1 AA (`#222222` / `#717171`) và sử dụng `InteractiveHoverButton` chuẩn hệ thống thay cho nút đen đặc tự chế.
 */
import type { FormEvent } from 'react';
import { AlertTriangle, Fingerprint, ShieldCheck } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
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
          <div className="flex items-center gap-1.5 font-semibold text-[#222222]">
            <AlertTriangle
              size={16}
              strokeWidth={1.75}
              className="text-[#E07912] shrink-0"
              aria-hidden="true"
            />
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
          className="bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#717171]"
        />
      </div>

      <InteractiveHoverButton
        type="submit"
        variant="primary"
        isLoading={isRegistering}
        disabled={isRegistering}
        icon={<Fingerprint size={16} strokeWidth={2} aria-hidden="true" />}
        text="Đăng ký khóa bảo mật / Passkey"
        className="w-full py-2.5 text-xs font-semibold"
      />
    </form>
  );
}

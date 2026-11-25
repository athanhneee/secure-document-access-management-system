'use client';

/**
 * Thuật toán: Thẻ Đăng Ký Khóa Phần Cứng FIDO2 / Passkey Trực Tiếp Trong Không Gian Phiên (`/sessions`) (`PasskeyEnrollmentCard`)
 * Mục đích:
 *   - Cho phép tài khoản đã xác thực Step-Up MFA (hoặc tài khoản chưa bật MFA lần nào) đăng ký khóa Windows Hello / Touch ID / YubiKey qua W3C WebAuthn `startRegistration`.
 *   - Hiển thị 10 mã khôi phục khẩn cấp trong `<dialog>` chuẩn WCAG `.showModal()` ngay sau khi kích hoạt thành công và tự phát hiện tên miền `127.0.0.1` để nhắc chuyển sang `localhost`.
 */
import { useState, type FormEvent } from 'react';
import { AlertTriangle, Check, Copy, Fingerprint, ShieldCheck } from 'lucide-react';
import {
  executeWebAuthnRegistration,
  formatWebAuthnError,
  useLocalhostSwitchUrl,
} from '@/app/mfa/webauthn-binary';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

export interface PasskeyEnrollmentCardProps {
  mfaVerified?: boolean | undefined;
  onRegistered: (message: string) => Promise<void>;
  onError: (message: string) => void;
}

export function PasskeyEnrollmentCard({
  mfaVerified,
  onRegistered,
  onError,
}: PasskeyEnrollmentCardProps) {
  const [deviceLabel, setDeviceLabel] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [copiedRecovery, setCopiedRecovery] = useState(false);
  const localhostUrl = useLocalhostSwitchUrl();

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setIsRegistering(true);
    try {
      const trimmedLabel = deviceLabel.trim();
      const result = await executeWebAuthnRegistration(trimmedLabel || undefined);
      setDeviceLabel('');
      if (result.recoveryCodes.length > 0) {
        setRecoveryCodes(result.recoveryCodes);
        setCopiedRecovery(false);
      }
      await onRegistered(
        `Đã đăng ký khóa bảo mật / Passkey${trimmedLabel ? ` "${trimmedLabel}"` : ''} thành công. Từ lần đăng nhập sau bạn có thể dùng sinh trắc học, mã PIN hoặc khóa bảo mật thay cho mã ứng dụng.`,
      );
    } catch (err: unknown) {
      onError(formatWebAuthnError(err));
    } finally {
      setIsRegistering(false);
    }
  }

  async function handleCopyAllCodes() {
    if (!recoveryCodes) return;
    try {
      await navigator.clipboard.writeText(recoveryCodes.join('\n'));
      setCopiedRecovery(true);
      setTimeout(() => setCopiedRecovery(false), 2000);
    } catch {
      onError('Không thể sao chép tự động. Vui lòng chọn và sao chép thủ công.');
    }
  }

  return (
    <>
      <Card>
        <CardHeader className="pb-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Fingerprint
                size={20}
                strokeWidth={1.75}
                className="text-[#FF385C] shrink-0"
                aria-hidden="true"
              />
              <CardTitle className="text-sm font-bold text-[#222222]">
                Khóa bảo mật &amp; Passkey
              </CardTitle>
            </div>
            <Badge variant={mfaVerified ? 'success' : 'info'}>
              {mfaVerified ? 'Đã xác thực MFA' : 'Chống giả mạo'}
            </Badge>
          </div>
          <CardDescription className="text-xs text-[#717171]">
            Đăng ký Windows Hello (PIN / Vân tay / Khuôn mặt), Touch ID, Passkey điện thoại hoặc
            khóa bảo mật USB để xác thực bước 2 nhanh chóng và chống giả mạo trang đăng nhập.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-3.5">
          {localhostUrl && (
            <output className="block rounded-[16px] border border-[#E07912]/35 bg-[#E07912]/10 p-3 text-xs text-[#222222] space-y-1">
              <div className="flex items-center gap-1.5 font-semibold text-[#222222]">
                <AlertTriangle
                  size={16}
                  strokeWidth={1.75}
                  className="text-[#E07912] shrink-0"
                  aria-hidden="true"
                />
                <span>Cần truy cập bằng localhost để kích hoạt Passkey</span>
              </div>
              <p className="text-[#717171] leading-relaxed">
                Chuẩn trình duyệt W3C WebAuthn không cho đăng ký khóa trên địa chỉ IP{' '}
                <code>127.0.0.1</code>. Hãy mở{' '}
                <a href={localhostUrl} className="font-semibold text-[#E31C5F] underline break-all">
                  {localhostUrl}
                </a>{' '}
                rồi bấm nút đăng ký bên dưới.
              </p>
            </output>
          )}

          <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row sm:items-end gap-3">
            <div className="flex-1 min-w-0 space-y-1.5">
              <label
                htmlFor="sessions-passkey-label"
                className="block text-xs font-semibold text-[#222222]"
              >
                Tên gợi nhớ thiết bị / khóa bảo mật
              </label>
              <Input
                id="sessions-passkey-label"
                name="passkeyLabel"
                type="text"
                maxLength={80}
                disabled={isRegistering}
                value={deviceLabel}
                onChange={(e) => setDeviceLabel(e.target.value)}
                placeholder="VD: Windows Hello Laptop, khóa USB văn phòng…"
                className="bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#717171] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20"
              />
            </div>

            <button
              type="submit"
              disabled={isRegistering}
              className="min-h-11 sm:h-10 shrink-0 rounded-full border border-[#222222] bg-[#222222] px-5 py-2 text-xs font-semibold text-[#ffffff] hover:opacity-90 transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {isRegistering ? (
                <>
                  <div className="h-4 w-4 rounded-full border-2 border-[#ffffff]/30 border-t-[#ffffff] animate-spin" />
                  <span>Đang xác nhận thiết bị…</span>
                </>
              ) : (
                <>
                  <Fingerprint
                    size={16}
                    strokeWidth={2}
                    className="text-[#ffffff]"
                    aria-hidden="true"
                  />
                  <span>Đăng ký khóa bảo mật / Passkey</span>
                </>
              )}
            </button>
          </form>
        </CardContent>
      </Card>

      <Dialog
        open={Boolean(recoveryCodes)}
        onOpenChange={(open) => {
          if (!open) setRecoveryCodes(null);
        }}
      >
        <DialogContent className="max-w-lg max-h-[88vh] overflow-y-auto border-[#ebebeb] bg-[#ffffff] text-[#222222]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base font-bold text-[#222222]">
              <ShieldCheck
                size={20}
                strokeWidth={1.75}
                className="text-[#008A05] shrink-0"
                aria-hidden="true"
              />
              <span>Lưu 10 mã khôi phục khẩn cấp mới</span>
            </DialogTitle>
            <DialogDescription className="text-xs text-[#717171]">
              Khóa bảo mật / Passkey đã được kích hoạt. Hãy sao lưu bộ 10 mã dùng một lần dưới đây
              để dự phòng khi thay đổi thiết bị — mã sẽ không hiển thị lại sau khi đóng hộp thoại.
            </DialogDescription>
          </DialogHeader>

          {recoveryCodes && (
            <div className="space-y-3 py-1">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 font-mono text-xs font-semibold text-[#222222]">
                {recoveryCodes.map((code) => (
                  <div
                    key={code}
                    className="min-w-0 break-all rounded-[12px] bg-[#ffffff] border border-[#ebebeb] px-3 py-2 text-center leading-snug tracking-tight select-all"
                  >
                    {code}
                  </div>
                ))}
              </div>

              <button
                type="button"
                onClick={() => void handleCopyAllCodes()}
                className="w-full min-h-11 rounded-full border border-[#dddddd] bg-[#ffffff] hover:bg-[#f7f7f7] px-4 py-2 text-xs font-semibold text-[#222222] flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
              >
                {copiedRecovery ? (
                  <Check size={16} strokeWidth={2} className="text-[#008A05]" aria-hidden="true" />
                ) : (
                  <Copy size={16} strokeWidth={1.75} aria-hidden="true" />
                )}
                <span>
                  {copiedRecovery ? 'Đã sao chép toàn bộ 10 mã' : 'Sao chép tất cả mã khôi phục'}
                </span>
              </button>
            </div>
          )}

          <DialogFooter>
            <InteractiveHoverButton
              type="button"
              variant="primary"
              size="sm"
              text="Tôi đã lưu mã khôi phục"
              onClick={() => setRecoveryCodes(null)}
            />
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

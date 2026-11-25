'use client';

/**
 * Thuật toán: Quản Lý Danh Sách Nhân Tố MFA (TOTP / Passkey), Thiết Lập TOTP & Tắt MFA Có Xác Minh Hai Yếu Tố (`MfaFactorsCard`)
 * Mục đích:
 *   - Kết nối đầy đủ `GET /auth/mfa/methods`, `DELETE /auth/mfa/methods/:id` và `DELETE /auth/mfa` để người xem (`DOCUMENT_READER`) chủ động bật/gỡ TOTP hoặc Passkey mà không bị kẹt khi truy cập tài liệu `TOP_SECRET` (`V-09`, `V-48`).
 *   - Đảm bảo mọi hộp thoại xác nhận dùng `<dialog>.showModal()` chuẩn WCAG 2.1 AA, không để lộ bí mật MFA.
 */
import { useCallback, useEffect, useState, type FormEvent } from 'react';
import {
  AlertCircle,
  Fingerprint,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Smartphone,
  Trash2,
} from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
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
import { formatSessionTimestamp } from './session-device.helper';

export interface ActiveMfaMethodItem {
  id: string;
  methodType: 'TOTP' | 'WEBAUTHN';
  label: string;
  createdAt: string;
}

interface MfaMethodsResponse {
  data?: ActiveMfaMethodItem[];
  canDisableMfa?: boolean;
}

export interface MfaFactorsCardProps {
  mfaVerified?: boolean | undefined;
  refreshTrigger?: number | undefined;
  onSuccess: (message: string) => void;
  onError: (message: string) => void;
  onAllMfaDisabled: () => Promise<void>;
}

export function MfaFactorsCard({
  mfaVerified,
  refreshTrigger = 0,
  onSuccess,
  onError,
  onAllMfaDisabled,
}: MfaFactorsCardProps) {
  const [methods, setMethods] = useState<ActiveMfaMethodItem[]>([]);
  const [canDisableMfa, setCanDisableMfa] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [removingId, setRemovingId] = useState<string | null>(null);
  const [confirmRemoveTarget, setConfirmRemoveTarget] = useState<ActiveMfaMethodItem | null>(null);

  const [disableDialogOpen, setDisableDialogOpen] = useState(false);
  const [disablePassword, setDisablePassword] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [disableError, setDisableError] = useState<string | null>(null);
  const [isDisabling, setIsDisabling] = useState(false);

  const loadMethods = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await apiClient<MfaMethodsResponse>('/auth/mfa/methods');
      setMethods(Array.isArray(res?.data) ? res.data : []);
      setCanDisableMfa(Boolean(res?.canDisableMfa));
    } catch {
      setMethods([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    let ignore = false;
    void Promise.resolve().then(() => {
      if (!ignore) void loadMethods();
    });
    return () => {
      ignore = true;
    };
  }, [loadMethods, refreshTrigger]);

  async function handleConfirmRemoveMethod(target: ActiveMfaMethodItem) {
    setConfirmRemoveTarget(null);
    setRemovingId(target.id);
    try {
      await apiClient(`/auth/mfa/methods/${encodeURIComponent(target.id)}`, { method: 'DELETE' });
      setMethods((prev) => prev.filter((item) => item.id !== target.id));
      onSuccess(`Đã gỡ phương thức xác thực "${target.label}" khỏi tài khoản.`);
    } catch (err) {
      onError(
        err instanceof ApiError && err.message
          ? err.message
          : 'Không thể gỡ phương thức xác thực này.',
      );
    } finally {
      setRemovingId(null);
    }
  }

  async function handleDisableAllMfa(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setDisableError(null);
    const trimmedCode = disableCode.trim();
    if (!disablePassword) {
      setDisableError('Vui lòng nhập mật khẩu hiện tại.');
      return;
    }
    const isTotp = /^\d{6}$/.test(trimmedCode);
    const isRecovery = trimmedCode.length >= 16;
    if (!isTotp && !isRecovery) {
      setDisableError('Nhập mã TOTP 6 chữ số hoặc mã khôi phục khẩn cấp (tối thiểu 16 ký tự).');
      return;
    }

    setIsDisabling(true);
    try {
      await apiClient('/auth/mfa', {
        method: 'DELETE',
        body: JSON.stringify({
          currentPassword: disablePassword,
          ...(isTotp ? { code: trimmedCode } : { recoveryCode: trimmedCode }),
        }),
      });
      setDisableDialogOpen(false);
      setDisablePassword('');
      setDisableCode('');
      await onAllMfaDisabled();
    } catch (err) {
      setDisableError(
        err instanceof ApiError && err.message
          ? err.message
          : 'Không thể tắt MFA. Kiểm tra lại mật khẩu và mã xác thực.',
      );
    } finally {
      setIsDisabling(false);
    }
  }

  const hasTotp = methods.some((m) => m.methodType === 'TOTP');
  const hasAnyMfa = methods.length > 0;

  return (
    <>
      <Card id="bao-mat-mfa">
        <CardHeader className="pb-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <ShieldCheck
                size={20}
                strokeWidth={1.75}
                className="text-[#008A05] shrink-0"
                aria-hidden="true"
              />
              <CardTitle className="text-sm font-bold text-[#222222]">
                Phương thức xác thực đa yếu tố (MFA)
              </CardTitle>
            </div>
            <Badge variant={hasAnyMfa ? 'success' : 'warning'}>
              {hasAnyMfa ? `Đang bật (${methods.length} phương thức)` : 'Chưa kích hoạt'}
            </Badge>
          </div>
          <CardDescription className="text-xs text-[#717171]">
            Quản lý ứng dụng tạo mã TOTP (6 chữ số) và khóa bảo mật / Passkey để đáp ứng yêu cầu xác
            thực tăng cường khi xem hoặc tải tài liệu Tuyệt mật.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-3.5 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            {!hasTotp && (
              <InteractiveHoverButton
                href="/mfa?enroll=1&method=totp&redirect=/sessions"
                variant="primary"
                size="sm"
                icon={<Smartphone size={16} strokeWidth={1.75} aria-hidden="true" />}
                text="Thiết lập TOTP (6 số)"
                className="w-full sm:w-auto"
              />
            )}
            {hasAnyMfa && !mfaVerified && (
              <InteractiveHoverButton
                href="/mfa?redirect=/sessions"
                variant="primary"
                size="sm"
                icon={<KeyRound size={16} strokeWidth={1.75} aria-hidden="true" />}
                text="Xác thực bước 2 cho phiên này"
                className="w-full sm:w-auto"
              />
            )}
            {canDisableMfa && hasAnyMfa && (
              <InteractiveHoverButton
                type="button"
                variant="danger"
                size="sm"
                icon={<ShieldOff size={16} strokeWidth={1.75} aria-hidden="true" />}
                text="Tắt toàn bộ MFA"
                onClick={() => {
                  setDisableError(null);
                  setDisableDialogOpen(true);
                }}
                className="w-full sm:w-auto"
              />
            )}
            <InteractiveHoverButton
              type="button"
              variant="secondary"
              size="sm"
              isLoading={isLoading}
              disabled={isLoading}
              icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
              text="Làm mới"
              onClick={() => void loadMethods()}
              className="w-full sm:w-auto"
            />
          </div>

          {isLoading && methods.length === 0 ? (
            <div className="py-4 text-center text-xs text-[#717171]">
              Đang kiểm tra các phương thức MFA đã kích hoạt…
            </div>
          ) : methods.length === 0 ? (
            <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 text-xs text-[#717171] leading-relaxed">
              Tài khoản chưa kích hoạt MFA. Bạn có thể bấm{' '}
              <strong className="text-[#222222]">Thiết lập TOTP (6 số)</strong> ở trên hoặc đăng ký{' '}
              <strong className="text-[#222222]">Khóa bảo mật / Passkey</strong> ngay bên dưới.
            </div>
          ) : (
            <div className="space-y-2">
              {methods.map((method) => {
                const isLastMethod = methods.length <= 1;
                const canRemoveSingle = !isLastMethod;
                return (
                  <div
                    key={method.id}
                    className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3"
                  >
                    <div className="flex items-start gap-2.5 min-w-0">
                      {method.methodType === 'WEBAUTHN' ? (
                        <Fingerprint
                          size={20}
                          strokeWidth={1.75}
                          className="shrink-0 text-[#E31C5F] mt-0.5"
                          aria-hidden="true"
                        />
                      ) : (
                        <Smartphone
                          size={20}
                          strokeWidth={1.75}
                          className="shrink-0 text-[#008489] mt-0.5"
                          aria-hidden="true"
                        />
                      )}
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-bold text-[#222222] break-words">
                            {method.label}
                          </span>
                          <Badge variant={method.methodType === 'WEBAUTHN' ? 'info' : 'success'}>
                            {method.methodType === 'WEBAUTHN' ? 'Passkey / FIDO2' : 'TOTP 6 số'}
                          </Badge>
                        </div>
                        <div className="text-xs text-[#717171] mt-0.5">
                          Kích hoạt: {formatSessionTimestamp(method.createdAt)}
                        </div>
                      </div>
                    </div>

                    {canRemoveSingle ? (
                      <InteractiveHoverButton
                        type="button"
                        variant="secondary"
                        size="sm"
                        isLoading={removingId === method.id}
                        disabled={Boolean(removingId)}
                        icon={<Trash2 size={16} strokeWidth={1.75} aria-hidden="true" />}
                        text="Gỡ bỏ"
                        onClick={() => setConfirmRemoveTarget(method)}
                        className="w-full sm:w-auto shrink-0"
                      />
                    ) : (
                      <span className="text-xs text-[#717171] shrink-0">
                        {canDisableMfa
                          ? 'Dùng "Tắt toàn bộ MFA" để gỡ'
                          : 'Bắt buộc theo chính sách vai trò'}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={Boolean(confirmRemoveTarget)}
        onOpenChange={(open) => {
          if (!open) setConfirmRemoveTarget(null);
        }}
        title="Gỡ phương thức xác thực MFA"
        description={
          confirmRemoveTarget
            ? `Bạn có chắc chắn muốn gỡ phương thức "${confirmRemoveTarget.label}" khỏi tài khoản? Các phương thức MFA còn lại vẫn hoạt động bình thường.`
            : ''
        }
        confirmText="Gỡ phương thức"
        cancelText="Giữ nguyên"
        variant="danger"
        isLoading={Boolean(confirmRemoveTarget && removingId === confirmRemoveTarget.id)}
        onConfirm={() => {
          if (confirmRemoveTarget) {
            void handleConfirmRemoveMethod(confirmRemoveTarget);
          }
        }}
      />

      <Dialog
        open={disableDialogOpen}
        onOpenChange={(open) => {
          setDisableDialogOpen(open);
          if (!open) {
            setDisablePassword('');
            setDisableCode('');
            setDisableError(null);
          }
        }}
      >
        <DialogContent
          showContextError={false}
          className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]"
        >
          <DialogHeader>
            <DialogTitle className="text-base font-bold text-[#C13515]">
              Xác nhận tắt toàn bộ MFA
            </DialogTitle>
            <DialogDescription className="text-xs text-[#717171]">
              Sau khi tắt MFA, toàn bộ phiên đăng nhập sẽ bị đăng xuất và bạn sẽ không thể mở các
              tài liệu yêu cầu xác thực tăng cường (như tài liệu Tuyệt mật).
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleDisableAllMfa} className="space-y-3.5">
            {disableError && (
              <Alert variant="destructive" className="text-xs">
                <AlertCircle size={16} strokeWidth={1.75} aria-hidden="true" />
                <AlertDescription className="ml-2">{disableError}</AlertDescription>
              </Alert>
            )}

            <div className="space-y-1.5">
              <label
                htmlFor="disable-mfa-password"
                className="block text-xs font-semibold text-[#222222]"
              >
                Mật khẩu hiện tại
              </label>
              <Input
                id="disable-mfa-password"
                type="password"
                autoComplete="current-password"
                disabled={isDisabling}
                value={disablePassword}
                onChange={(e) => setDisablePassword(e.target.value)}
                placeholder="Nhập mật khẩu hiện tại"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="disable-mfa-code"
                className="block text-xs font-semibold text-[#222222]"
              >
                Mã TOTP 6 chữ số hoặc mã khôi phục khẩn cấp
              </label>
              <Input
                id="disable-mfa-code"
                type="text"
                autoComplete="one-time-code"
                disabled={isDisabling}
                value={disableCode}
                onChange={(e) => setDisableCode(e.target.value)}
                placeholder="123456 hoặc mã khôi phục"
              />
            </div>

            <DialogFooter>
              <InteractiveHoverButton
                type="button"
                variant="secondary"
                size="sm"
                text="Hủy"
                disabled={isDisabling}
                onClick={() => setDisableDialogOpen(false)}
              />
              <InteractiveHoverButton
                type="submit"
                variant="danger"
                size="sm"
                isLoading={isDisabling}
                disabled={isDisabling}
                text="Xác nhận tắt MFA"
              />
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}

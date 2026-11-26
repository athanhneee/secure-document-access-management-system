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
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { CollapsibleCard } from '@/components/ui/collapsible-card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { HandwritingText } from '@/components/ui/handwriting-text';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { formatSessionTimestamp } from './session-device.helper';

const MFA_CARD_DESCRIPTION =
  'Quản lý ứng dụng tạo mã TOTP (6 chữ số) và khóa bảo mật / Passkey để đáp ứng yêu cầu xác thực tăng cường khi xem hoặc tải tài liệu Tuyệt mật.';

const MFA_EMPTY_SEGMENTS = [
  { text: 'Tài khoản chưa kích hoạt MFA. Bạn có thể bấm ' },
  { text: 'Thiết lập TOTP (6 số)', strong: true },
  { text: ' ở trên hoặc đăng ký ' },
  { text: 'Khóa bảo mật / Passkey', strong: true },
  { text: ' ngay bên dưới.' },
] as const;

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
  onError?: ((message: string) => void) | undefined;
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
  const [loadFailed, setLoadFailed] = useState(false);
  const [removingId, setRemovingId] = useState<string | null>(null);
  const [confirmRemoveTarget, setConfirmRemoveTarget] = useState<ActiveMfaMethodItem | null>(null);
  const [removePassword, setRemovePassword] = useState('');
  const [removeCode, setRemoveCode] = useState('');
  const [removeError, setRemoveError] = useState<string | null>(null);

  const [isCardOpen, setIsCardOpen] = useState(false);

  const [disableDialogOpen, setDisableDialogOpen] = useState(false);
  const [disablePassword, setDisablePassword] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [disableError, setDisableError] = useState<string | null>(null);
  const [isDisabling, setIsDisabling] = useState(false);

  useEffect(() => {
    let ignore = false;
    void Promise.resolve().then(() => {
      if (!ignore && typeof window !== 'undefined' && window.location.hash === '#bao-mat-mfa') {
        setIsCardOpen(true);
      }
    });
    return () => {
      ignore = true;
    };
  }, []);

  const loadMethods = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await apiClient<MfaMethodsResponse>('/auth/mfa/methods');
      setMethods(Array.isArray(res?.data) ? res.data : []);
      setCanDisableMfa(Boolean(res?.canDisableMfa));
      setLoadFailed(false);
    } catch (err) {
      setLoadFailed(true);
      onError?.(
        err instanceof ApiError && err.message
          ? err.message
          : 'Không thể tải danh sách phương thức MFA. Vui lòng thử làm mới lại.',
      );
    } finally {
      setIsLoading(false);
    }
  }, [onError]);

  useEffect(() => {
    let ignore = false;
    void Promise.resolve().then(() => {
      if (!ignore) void loadMethods();
    });
    return () => {
      ignore = true;
    };
  }, [loadMethods, refreshTrigger]);

  async function handleConfirmRemoveMethod(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!confirmRemoveTarget) return;
    setRemoveError(null);

    const trimmedCode = removeCode.trim();
    if (!removePassword) {
      setRemoveError('Vui lòng nhập mật khẩu hiện tại.');
      return;
    }
    const isTotp = /^\d{6}$/.test(trimmedCode);
    const isRecovery = trimmedCode.length >= 16 && trimmedCode.length <= 64;
    if (!isTotp && !isRecovery) {
      setRemoveError(
        'Nhập mã TOTP 6 chữ số hoặc mã khôi phục khẩn cấp (16–64 ký tự, phân biệt chữ HOA/thường).',
      );
      return;
    }

    const target = confirmRemoveTarget;
    setRemovingId(target.id);
    try {
      await apiClient(`/auth/mfa/methods/${encodeURIComponent(target.id)}`, {
        method: 'DELETE',
        body: JSON.stringify({
          currentPassword: removePassword,
          ...(isTotp ? { code: trimmedCode } : { recoveryCode: trimmedCode }),
        }),
      });
      const nextMethods = methods.filter((item) => item.id !== target.id);
      setMethods(nextMethods);
      setConfirmRemoveTarget(null);
      setRemovePassword('');
      setRemoveCode('');
      setRemoveError(null);
      if (nextMethods.length === 0) {
        await onAllMfaDisabled();
      } else {
        onSuccess(`Đã gỡ phương thức xác thực "${target.label}" khỏi tài khoản.`);
      }
    } catch (err) {
      const rawBackendMsg =
        err instanceof ApiError && typeof err.response?.message === 'string'
          ? err.response.message.toLowerCase()
          : '';
      setRemoveError(
        err instanceof ApiError &&
          err.status === 401 &&
          rawBackendMsg.includes('step-up authentication failed')
          ? 'Mật khẩu hiện tại hoặc mã MFA / mã khôi phục không chính xác. Vui lòng kiểm tra và thử lại.'
          : err instanceof ApiError && err.message
            ? err.message
            : 'Không thể gỡ phương thức xác thực này. Kiểm tra lại mật khẩu và mã xác thực.',
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
    const isRecovery = trimmedCode.length >= 16 && trimmedCode.length <= 64;
    if (!isTotp && !isRecovery) {
      setDisableError(
        'Nhập mã TOTP 6 chữ số hoặc mã khôi phục khẩn cấp (16–64 ký tự, phân biệt chữ HOA/thường).',
      );
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
      const rawBackendMsg =
        err instanceof ApiError && typeof err.response?.message === 'string'
          ? err.response.message.toLowerCase()
          : '';
      setDisableError(
        err instanceof ApiError &&
          err.status === 401 &&
          rawBackendMsg.includes('step-up authentication failed')
          ? 'Mật khẩu hiện tại hoặc mã MFA / mã khôi phục không chính xác. Vui lòng kiểm tra và thử lại.'
          : err instanceof ApiError && err.message
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
      <CollapsibleCard
        id="bao-mat-mfa"
        open={isCardOpen}
        onOpenChange={setIsCardOpen}
        icon={
          <ShieldCheck
            size={20}
            strokeWidth={1.75}
            className="text-[#008A05] shrink-0"
            aria-hidden="true"
          />
        }
        title="Phương thức xác thực đa yếu tố (MFA)"
        badge={
          <Badge
            variant={loadFailed && !hasAnyMfa ? 'destructive' : hasAnyMfa ? 'success' : 'warning'}
          >
            {loadFailed && !hasAnyMfa
              ? 'Không thể tải trạng thái'
              : hasAnyMfa
                ? `Đang bật (${methods.length} phương thức)`
                : 'Chưa kích hoạt'}
          </Badge>
        }
        contentClassName="space-y-3.5 text-xs"
      >
        {({ isOpen, revealKey }) => (
          <>
            <p className="text-xs text-[#717171] leading-relaxed">
              <HandwritingText
                key={`mfa-desc-${revealKey}`}
                text={MFA_CARD_DESCRIPTION}
                active={isOpen}
                startDelayMs={80}
                charIntervalMs={18}
                maxDurationMs={1400}
              />
            </p>

            <div
              className={cn(
                'space-y-3.5 transition-all duration-300 ease-[cubic-bezier(0.16,1,0.3,1)]',
                isOpen ? 'translate-y-0 opacity-100 delay-75' : 'translate-y-1.5 opacity-0',
              )}
            >
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
              ) : loadFailed && methods.length === 0 ? (
                <Alert variant="destructive" className="text-xs">
                  <AlertCircle
                    size={16}
                    strokeWidth={1.75}
                    className="shrink-0"
                    aria-hidden="true"
                  />
                  <AlertDescription className="ml-2">
                    Không thể tải danh sách phương thức MFA từ máy chủ. Hãy nhấn nút &ldquo;Làm
                    mới&rdquo; để kiểm tra lại.
                  </AlertDescription>
                </Alert>
              ) : methods.length === 0 ? (
                <p className="text-xs text-[#717171] leading-relaxed">
                  <HandwritingText
                    key={`mfa-empty-${revealKey}`}
                    segments={MFA_EMPTY_SEGMENTS}
                    active={isOpen}
                    startDelayMs={420}
                    charIntervalMs={18}
                    maxDurationMs={1350}
                  />
                </p>
              ) : (
                <div className="divide-y divide-[#ebebeb]">
                  {methods.map((method) => {
                    const isLastMethod = methods.length <= 1;
                    const canRemoveSingle = !isLastMethod;
                    return (
                      <div
                        key={method.id}
                        className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 py-3 first:pt-1 last:pb-0"
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
                              <Badge
                                variant={method.methodType === 'WEBAUTHN' ? 'info' : 'success'}
                              >
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
                            onClick={() => {
                              setRemovePassword('');
                              setRemoveCode('');
                              setRemoveError(null);
                              setConfirmRemoveTarget(method);
                            }}
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
            </div>
          </>
        )}
      </CollapsibleCard>

      <Dialog
        open={Boolean(confirmRemoveTarget)}
        onOpenChange={(open) => {
          if (!open && !removingId) {
            setConfirmRemoveTarget(null);
            setRemovePassword('');
            setRemoveCode('');
            setRemoveError(null);
          }
        }}
      >
        <DialogContent
          showContextError={false}
          className="max-w-md border-[#ebebeb] bg-[#ffffff] text-[#222222]"
        >
          <DialogHeader>
            <DialogTitle className="text-base font-bold text-[#C13515]">
              Xác nhận gỡ phương thức xác thực MFA
            </DialogTitle>
            <DialogDescription className="text-xs text-[#717171]">
              {confirmRemoveTarget
                ? `Nhập mật khẩu hiện tại và mã xác thực MFA đang hoạt động để gỡ phương thức "${confirmRemoveTarget.label}" khỏi tài khoản. Các phương thức MFA còn lại vẫn hoạt động bình thường.`
                : ''}
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleConfirmRemoveMethod} noValidate className="space-y-3.5">
            {removeError && (
              <Alert variant="destructive" className="text-xs">
                <AlertCircle size={16} strokeWidth={1.75} aria-hidden="true" />
                <AlertDescription className="ml-2">{removeError}</AlertDescription>
              </Alert>
            )}

            <div className="space-y-1.5">
              <label
                htmlFor="remove-mfa-password"
                className="block text-xs font-semibold text-[#222222]"
              >
                Mật khẩu hiện tại
              </label>
              <Input
                id="remove-mfa-password"
                type="password"
                autoComplete="current-password"
                disabled={Boolean(removingId)}
                value={removePassword}
                onChange={(e) => setRemovePassword(e.target.value)}
                placeholder="Nhập mật khẩu hiện tại"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="remove-mfa-code"
                className="block text-xs font-semibold text-[#222222]"
              >
                Mã TOTP 6 chữ số hoặc mã khôi phục khẩn cấp
              </label>
              <Input
                id="remove-mfa-code"
                type="text"
                autoComplete="one-time-code"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                maxLength={64}
                disabled={Boolean(removingId)}
                value={removeCode}
                onChange={(e) => setRemoveCode(e.target.value)}
                placeholder="123456 hoặc mã khôi phục (phân biệt hoa/thường)"
                className="font-mono"
              />
            </div>

            <DialogFooter>
              <InteractiveHoverButton
                type="button"
                variant="secondary"
                size="sm"
                text="Giữ nguyên"
                disabled={Boolean(removingId)}
                onClick={() => setConfirmRemoveTarget(null)}
              />
              <InteractiveHoverButton
                type="submit"
                variant="danger"
                size="sm"
                isLoading={Boolean(confirmRemoveTarget && removingId === confirmRemoveTarget.id)}
                disabled={Boolean(removingId)}
                text="Xác nhận gỡ phương thức"
              />
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog
        open={disableDialogOpen}
        onOpenChange={(open) => {
          if (!open && isDisabling) return;
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

          <form onSubmit={handleDisableAllMfa} noValidate className="space-y-3.5">
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
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                maxLength={64}
                disabled={isDisabling}
                value={disableCode}
                onChange={(e) => setDisableCode(e.target.value)}
                placeholder="123456 hoặc mã khôi phục (phân biệt hoa/thường)"
                className="font-mono"
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

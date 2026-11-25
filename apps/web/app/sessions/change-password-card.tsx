'use client';

/**
 * Thuật toán: Thẻ Tự Đổi Mật Khẩu Chuẩn NIST SP 800-63B Trong Không Gian `/sessions` (`ChangePasswordCard`, V-48)
 * Mục đích:
 *   - Kết nối trực tiếp `POST /api/v1/auth/change-password` để mọi người dùng (bao gồm `DOCUMENT_READER`) tự đổi mật khẩu an toàn mà không cần quản trị viên.
 *   - Kiểm tra độ dài 15–128 ký tự khớp chính xác `PasswordService` của máy chủ, hỗ trợ nút Hiện/Ẩn chuẩn WCAG (`44x44px`) và tự chuyển về `/login` sau khi máy chủ thu hồi phiên cũ.
 */
import { useState, type FormEvent } from 'react';
import { Eye, EyeOff, KeyRound, Lock } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { evaluatePasswordStrength } from '@/app/reset-password/password-strength';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

export interface ChangePasswordCardProps {
  onPasswordChanged: () => Promise<void>;
  onError: (message: string) => void;
}

export function ChangePasswordCard({ onPasswordChanged, onError }: ChangePasswordCardProps) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const strength = evaluatePasswordStrength(newPassword);

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!currentPassword) {
      onError('Vui lòng nhập mật khẩu hiện tại.');
      return;
    }
    if (newPassword.length < 15 || newPassword.length > 128) {
      onError('Mật khẩu mới phải có độ dài từ 15 đến 128 ký tự theo chính sách bảo mật.');
      return;
    }
    if (newPassword === currentPassword) {
      onError('Mật khẩu mới không được trùng với mật khẩu hiện tại.');
      return;
    }
    if (newPassword !== confirmPassword) {
      onError('Mật khẩu xác nhận không khớp với mật khẩu mới.');
      return;
    }

    setIsSubmitting(true);
    try {
      await apiClient('/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      await onPasswordChanged();
    } catch (err) {
      onError(
        err instanceof ApiError && err.message
          ? err.message
          : 'Không thể đổi mật khẩu. Vui lòng kiểm tra lại mật khẩu hiện tại.',
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <KeyRound
            size={20}
            strokeWidth={1.75}
            className="text-[#FF385C] shrink-0"
            aria-hidden="true"
          />
          <CardTitle className="text-sm font-bold text-[#222222]">Đổi mật khẩu tài khoản</CardTitle>
        </div>
        <CardDescription className="text-xs text-[#717171]">
          Mật khẩu mới yêu cầu độ dài từ 15 đến 128 ký tự, không trùng mật khẩu cũ và không chứa tên
          đăng nhập hoặc email. Sau khi đổi, mọi phiên trên các thiết bị sẽ tự động đăng xuất để bảo
          vệ tài khoản.
        </CardDescription>
      </CardHeader>

      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-3.5 text-xs">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="space-y-1.5">
              <label
                htmlFor="change-pw-current"
                className="block text-xs font-semibold text-[#222222]"
              >
                Mật khẩu hiện tại
              </label>
              <div className="relative">
                <Input
                  id="change-pw-current"
                  type={showCurrent ? 'text' : 'password'}
                  autoComplete="current-password"
                  disabled={isSubmitting}
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  placeholder="Nhập mật khẩu hiện tại"
                  className="pr-11"
                />
                <button
                  type="button"
                  disabled={isSubmitting}
                  onClick={() => setShowCurrent((prev) => !prev)}
                  aria-label={showCurrent ? 'Ẩn mật khẩu hiện tại' : 'Hiện mật khẩu hiện tại'}
                  className="absolute inset-y-0 right-0 flex w-11 items-center justify-center rounded-r-full text-[#717171] hover:text-[#222222] cursor-pointer"
                >
                  {showCurrent ? (
                    <EyeOff size={16} strokeWidth={1.75} aria-hidden="true" />
                  ) : (
                    <Eye size={16} strokeWidth={1.75} aria-hidden="true" />
                  )}
                </button>
              </div>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="change-pw-new" className="block text-xs font-semibold text-[#222222]">
                Mật khẩu mới (tối thiểu 15 ký tự)
              </label>
              <div className="relative">
                <Input
                  id="change-pw-new"
                  type={showNew ? 'text' : 'password'}
                  autoComplete="new-password"
                  minLength={15}
                  maxLength={128}
                  disabled={isSubmitting}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Tối thiểu 15 ký tự"
                  className="pr-11"
                />
                <button
                  type="button"
                  disabled={isSubmitting}
                  onClick={() => setShowNew((prev) => !prev)}
                  aria-label={showNew ? 'Ẩn mật khẩu mới' : 'Hiện mật khẩu mới'}
                  className="absolute inset-y-0 right-0 flex w-11 items-center justify-center rounded-r-full text-[#717171] hover:text-[#222222] cursor-pointer"
                >
                  {showNew ? (
                    <EyeOff size={16} strokeWidth={1.75} aria-hidden="true" />
                  ) : (
                    <Eye size={16} strokeWidth={1.75} aria-hidden="true" />
                  )}
                </button>
              </div>
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="change-pw-confirm"
                className="block text-xs font-semibold text-[#222222]"
              >
                Xác nhận mật khẩu mới
              </label>
              <div className="relative">
                <Input
                  id="change-pw-confirm"
                  type={showConfirm ? 'text' : 'password'}
                  autoComplete="new-password"
                  minLength={15}
                  maxLength={128}
                  disabled={isSubmitting}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Nhập lại mật khẩu mới"
                  className="pr-11"
                />
                <button
                  type="button"
                  disabled={isSubmitting}
                  onClick={() => setShowConfirm((prev) => !prev)}
                  aria-label={showConfirm ? 'Ẩn mật khẩu xác nhận' : 'Hiện mật khẩu xác nhận'}
                  className="absolute inset-y-0 right-0 flex w-11 items-center justify-center rounded-r-full text-[#717171] hover:text-[#222222] cursor-pointer"
                >
                  {showConfirm ? (
                    <EyeOff size={16} strokeWidth={1.75} aria-hidden="true" />
                  ) : (
                    <Eye size={16} strokeWidth={1.75} aria-hidden="true" />
                  )}
                </button>
              </div>
            </div>
          </div>

          {newPassword && (
            <div className="space-y-1">
              <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-[#ebebeb]">
                <div className={`h-full transition-all ${strength.barClassName}`} />
              </div>
              <p className="text-xs text-[#717171]">
                Độ dài: {newPassword.length}/15+ ký tự · Độ mạnh gợi ý: {strength.strengthLabel}
              </p>
            </div>
          )}

          <div className="flex justify-end">
            <InteractiveHoverButton
              type="submit"
              variant="primary"
              size="sm"
              isLoading={isSubmitting}
              disabled={
                isSubmitting || !currentPassword || newPassword.length < 15 || !confirmPassword
              }
              icon={<Lock size={16} strokeWidth={1.75} aria-hidden="true" />}
              text="Cập nhật mật khẩu"
              className="w-full sm:w-auto"
            />
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

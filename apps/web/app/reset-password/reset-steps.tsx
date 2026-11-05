'use client';

import type { FormEvent } from 'react';
import { Lock, Mail, ShieldCheck, CheckCircle2 } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Input } from '@/components/ui/input';
import { evaluatePasswordStrength } from './password-strength';

interface ForgotStepProps {
  identifier: string;
  isLoading: boolean;
  disabled: boolean;
  onChangeIdentifier: (val: string) => void;
  onSubmit: (e: FormEvent<HTMLFormElement>) => void;
}

export function ForgotPasswordStepForm({
  identifier,
  isLoading,
  disabled,
  onChangeIdentifier,
  onSubmit,
}: ForgotStepProps) {
  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <div className="space-y-1.5">
        <label htmlFor="identifier" className="block text-xs font-semibold text-[#222222]">
          Tên đăng nhập hoặc Email
        </label>
        <div className="relative">
          <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-[#717171]">
            <Mail size={16} strokeWidth={1.75} aria-hidden="true" />
          </div>
          <Input
            id="identifier"
            name="identifier"
            type="text"
            disabled={disabled}
            value={identifier}
            onChange={(e) => onChangeIdentifier(e.target.value)}
            placeholder="nguyenvana hoặc email nội bộ"
            className="pl-10 bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
          />
        </div>
      </div>

      <InteractiveHoverButton
        type="submit"
        disabled={disabled}
        isLoading={isLoading}
        text="Gửi liên kết khôi phục"
        className="w-full py-2.5 text-xs font-semibold"
      />
    </form>
  );
}

interface ConfirmResetStepProps {
  newPassword: string;
  confirmPassword: string;
  isLoading: boolean;
  disabled: boolean;
  onChangeNewPassword: (val: string) => void;
  onChangeConfirmPassword: (val: string) => void;
  onSubmit: (e: FormEvent<HTMLFormElement>) => void;
}

export function ConfirmResetStepForm({
  newPassword,
  confirmPassword,
  isLoading,
  disabled,
  onChangeNewPassword,
  onChangeConfirmPassword,
  onSubmit,
}: ConfirmResetStepProps) {
  const strength = evaluatePasswordStrength(newPassword);
  const requirements = [
    { label: 'Từ 15 ký tự trở lên', met: strength.hasMinLength },
    { label: 'Chữ in hoa & chữ thường', met: strength.hasUpper && strength.hasLower },
    { label: 'Chữ số & ký tự đặc biệt', met: strength.hasNumber && strength.hasSpecial },
  ];

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <div className="space-y-1.5">
        <label htmlFor="new-password" className="block text-xs font-semibold text-[#222222]">
          Mật khẩu mới (Tối thiểu 15 ký tự)
        </label>
        <div className="relative">
          <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-[#717171]">
            <Lock size={16} strokeWidth={1.75} aria-hidden="true" />
          </div>
          <Input
            id="new-password"
            name="newPassword"
            type="password"
            disabled={disabled}
            value={newPassword}
            onChange={(e) => onChangeNewPassword(e.target.value)}
            placeholder="•••••••••••••••"
            className="pl-10 bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
          />
        </div>

        {newPassword && (
          <div className="space-y-1.5 pt-1">
            <div className="flex h-1.5 w-full gap-1 overflow-hidden rounded-full bg-[#ebebeb]">
              <div className={`h-full transition-all ${strength.barClassName}`} />
            </div>
            <p className="text-[10px] text-[#717171]">Độ mạnh: {strength.strengthLabel}</p>
            <div className="grid grid-cols-1 gap-1 pt-0.5">
              {requirements.map((req) => (
                <div
                  key={req.label}
                  className={`flex items-center gap-1.5 text-[10px] ${
                    req.met ? 'text-[#008A05] font-medium' : 'text-[#717171]'
                  }`}
                >
                  <CheckCircle2
                    size={16}
                    strokeWidth={1.75}
                    className="shrink-0"
                    aria-hidden="true"
                  />
                  <span>{req.label}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="space-y-1.5">
        <label htmlFor="confirm-password" className="block text-xs font-semibold text-[#222222]">
          Xác nhận mật khẩu mới
        </label>
        <div className="relative">
          <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-[#717171]">
            <ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />
          </div>
          <Input
            id="confirm-password"
            name="confirmPassword"
            type="password"
            disabled={disabled}
            value={confirmPassword}
            onChange={(e) => onChangeConfirmPassword(e.target.value)}
            placeholder="•••••••••••••••"
            className="pl-10 bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
          />
        </div>
      </div>

      <InteractiveHoverButton
        type="submit"
        disabled={disabled}
        isLoading={isLoading}
        text="Cập nhật mật khẩu mới"
        className="w-full py-2.5 text-xs font-semibold"
      />
    </form>
  );
}

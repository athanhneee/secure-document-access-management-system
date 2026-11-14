'use client';

/**
 * Thuật toán: Biểu Mẫu Nhập Định Danh & Mật Khẩu Kèm Chuyển Đổi Hiển Thị Trợ Năng (`LoginFormFields`)
 * Mục đích: Liên kết tường minh `<label htmlFor>` - `id`, báo lỗi nội dòng qua `aria-describedby` và hỗ trợ nút Hiện/Ẩn mật khẩu (`Eye`/`EyeOff`) đạt vùng chạm chuẩn `44x44px` trên thiết bị di động `375px`.
 */
import { useState, type FormEvent } from 'react';
import Link from 'next/link';
import { Eye, EyeOff, Lock, User } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Input } from '@/components/ui/input';

export interface FormFieldErrors {
  identifier?: string;
  password?: string;
}

interface LoginFormFieldsProps {
  identifier: string;
  password: string;
  isLoading: boolean;
  fieldErrors: FormFieldErrors;
  onChangeIdentifier: (val: string) => void;
  onChangePassword: (val: string) => void;
  onSubmit: (e: FormEvent<HTMLFormElement>) => void;
}

export function LoginFormFields({
  identifier,
  password,
  isLoading,
  fieldErrors,
  onChangeIdentifier,
  onChangePassword,
  onSubmit,
}: LoginFormFieldsProps) {
  const [showPassword, setShowPassword] = useState(false);

  return (
    <form id="login-form" onSubmit={onSubmit} className="space-y-4" noValidate>
      <div className="space-y-1.5">
        <label htmlFor="identifier" className="block text-xs font-semibold text-[#222222]">
          Tên đăng nhập hoặc Email <span className="text-[#C13515]">*</span>
        </label>
        <div className="relative">
          <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-[#717171]">
            <User size={16} strokeWidth={1.75} aria-hidden="true" />
          </div>
          <Input
            id="identifier"
            name="identifier"
            type="text"
            autoComplete="username"
            disabled={isLoading}
            value={identifier}
            onChange={(e) => onChangeIdentifier(e.target.value)}
            placeholder="nguyenvana hoặc email nội bộ"
            className="pl-10 bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
            aria-invalid={Boolean(fieldErrors.identifier)}
            aria-describedby={fieldErrors.identifier ? 'identifier-error' : undefined}
          />
        </div>
        {fieldErrors.identifier && (
          <p id="identifier-error" className="text-xs text-[#C13515] font-medium">
            {fieldErrors.identifier}
          </p>
        )}
      </div>

      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <label htmlFor="password" className="block text-xs font-semibold text-[#222222]">
            Mật khẩu <span className="text-[#C13515]">*</span>
          </label>
          <Link
            href="/reset-password"
            className="text-xs font-medium text-[#E31C5F] hover:underline transition-colors"
          >
            Quên mật khẩu?
          </Link>
        </div>
        <div className="relative">
          <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-[#717171]">
            <Lock size={16} strokeWidth={1.75} aria-hidden="true" />
          </div>
          <Input
            id="password"
            name="password"
            type={showPassword ? 'text' : 'password'}
            autoComplete="current-password"
            disabled={isLoading}
            value={password}
            onChange={(e) => onChangePassword(e.target.value)}
            placeholder="••••••••••••"
            className="pl-10 pr-11 bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
            aria-invalid={Boolean(fieldErrors.password)}
            aria-describedby={fieldErrors.password ? 'password-error' : undefined}
          />
          <button
            type="button"
            disabled={isLoading}
            onClick={() => setShowPassword((prev) => !prev)}
            aria-label={showPassword ? 'Ẩn mật khẩu' : 'Hiện mật khẩu'}
            className="absolute inset-y-0 right-0 flex w-11 items-center justify-center rounded-r-full text-[#717171] hover:text-[#222222] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF385C] disabled:opacity-50 cursor-pointer"
          >
            {showPassword ? (
              <EyeOff size={16} strokeWidth={1.75} aria-hidden="true" />
            ) : (
              <Eye size={16} strokeWidth={1.75} aria-hidden="true" />
            )}
          </button>
        </div>
        {fieldErrors.password && (
          <p id="password-error" className="text-xs text-[#C13515] font-medium">
            {fieldErrors.password}
          </p>
        )}
      </div>

      <InteractiveHoverButton
        type="submit"
        disabled={isLoading}
        isLoading={isLoading}
        text="Đăng nhập hệ thống"
        className="w-full py-2.5 text-xs font-semibold"
      />
    </form>
  );
}

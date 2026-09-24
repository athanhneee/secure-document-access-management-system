'use client';

import { useState, Suspense, type FormEvent } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldCheck, Lock, User, AlertCircle, KeyRound } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Input } from '@/components/ui/input';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';

interface FormFieldErrors {
  identifier?: string;
  password?: string;
}

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectTarget = searchParams.get('redirect') ?? '/';
  const { refreshUser } = useAuth();

  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<FormFieldErrors>({});

  async function handleLogin(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setErrorMessage(null);
    setFieldErrors({});

    const errors: FormFieldErrors = {};
    if (!identifier.trim()) {
      errors.identifier = 'Vui lòng nhập tên đăng nhập hoặc email.';
    }
    if (!password) {
      errors['password'] = 'Vui lòng nhập mật khẩu.';
    }
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }

    setIsLoading(true);

    try {
      const result = await apiClient<{
        authenticated: boolean;
        mfaRequired: boolean;
        enrollmentRequired: boolean;
      }>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ identifier: identifier.trim(), password }),
      });

      if (result.mfaRequired) {
        // MFA verification required
        router.push(`/mfa?redirect=${encodeURIComponent(redirectTarget)}`);
        return;
      }

      // Login successful, refresh authenticated user state
      const user = await refreshUser();
      if (user && user.roles.length > 0) {
        // If there's a specific redirect requested, go there
        if (redirectTarget && redirectTarget !== '/') {
          router.push(redirectTarget);
        } else {
          // Route by primary role
          if (user.roles.includes('SYSTEM_ADMIN')) router.push('/admin');
          else if (user.roles.includes('DOCUMENT_OWNER')) router.push('/owner');
          else if (user.roles.includes('SECURITY_OFFICER')) router.push('/security');
          else if (user.roles.includes('AUDITOR')) router.push('/auditor');
          else router.push('/reader');
        }
      } else {
        router.push(redirectTarget);
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(
          err.message || 'Xác thực không thành công. Vui lòng kiểm tra lại thông tin.',
        );
      } else {
        setErrorMessage('Không thể kết nối đến máy chủ xác thực.');
      }
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="relative flex min-h-screen flex-col items-center justify-center bg-[#f7f7f7] px-4 py-12 antialiased selection:bg-[#FF385C]/15 selection:text-[#FF385C] overflow-hidden">
      {/* Ambient background aura (Light theme compliant) */}
      <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden" aria-hidden="true">
        <div className="absolute -top-32 left-1/2 -translate-x-1/2 w-[600px] h-[400px] rounded-full bg-[#FF385C]/5 blur-3xl animate-float" />
        <div className="absolute -bottom-32 left-1/3 w-[500px] h-[400px] rounded-full bg-[#008489]/5 blur-3xl animate-float delay-200" />
      </div>

      <div className="relative z-10 w-full max-w-md space-y-6">
        {/* Brand identity header */}
        <div className="flex flex-col items-center text-center space-y-2 animate-fade-in-down">
          <Link
            href="/"
            className="inline-flex items-center gap-2 text-[#222222] hover:opacity-90 transition-opacity"
            aria-label="Về trang chủ Secure Document"
          >
            <ShieldCheck
              size={24}
              strokeWidth={1.75}
              className="text-[#FF385C]"
              aria-hidden="true"
            />
            <span className="text-2xl font-bold tracking-tight text-[#222222]">
              Secure<span className="font-light text-[#FF385C]">Document</span>
            </span>
          </Link>
          <p className="text-xs text-[#717171] max-w-xs leading-relaxed">
            <span className="sm:hidden">Quản lý tài liệu mật tổ chức · Zero Trust</span>
            <span className="hidden sm:inline">
              Hệ thống quản lý tài liệu mật tổ chức · Xác thực hai lớp và kiểm soát phiên nghiêm
              ngặt
            </span>
          </p>
        </div>

        <Card className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] shadow-[0_12px_40px_rgba(0,0,0,0.06)] animate-fade-in-up delay-100">
          <CardHeader className="space-y-1 pb-4">
            <CardTitle className="text-lg font-bold text-[#222222]">Đăng nhập tài khoản</CardTitle>
            <CardDescription className="text-xs text-[#717171]">
              <span className="sm:hidden">Nhập định danh & mật khẩu được cấp</span>
              <span className="hidden sm:inline">
                Nhập định danh và mật khẩu được cấp bởi quản trị viên
              </span>
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            {errorMessage && (
              <Alert
                variant="destructive"
                className="rounded-[20px] border border-[#C13515]/30 bg-[#C13515]/10 text-[#C13515] text-xs"
              >
                <AlertCircle className="h-4 w-4 shrink-0 text-[#C13515]" aria-hidden="true" />
                <AlertDescription className="ml-2 leading-relaxed">{errorMessage}</AlertDescription>
              </Alert>
            )}

            <form id="login-form" onSubmit={handleLogin} className="space-y-4" noValidate>
              <div className="space-y-1.5">
                <label htmlFor="identifier" className="block text-xs font-semibold text-[#222222]">
                  Tên đăng nhập hoặc Email <span className="text-[#C13515]">*</span>
                </label>
                <div className="relative">
                  <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-[#717171]">
                    <User className="h-4 w-4" aria-hidden="true" />
                  </div>
                  <Input
                    id="identifier"
                    name="identifier"
                    type="text"
                    autoComplete="username"
                    disabled={isLoading}
                    value={identifier}
                    onChange={(e) => setIdentifier(e.target.value)}
                    placeholder="nguyenvana hoặc email nội bộ"
                    className="pl-10 bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
                    aria-invalid={Boolean(fieldErrors.identifier)}
                    aria-describedby={fieldErrors.identifier ? 'identifier-error' : undefined}
                  />
                </div>
                {fieldErrors.identifier && (
                  <p id="identifier-error" className="text-[11px] text-[#C13515] font-medium">
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
                    className="text-[11px] font-medium text-[#FF385C] hover:underline transition-colors"
                  >
                    Quên mật khẩu?
                  </Link>
                </div>
                <div className="relative">
                  <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-[#717171]">
                    <Lock className="h-4 w-4" aria-hidden="true" />
                  </div>
                  <Input
                    id="password"
                    name="password"
                    type="password"
                    autoComplete="current-password"
                    disabled={isLoading}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="pl-10 bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C] focus-visible:ring-2 focus-visible:ring-[#FF385C]/20 shadow-2xs"
                    aria-invalid={Boolean(fieldErrors.password)}
                    aria-describedby={fieldErrors.password ? 'password-error' : undefined}
                  />
                </div>
                {fieldErrors.password && (
                  <p id="password-error" className="text-[11px] text-[#C13515] font-medium">
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
          </CardContent>

          <CardFooter className="flex flex-col space-y-3 pt-2 border-t border-[#ebebeb] text-center">
            <div className="flex items-center justify-center gap-1.5 text-[11px] text-[#717171]">
              <KeyRound className="h-3.5 w-3.5 text-[#717171]" aria-hidden="true" />
              <span className="sm:hidden">Bảo mật HttpOnly Cookie & CSRF</span>
              <span className="hidden sm:inline">
                Phiên đăng nhập được bảo vệ bằng HttpOnly Cookie và CSRF token
              </span>
            </div>
          </CardFooter>
        </Card>

        {/* Quick Demo Accounts */}
        <div className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] p-4 sm:p-5 space-y-3 shadow-[0_6px_20px_rgba(0,0,0,0.03)] animate-fade-in-up delay-200 hover-card">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#222222]">
              <span className="sm:hidden">Tài khoản Demo</span>
              <span className="hidden sm:inline">Tài khoản kiểm thử nhanh (Demo)</span>
            </span>
            <span className="text-[10px] text-[#717171] font-bold">Nhấp để điền</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {[
              {
                label: 'Quản trị viên',
                user: 'admin.demo',
                dot: 'dot-success',
              },
              {
                label: 'Chủ tài liệu',
                user: 'owner.demo',
                dot: 'dot-warning',
              },
              {
                label: 'Người đọc',
                user: 'reader.demo',
                dot: 'dot-info',
              },
              {
                label: 'An ninh thông tin',
                user: 'security.demo',
                dot: 'dot-danger',
              },
              {
                label: 'Kiểm toán viên',
                user: 'auditor.demo',
                dot: 'dot-neutral',
              },
            ].map((item) => (
              <button
                key={item.user}
                type="button"
                onClick={() => {
                  setIdentifier(item.user);
                  setPassword('DemoPass@123');
                  setFieldErrors({});
                }}
                className="group flex items-center justify-between px-3.5 py-2.5 rounded-full border border-[#ebebeb] bg-[#f7f7f7] hover:border-[#FF385C]/30 hover:bg-[#ffffff] hover:shadow-[0_4px_12px_rgba(0,0,0,0.05)] hover:-translate-y-0.5 active:scale-[0.98] text-xs transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer text-left shadow-2xs"
              >
                <span className="staff-badge inline-flex items-center gap-1.5 font-medium text-[#222222]">
                  <span
                    className={`dot ${item.dot} transition-transform duration-200 group-hover:scale-125`}
                    aria-hidden="true"
                  />
                  <span>{item.label}</span>
                </span>
                <span className="text-[10px] text-[#717171] font-bold transition-colors group-hover:text-[#FF385C]">
                  {item.user}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Security notice below card */}
        <div className="text-center text-[11px] text-[#717171] space-y-1">
          <p className="sm:hidden">Chỉ dành cho cán bộ được phân quyền truy cập.</p>
          <div className="hidden sm:block space-y-1">
            <p>Hệ thống chỉ dành cho cán bộ, nhân viên được ủy quyền.</p>
            <p>Mọi hành vi truy cập bất hợp pháp đều bị xử lý theo quy định pháp luật.</p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-[#f7f7f7] text-[#717171] text-xs">
          Đang tải trang đăng nhập…
        </div>
      }
    >
      <LoginForm />
    </Suspense>
  );
}

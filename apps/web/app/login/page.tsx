'use client';

import { useState, Suspense, type FormEvent } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  ShieldCheck,
  Lock,
  User,
  ArrowRight,
  AlertCircle,
  KeyRound,
  RefreshCw,
} from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { Button } from '@/components/ui/button';
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
    <div className="flex min-h-screen flex-col items-center justify-center bg-slate-950 px-4 py-12 antialiased selection:bg-emerald-500/20 selection:text-emerald-300">
      <div className="w-full max-w-md space-y-6">
        {/* Brand identity header */}
        <div className="flex flex-col items-center text-center space-y-2">
          <Link
            href="/"
            className="group flex items-center gap-2.5 transition-transform hover:scale-105"
            aria-label="Về trang chủ Secure Document"
          >
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-emerald-950/90 border border-emerald-500/40 text-emerald-400 shadow-xl shadow-emerald-950/30">
              <ShieldCheck className="h-7 w-7" aria-hidden="true" />
            </div>
          </Link>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Secure<span className="font-light text-emerald-400">Document</span>
          </h1>
          <p className="text-xs text-slate-400 max-w-xs">
            Hệ thống quản lý tài liệu mật tổ chức · Xác thực hai lớp và kiểm soát phiên nghiêm ngặt
          </p>
        </div>

        <Card className="border-slate-800 bg-slate-900/90 shadow-2xl backdrop-blur-xl">
          <CardHeader className="space-y-1 pb-4">
            <CardTitle className="text-lg font-semibold text-slate-100">
              Đăng nhập tài khoản
            </CardTitle>
            <CardDescription className="text-xs text-slate-400">
              Nhập định danh và mật khẩu được cấp bởi quản trị viên
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            {errorMessage && (
              <Alert
                variant="destructive"
                className="border-red-900/60 bg-red-950/40 text-red-300 text-xs"
              >
                <AlertCircle className="h-4 w-4 shrink-0 text-red-400" aria-hidden="true" />
                <AlertDescription className="ml-2 leading-relaxed">{errorMessage}</AlertDescription>
              </Alert>
            )}

            <form id="login-form" onSubmit={handleLogin} className="space-y-4" noValidate>
              <div className="space-y-1.5">
                <label htmlFor="identifier" className="block text-xs font-medium text-slate-300">
                  Tên đăng nhập hoặc Email <span className="text-red-400">*</span>
                </label>
                <div className="relative">
                  <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
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
                    className="pl-9 bg-slate-950/80 border-slate-800 text-slate-100 placeholder:text-slate-600 focus:border-emerald-500 focus:ring-emerald-500/20"
                    aria-invalid={Boolean(fieldErrors.identifier)}
                    aria-describedby={fieldErrors.identifier ? 'identifier-error' : undefined}
                  />
                </div>
                {fieldErrors.identifier && (
                  <p id="identifier-error" className="text-[11px] text-red-400 font-medium">
                    {fieldErrors.identifier}
                  </p>
                )}
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label htmlFor="password" className="block text-xs font-medium text-slate-300">
                    Mật khẩu <span className="text-red-400">*</span>
                  </label>
                  <Link
                    href="/reset-password"
                    className="text-[11px] text-emerald-400 hover:text-emerald-300 transition-colors"
                  >
                    Quên mật khẩu?
                  </Link>
                </div>
                <div className="relative">
                  <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
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
                    className="pl-9 bg-slate-950/80 border-slate-800 text-slate-100 placeholder:text-slate-600 focus:border-emerald-500 focus:ring-emerald-500/20"
                    aria-invalid={Boolean(fieldErrors.password)}
                    aria-describedby={fieldErrors.password ? 'password-error' : undefined}
                  />
                </div>
                {fieldErrors.password && (
                  <p id="password-error" className="text-[11px] text-red-400 font-medium">
                    {fieldErrors.password}
                  </p>
                )}
              </div>

              <Button
                type="submit"
                disabled={isLoading}
                className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2 rounded-lg transition-all shadow-lg shadow-emerald-950/40"
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                    Đang xác thực thông tin…
                  </>
                ) : (
                  <>
                    <span>Đăng nhập hệ thống</span>
                    <ArrowRight className="ml-2 h-4 w-4" aria-hidden="true" />
                  </>
                )}
              </Button>
            </form>
          </CardContent>

          <CardFooter className="flex flex-col space-y-3 pt-2 border-t border-slate-800/80 text-center">
            <div className="flex items-center justify-center gap-1.5 text-[11px] text-slate-400">
              <KeyRound className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
              <span>Phiên đăng nhập được bảo vệ bằng HttpOnly Cookie và CSRF token</span>
            </div>
          </CardFooter>
        </Card>

        {/* Security notice below card */}
        <div className="text-center text-[11px] text-slate-400 space-y-1">
          <p>Hệ thống chỉ dành cho cán bộ, nhân viên được ủy quyền.</p>
          <p>Mọi hành vi truy cập bất hợp pháp đều bị xử lý theo quy định pháp luật.</p>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-slate-950 text-slate-400 text-xs">
          Đang tải trang đăng nhập…
        </div>
      }
    >
      <LoginForm />
    </Suspense>
  );
}

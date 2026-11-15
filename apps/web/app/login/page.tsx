'use client';

/**
 * Thuật toán: Điều Phối Đăng Nhập Bước Một & Chống Bẫy Điều Hướng Chéo Vai Trò (`LoginPage`, `LoginForm`)
 * Mục đích: Xác thực định danh/mật khẩu qua cookie `HttpOnly`, chuyển tiếp thử thách MFA khi cần và đối chiếu tham số `?redirect=` với tập vai trò thực tế từ `/users/me` để người dùng luôn vào đúng cổng phân quyền thay vì rơi vào màn hình `403`.
 */
import { useState, Suspense, type FormEvent } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldCheck, AlertCircle, KeyRound } from 'lucide-react';
import { apiClient, ApiError, sanitizeRedirectPath } from '@/lib/api-client';
import { resolveAuthorizedRedirectPath, useAuth } from '@/lib/auth-context';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { LoginFormFields, type FormFieldErrors } from './login-form-fields';
import { LoginDemoPanel } from './login-demo-panel';

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectTarget = sanitizeRedirectPath(searchParams.get('redirect'));
  const { refreshUser } = useAuth();

  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<FormFieldErrors>({});

  /**
   * Algorithm / Thuật toán: Máy Trạng Thái Đăng Nhập Đa Bước & Điều Hướng Phân Quyền (Multi-Step Authentication & RBAC Routing)
   * Mục đích: Kiểm tra dữ liệu biểu mẫu, thực thi xác thực bước một qua cookie HttpOnly và rẽ nhánh sang thử thách MFA hoặc phân hệ vai trò đích.
   * Cơ chế hoạt động:
   *   - Tiền kiểm các trường bắt buộc tại trình duyệt; gửi thông tin xác thực lên `/auth/login`.
   *   - Nếu máy chủ yêu cầu MFA (`mfaRequired === true`), bảo toàn đường dẫn `redirectTarget` đã khử độc sang `/mfa`; ngược lại đồng bộ hồ sơ và điều hướng theo ưu tiên vai trò RBAC.
   */
  async function handleLogin(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setErrorMessage(null);
    setFieldErrors({});

    const errors: FormFieldErrors = {};
    if (!identifier.trim()) {
      errors.identifier = 'Vui lòng nhập tên đăng nhập hoặc email.';
    }
    if (!password) {
      const missingPasswordMessage = 'Vui lòng nhập mật khẩu.';
      errors.password = missingPasswordMessage;
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
        const enrollPrefix = result.enrollmentRequired ? 'enroll=1&' : '';
        router.push(`/mfa?${enrollPrefix}redirect=${encodeURIComponent(redirectTarget)}`);
        return;
      }

      const user = await refreshUser();
      router.push(resolveAuthorizedRedirectPath(redirectTarget, user?.roles));
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
    <div className="relative flex min-h-screen flex-col items-center justify-center bg-[#f7f7f7] px-4 py-8 antialiased selection:bg-[#FF385C]/15 selection:text-[#E31C5F] overflow-hidden">
      <div className="relative z-10 w-full max-w-md space-y-5">
        <div className="flex flex-col items-center text-center space-y-1 animate-fade-in-down">
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
            <span className="text-xl font-bold tracking-tight text-[#222222]">
              Secure<span className="font-light text-[#E31C5F]">Document</span>
            </span>
          </Link>
          <p className="text-xs text-[#717171]">Cổng xác thực truy cập tài liệu mật</p>
        </div>

        <Card className="rounded-[24px] border border-[#ebebeb] bg-[#ffffff] shadow-[0_8px_30px_rgba(0,0,0,0.05)] animate-fade-in-up delay-75">
          <CardHeader className="space-y-1 pb-3">
            <CardTitle className="text-lg font-bold text-[#222222]">Đăng nhập tài khoản</CardTitle>
            <CardDescription className="text-xs text-[#717171]">
              Nhập định danh và mật khẩu nội bộ của bạn
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            {errorMessage && (
              <Alert
                variant="destructive"
                className="rounded-[16px] border border-[#C13515]/30 bg-[#C13515]/10 text-[#C13515] text-xs"
              >
                <AlertCircle
                  size={16}
                  strokeWidth={1.75}
                  className="shrink-0 text-[#C13515]"
                  aria-hidden="true"
                />
                <AlertDescription className="ml-2 leading-relaxed">{errorMessage}</AlertDescription>
              </Alert>
            )}

            <LoginFormFields
              identifier={identifier}
              password={password}
              isLoading={isLoading}
              fieldErrors={fieldErrors}
              onChangeIdentifier={setIdentifier}
              onChangePassword={setPassword}
              onSubmit={handleLogin}
            />
          </CardContent>

          <CardFooter className="flex justify-center pt-3 border-t border-[#ebebeb]">
            <div className="flex items-center gap-1.5 text-xs text-[#717171]">
              <KeyRound
                size={16}
                strokeWidth={1.75}
                className="text-[#717171]"
                aria-hidden="true"
              />
              <span>Bảo mật phiên bằng HttpOnly Cookie &amp; CSRF</span>
            </div>
          </CardFooter>
        </Card>

        <LoginDemoPanel
          onSelectAccount={(user) => {
            setIdentifier(user);
            setPassword('');
            setFieldErrors({});
          }}
        />
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

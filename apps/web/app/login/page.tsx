'use client';

/**
 * Thuật toán: Điều Phối Đăng Nhập Bước Một & Chống Bẫy Điều Hướng Chéo Vai Trò (`LoginPage`, `LoginForm`)
 * Mục đích: Xác thực định danh/mật khẩu qua cookie `HttpOnly`, chuyển tiếp thử thách MFA khi cần và đối chiếu tham số `?redirect=` với tập vai trò thực tế từ `/users/me` để người dùng luôn vào đúng cổng phân quyền thay vì rơi vào màn hình `403`.
 */
import { useEffect, useState, Suspense, type FormEvent } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldCheck, AlertCircle } from 'lucide-react';
import { apiClient, ApiError, sanitizeRedirectPath } from '@/lib/api-client';
import { resolveAuthorizedRedirectPath, useAuth, type AuthUser } from '@/lib/auth-context';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { LoginFormFields, type FormFieldErrors } from './login-form-fields';
import { LoginDemoPanel } from './login-demo-panel';

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectTarget = sanitizeRedirectPath(searchParams.get('redirect'));
  const sessionReason = searchParams.get('reason');
  const sessionBannerMessage =
    sessionReason === 'locked'
      ? 'Tài khoản của bạn đã bị tạm khóa bảo mật và phiên làm việc đã được đăng xuất ngay lập tức.'
      : sessionReason === 'disabled'
        ? 'Tài khoản của bạn đã bị vô hiệu hóa bởi quản trị viên. Vui lòng liên hệ bộ phận quản trị.'
        : sessionReason === 'session_revoked'
          ? 'Phiên làm việc đã hết hạn hoặc bị thu hồi. Vui lòng đăng nhập lại để tiếp tục.'
          : null;
  const { user, isAuthenticated, isLoading: isAuthLoading, hydrateUser, refreshUser } = useAuth();

  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<FormFieldErrors>({});

  /**
   * Thuật toán: Tự Động Chuyển Tiếp Phiên Đã Xác Thực Khỏi Màn Hình Đăng Nhập
   * Mục đích: Nếu người dùng đã có phiên đăng nhập hợp lệ mà vô tình mở `/login`, tự động đưa về đúng phân hệ được cấp quyền thay vì hiển thị lại biểu mẫu đăng nhập.
   */
  useEffect(() => {
    if (!isAuthLoading && isAuthenticated && user) {
      router.replace(resolveAuthorizedRedirectPath(redirectTarget, user));
    }
  }, [isAuthLoading, isAuthenticated, user, redirectTarget, router]);

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
        user?: AuthUser;
      }>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ identifier: identifier.trim(), password }),
      });

      if (result.mfaRequired) {
        const enrollFlag = result.enrollmentRequired ? 'enroll=1&' : 'enroll=0&';
        router.push(`/mfa?${enrollFlag}redirect=${encodeURIComponent(redirectTarget)}`);
        return;
      }

      if (result.user) {
        hydrateUser(result.user);
        router.push(resolveAuthorizedRedirectPath(redirectTarget, result.user));
        return;
      }

      const resolvedUser = await refreshUser();
      router.push(resolveAuthorizedRedirectPath(redirectTarget, resolvedUser));
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
            aria-label="Về trang chủ SecureDocument"
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
              Nhập tên đăng nhập (hoặc email) và mật khẩu của bạn.
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            {!errorMessage && sessionBannerMessage && (
              <Alert
                variant="warning"
                className="rounded-[16px] border border-[#E07912]/30 bg-[#E07912]/10 text-[#222222] text-xs"
              >
                <AlertCircle
                  size={16}
                  strokeWidth={1.75}
                  className="shrink-0 text-[#E07912]"
                  aria-hidden="true"
                />
                <AlertDescription className="ml-2 leading-relaxed">
                  {sessionBannerMessage}
                </AlertDescription>
              </Alert>
            )}

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

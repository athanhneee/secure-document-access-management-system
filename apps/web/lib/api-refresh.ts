/**
 * Thuật toán: Khóa Đơn Luồng Xoay Vòng Phiên `POST /auth/refresh` (`attemptSessionRefresh`)
 * Mục đích: Gộp nhiều yêu cầu nhận mã `401` đồng thời vào đúng một lời gọi `/auth/refresh` duy nhất nhằm tránh tranh chấp thu hồi Refresh Token (Token Replay Detection).
 */
let refreshPromise: Promise<boolean> | null = null;

export function isRefreshExcludedEndpoint(endpoint: string): boolean {
  const clean = endpoint.replace(/^https?:\/\/[^/]+/iu, '').replace(/^\/api\/v1/u, '');
  const normalized = clean.startsWith('/') ? clean : `/${clean}`;
  return (
    normalized.startsWith('/auth/login') ||
    normalized.startsWith('/auth/refresh') ||
    normalized.startsWith('/auth/logout') ||
    normalized.startsWith('/auth/mfa/') ||
    normalized.startsWith('/auth/password-reset/') ||
    normalized.startsWith('/auth/forgot-password') ||
    normalized.startsWith('/auth/reset-password') ||
    normalized.startsWith('/auth/webauthn/')
  );
}

export async function attemptSessionRefresh(
  resolveSafeApiUrl: (endpoint: string) => string,
  getCsrfToken: () => string,
): Promise<boolean> {
  if (typeof window === 'undefined') return false;
  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    try {
      const refreshUrl = resolveSafeApiUrl('/auth/refresh');
      const csrf = getCsrfToken();
      const res = await fetch(refreshUrl, {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          ...(csrf ? { 'x-csrf-token': csrf } : {}),
        },
      });
      return res.ok;
    } catch {
      return false;
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

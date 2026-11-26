import { localizeApiErrorMessage } from './api-error-messages';
import { attemptSessionRefresh, isRefreshExcludedEndpoint } from './api-refresh';

/**
 * Thuật toán: Chuẩn Hóa Điểm Cuối Cùng Nguồn `/api/v1`, Xoay Vòng Phiên `401` Đơn Luồng Liên Tab, Việt Hóa Lỗi & Xác Thực Chữ Ký PDF (`api-client`)
 * Mục đích:
 *   - Định tuyến mọi yêu cầu trình duyệt qua `/api/v1` cùng nguồn `'self'`, tự động đính kèm mã CSRF Double-Submit Cookie (`sda_csrf` -> `x-csrf-token`) và hỗ trợ hủy yêu cầu qua `AbortSignal`.
 *   - Phối hợp cùng `attemptSessionRefresh` (Mutex Promise trong tab + `BroadcastChannel('sda_auth_refresh')` liên tab + dấu thời gian `requestStartedAt`) để gộp toàn bộ các yêu cầu nhận `401` song song vào đúng 1 lần gọi `POST /auth/refresh`.
 *   - Tự động chuyển ngữ mã lỗi `errorCode` và thông điệp tiếng Anh của Backend sang tiếng Việt chuẩn xác qua `localizeApiErrorMessage`.
 */
function resolveInternalSsrOrigin(): string {
  const rawInternal = (
    process.env['INTERNAL_API_ORIGIN'] ||
    process.env['API_INTERNAL_URL'] ||
    'http://127.0.0.1:3001'
  ).trim();
  return rawInternal.replace(/\/api\/v1\/?$/u, '').replace(/\/+$/u, '');
}

function resolveApiBaseUrl(): string {
  const rawApiUrl = (
    process.env['NEXT_PUBLIC_API_BASE_URL'] ??
    process.env['NEXT_PUBLIC_API_URL'] ??
    ''
  ).trim();

  if (rawApiUrl) {
    const normalized = rawApiUrl.endsWith('/api/v1')
      ? rawApiUrl
      : `${rawApiUrl.replace(/\/+$/u, '')}/api/v1`;
    if (normalized.startsWith('/') && typeof window === 'undefined') {
      return `${resolveInternalSsrOrigin()}${normalized}`;
    }
    return normalized;
  }

  return typeof window !== 'undefined' ? '/api/v1' : `${resolveInternalSsrOrigin()}/api/v1`;
}

function resolveAllowedApiOrigin(baseUrl: string): string {
  const fallbackOrigin =
    typeof window !== 'undefined' ? window.location.origin : resolveInternalSsrOrigin();
  try {
    return new URL(baseUrl, fallbackOrigin).origin;
  } catch {
    return fallbackOrigin;
  }
}

export const API_BASE_URL = resolveApiBaseUrl();

/**
 * Thuật toán: Khử Độc Đường Dẫn Chuyển Hướng Nội Bộ Chống Open Redirect (`sanitizeRedirectPath`)
 * Mục đích: Chỉ cho phép đường dẫn tương đối bắt đầu bằng đúng một dấu `/`, chặn `//`, `/\`, ký tự điều khiển và URI có `scheme:`.
 */
export function sanitizeRedirectPath(raw: string | null | undefined, fallback = '/'): string {
  if (!raw || typeof raw !== 'string') return fallback;
  const trimmed = raw.trim();
  if (
    !trimmed.startsWith('/') ||
    trimmed.startsWith('//') ||
    trimmed.startsWith('/\\') ||
    /[\p{Cc}\\]/u.test(trimmed) ||
    /^[a-zA-Z][a-zA-Z0-9+.-]*:/u.test(trimmed)
  ) {
    return fallback;
  }
  return trimmed;
}

function resolveSafeApiUrl(endpoint: string): string {
  const baseUrl = resolveApiBaseUrl();
  const allowedOrigin = resolveAllowedApiOrigin(baseUrl);
  if (endpoint.startsWith('http://') || endpoint.startsWith('https://')) {
    let parsed: URL;
    try {
      parsed = new URL(endpoint);
    } catch {
      throw new Error('Địa chỉ điểm cuối API không hợp lệ.');
    }
    if (parsed.origin !== allowedOrigin) {
      throw new Error('Đã chặn yêu cầu API gửi thông tin xác thực chéo nguồn.');
    }
    return parsed.toString();
  }
  return `${baseUrl}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;
}

/**
 * Thuật toán: Kiểm Định Chữ Ký Tệp Nhị Phân `%PDF-` Theo ISO 32000 (`verifyPdfMagicBytes`)
 */
export async function verifyPdfMagicBytes(blob: Blob): Promise<boolean> {
  if (blob.size < 5) return false;
  const headerBytes = new Uint8Array(await blob.slice(0, 5).arrayBuffer());
  return (
    headerBytes[0] === 0x25 &&
    headerBytes[1] === 0x50 &&
    headerBytes[2] === 0x44 &&
    headerBytes[3] === 0x46 &&
    headerBytes[4] === 0x2d
  );
}

/**
 * Thuật toán: Trích Xuất Token Chống Giả Mạo Chéo Trang Từ Cookie `sda_csrf` (`getCsrfToken`)
 */
export function getCsrfToken(): string {
  if (typeof document === 'undefined') return '';
  const match = document.cookie.split('; ').find((row) => row.startsWith('sda_csrf='));
  if (!match) return '';
  const rawValue = match.slice('sda_csrf='.length);
  try {
    return decodeURIComponent(rawValue);
  } catch {
    return rawValue;
  }
}

export interface ApiErrorResponse {
  statusCode?: number;
  errorCode?: string;
  code?: string;
  message?: string | string[];
  error?: string;
  correlationId?: string;
  details?: unknown;
}

export class ApiError extends Error {
  public readonly status: number;
  public readonly response: ApiErrorResponse;
  public readonly errorCode: string | undefined;

  constructor(status: number, response: ApiErrorResponse, message?: string) {
    super(localizeApiErrorMessage(status, response, message));
    this.name = 'ApiError';
    this.status = status;
    this.response = response;
    this.errorCode = response.errorCode ?? response.code;
  }
}

export type SessionExpiredReason = 'session_revoked' | 'mfa_required';
export type SessionExpiredListener = (reason: SessionExpiredReason) => void;
const sessionExpiredListeners = new Set<SessionExpiredListener>();

/**
 * Thuật toán: Kênh Phát Tín Hiệu Phiên Hết Hạn `401` (Không Bao Giờ Kích Hoạt Với `403`) Cho `AuthProvider` (`subscribeSessionExpired`)
 */
export function subscribeSessionExpired(listener: SessionExpiredListener): () => void {
  sessionExpiredListeners.add(listener);
  return () => {
    sessionExpiredListeners.delete(listener);
  };
}

function emitSessionExpired(reason: SessionExpiredReason = 'session_revoked'): void {
  for (const listener of sessionExpiredListeners) {
    try {
      listener(reason);
    } catch {
      // Cô lập lỗi giữa các listener phiên
    }
  }
}

function isPreMfaErrorPayload(payload: ApiErrorResponse | null | undefined): boolean {
  if (!payload) return false;
  if (payload.errorCode === 'MFA_REQUIRED' || payload.code === 'MFA_REQUIRED') {
    return true;
  }
  const msg = Array.isArray(payload.message)
    ? payload.message.join(' ')
    : typeof payload.message === 'string'
      ? payload.message
      : '';
  return msg.toLowerCase().includes('mfa verification is required');
}

export function isPreMfaApiError(err: unknown): boolean {
  return err instanceof ApiError && err.status === 401 && isPreMfaErrorPayload(err.response);
}

async function isPreMfa401Response(response: Response): Promise<boolean> {
  try {
    const cloned = response.clone();
    const payload = (await cloned.json()) as ApiErrorResponse;
    return isPreMfaErrorPayload(payload);
  } catch {
    return false;
  }
}

/**
 * Thuật toán: Trích Xuất Tên Tệp Tin An Toàn Từ Tiêu Đề `Content-Disposition` (`parseContentDispositionFilename`, V-08).
 */
export function parseContentDispositionFilename(header: string | null): string | undefined {
  if (!header) return undefined;
  const utf8Match = header.match(/filename\*\s*=\s*UTF-8''([^;\r\n]+)/i);
  if (utf8Match?.[1]) {
    try {
      const decoded = decodeURIComponent(utf8Match[1].trim());
      if (decoded) return decoded;
    } catch {
      // Fallback sang mẫu filename="..."
    }
  }
  const plainMatch = header.match(/filename\s*=\s*"?([^";\r\n]+)"?/i);
  const candidate = plainMatch?.[1]?.trim();
  return candidate || undefined;
}

export interface ApiRequestOptions extends Omit<RequestInit, 'signal'> {
  signal?: AbortSignal | null | undefined;
  _retriedAfterRefresh?: boolean | undefined;
}

export async function apiClient<T>(endpoint: string, options: ApiRequestOptions = {}): Promise<T> {
  const { _retriedAfterRefresh, signal, ...fetchInit } = options;
  const url = resolveSafeApiUrl(endpoint);
  const csrf = getCsrfToken();

  const method = (fetchInit.method ?? 'GET').toUpperCase();
  const isStateChangingMethod = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(fetchInit.headers as Record<string, string>),
  };
  if (!(fetchInit.body instanceof FormData) && !headers['Content-Type'] && fetchInit.body) {
    headers['Content-Type'] = 'application/json';
  }
  if (csrf && isStateChangingMethod) headers['x-csrf-token'] = csrf;

  const requestStartedAt = Date.now();
  const response = await fetch(url, {
    ...fetchInit,
    credentials: 'include',
    headers,
    ...(signal ? { signal } : {}),
  });

  if (
    response.status === 401 &&
    !_retriedAfterRefresh &&
    !signal?.aborted &&
    !isRefreshExcludedEndpoint(endpoint)
  ) {
    // CONFLICT-RESOLVED: Phân biệt 401 tiền-MFA (`MFA verification is required.`) để chuyển về `/mfa` thay vì báo sai `session_revoked` (V-14).
    if (await isPreMfa401Response(response)) {
      emitSessionExpired('mfa_required');
    } else {
      const refreshed = await attemptSessionRefresh(
        resolveSafeApiUrl,
        getCsrfToken,
        requestStartedAt,
      );
      if (refreshed && !signal?.aborted) {
        return apiClient<T>(endpoint, { ...options, _retriedAfterRefresh: true });
      }
      if (!signal?.aborted) {
        emitSessionExpired('session_revoked');
      }
    }
  } else if (
    response.status === 401 &&
    _retriedAfterRefresh &&
    !signal?.aborted &&
    !isRefreshExcludedEndpoint(endpoint)
  ) {
    emitSessionExpired('session_revoked');
  }

  if (response.status === 204) return undefined as unknown as T;

  if (!response.ok) {
    let errorData: ApiErrorResponse = {};
    try {
      errorData = (await response.json()) as ApiErrorResponse;
    } catch {
      errorData = { message: response.statusText };
    }
    throw new ApiError(response.status, errorData);
  }

  return response.json() as Promise<T>;
}

export type DownloadBlob = Blob & { totalPages?: number; filename?: string };

export interface ApiDownloadOptions {
  signal?: AbortSignal | null | undefined;
  headers?: Record<string, string> | undefined;
  _retriedAfterRefresh?: boolean | undefined;
}

export async function apiDownload(
  endpoint: string,
  options: ApiDownloadOptions = {},
): Promise<DownloadBlob> {
  const { _retriedAfterRefresh, signal, headers: extraHeaders } = options;
  const url = resolveSafeApiUrl(endpoint);

  const headers: Record<string, string> = {
    ...(extraHeaders ?? {}),
  };

  const requestStartedAt = Date.now();
  const response = await fetch(url, {
    method: 'GET',
    credentials: 'include',
    headers,
    ...(signal ? { signal } : {}),
  });

  if (
    response.status === 401 &&
    !_retriedAfterRefresh &&
    !signal?.aborted &&
    !isRefreshExcludedEndpoint(endpoint)
  ) {
    if (await isPreMfa401Response(response)) {
      emitSessionExpired('mfa_required');
    } else {
      const refreshed = await attemptSessionRefresh(
        resolveSafeApiUrl,
        getCsrfToken,
        requestStartedAt,
      );
      if (refreshed && !signal?.aborted) {
        return apiDownload(endpoint, { ...options, _retriedAfterRefresh: true });
      }
      if (!signal?.aborted) {
        emitSessionExpired('session_revoked');
      }
    }
  } else if (
    response.status === 401 &&
    _retriedAfterRefresh &&
    !signal?.aborted &&
    !isRefreshExcludedEndpoint(endpoint)
  ) {
    emitSessionExpired('session_revoked');
  }

  if (!response.ok) {
    let errorData: ApiErrorResponse = {};
    try {
      errorData = (await response.json()) as ApiErrorResponse;
    } catch {
      errorData = { message: response.statusText };
    }
    throw new ApiError(response.status, errorData);
  }

  const downloadBlob = (await response.blob()) as DownloadBlob;
  const totalPagesHeader = response.headers.get('x-total-pages');
  if (totalPagesHeader) {
    const parsed = parseInt(totalPagesHeader, 10);
    if (!isNaN(parsed) && parsed > 0) downloadBlob.totalPages = parsed;
  }
  const parsedFilename = parseContentDispositionFilename(
    response.headers.get('content-disposition'),
  );
  if (parsedFilename) {
    downloadBlob.filename = parsedFilename;
  }

  return downloadBlob;
}

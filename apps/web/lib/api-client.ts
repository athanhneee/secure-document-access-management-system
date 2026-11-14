import { attemptSessionRefresh, isRefreshExcludedEndpoint } from './api-refresh';

/**
 * Thuật toán: Chuẩn Hóa Điểm Cuối Cùng Nguồn `/api/v1`, Xoay Vòng Phiên `401` Đơn Luồng & Xác Thực Chữ Ký PDF (`api-client`)
 * Mục đích: Định tuyến trình duyệt qua `/api/v1` cùng nguồn `'self'`, bảo vệ CSRF Double-Submit Cookie (`sda_csrf` -> `x-csrf-token`), hỗ trợ hủy yêu cầu qua `AbortSignal`, và tự động làm mới phiên một lần duy nhất khi gặp mã `401`.
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
      throw new Error('Invalid API endpoint URL.');
    }
    if (parsed.origin !== allowedOrigin) {
      throw new Error('Blocked cross-origin credentialed API request.');
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
  message?: string | string[];
  error?: string;
  code?: string;
  details?: unknown;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly response: ApiErrorResponse,
    message?: string,
  ) {
    const errorMsg =
      message ||
      (Array.isArray(response.message) ? response.message.join(', ') : response.message) ||
      response.error ||
      `Yêu cầu thất bại với mã trạng thái ${status}`;
    super(errorMsg);
    this.name = 'ApiError';
  }
}

export interface ApiRequestOptions extends Omit<RequestInit, 'signal'> {
  signal?: AbortSignal | null | undefined;
  _retriedAfterRefresh?: boolean | undefined;
}

export async function apiClient<T>(endpoint: string, options: ApiRequestOptions = {}): Promise<T> {
  const { _retriedAfterRefresh, signal, ...fetchInit } = options;
  const url = resolveSafeApiUrl(endpoint);
  const csrf = getCsrfToken();

  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(fetchInit.headers as Record<string, string>),
  };
  if (!(fetchInit.body instanceof FormData) && !headers['Content-Type'] && fetchInit.body) {
    headers['Content-Type'] = 'application/json';
  }
  if (csrf) headers['x-csrf-token'] = csrf;

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
    const refreshed = await attemptSessionRefresh(resolveSafeApiUrl, getCsrfToken);
    if (refreshed && !signal?.aborted) {
      return apiClient<T>(endpoint, { ...options, _retriedAfterRefresh: true });
    }
  }

  if (response.status === 204) return undefined as unknown as T;

  if (!response.ok) {
    let errorData: ApiErrorResponse = {};
    try {
      errorData = await response.json();
    } catch {
      errorData = { message: response.statusText };
    }
    throw new ApiError(response.status, errorData);
  }

  return response.json() as Promise<T>;
}

export type DownloadBlob = Blob & { totalPages?: number };

export interface ApiDownloadOptions {
  signal?: AbortSignal | null | undefined;
  _retriedAfterRefresh?: boolean | undefined;
}

export async function apiDownload(
  endpoint: string,
  options: ApiDownloadOptions = {},
): Promise<DownloadBlob> {
  const { _retriedAfterRefresh, signal } = options;
  const url = resolveSafeApiUrl(endpoint);
  const csrf = getCsrfToken();

  const response = await fetch(url, {
    method: 'GET',
    credentials: 'include',
    headers: csrf ? { 'x-csrf-token': csrf } : {},
    ...(signal ? { signal } : {}),
  });

  if (
    response.status === 401 &&
    !_retriedAfterRefresh &&
    !signal?.aborted &&
    !isRefreshExcludedEndpoint(endpoint)
  ) {
    const refreshed = await attemptSessionRefresh(resolveSafeApiUrl, getCsrfToken);
    if (refreshed && !signal?.aborted) {
      return apiDownload(endpoint, { ...options, _retriedAfterRefresh: true });
    }
  }

  if (!response.ok) {
    let errorData: ApiErrorResponse = {};
    try {
      errorData = await response.json();
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

  return downloadBlob;
}

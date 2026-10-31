const rawApiUrl = process.env['NEXT_PUBLIC_API_BASE_URL'] ?? process.env['NEXT_PUBLIC_API_URL'];
const API_BASE_URL = rawApiUrl
  ? rawApiUrl.endsWith('/api/v1')
    ? rawApiUrl
    : `${rawApiUrl.replace(/\/+$/u, '')}/api/v1`
  : 'http://127.0.0.1:3001/api/v1';

const ALLOWED_API_ORIGIN = (() => {
  try {
    return new URL(API_BASE_URL).origin;
  } catch {
    return 'http://127.0.0.1:3001';
  }
})();

/**
 * Sanitizes post-login / post-MFA redirect targets to prevent Open Redirect attacks.
 * Only permits same-origin relative paths starting with a single `/` (never `//` or `/\`).
 */
export function sanitizeRedirectPath(raw: string | null | undefined, fallback = '/'): string {
  if (!raw || typeof raw !== 'string') {
    return fallback;
  }
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
  if (endpoint.startsWith('http://') || endpoint.startsWith('https://')) {
    let parsed: URL;
    try {
      parsed = new URL(endpoint);
    } catch {
      throw new Error('Invalid API endpoint URL.');
    }
    if (parsed.origin !== ALLOWED_API_ORIGIN) {
      throw new Error('Blocked cross-origin credentialed API request.');
    }
    return parsed.toString();
  }
  const normalizedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return `${API_BASE_URL}${normalizedEndpoint}`;
}

/**
 * Verifies that a downloaded preview Blob starts with the PDF magic header (`%PDF-`)
 * before creating a browser `blob:` URL rendered in a preview frame.
 */
export async function verifyPdfMagicBytes(blob: Blob): Promise<boolean> {
  if (blob.size < 5) {
    return false;
  }
  const headerBytes = new Uint8Array(await blob.slice(0, 5).arrayBuffer());
  return (
    headerBytes[0] === 0x25 && // %
    headerBytes[1] === 0x50 && // P
    headerBytes[2] === 0x44 && // D
    headerBytes[3] === 0x46 && // F
    headerBytes[4] === 0x2d // -
  );
}

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

export async function apiClient<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = resolveSafeApiUrl(endpoint);
  const csrf = getCsrfToken();

  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(options.headers as Record<string, string>),
  };

  // Only set Content-Type to JSON if not sending FormData
  if (!(options.body instanceof FormData) && !headers['Content-Type'] && options.body) {
    headers['Content-Type'] = 'application/json';
  }

  if (csrf) {
    headers['x-csrf-token'] = csrf;
  }

  const response = await fetch(url, {
    ...options,
    credentials: 'include',
    headers,
  });

  if (response.status === 204) {
    return undefined as unknown as T;
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

  return response.json() as Promise<T>;
}

export type DownloadBlob = Blob & { totalPages?: number };

export async function apiDownload(endpoint: string): Promise<DownloadBlob> {
  const url = resolveSafeApiUrl(endpoint);
  const csrf = getCsrfToken();

  const response = await fetch(url, {
    method: 'GET',
    credentials: 'include',
    headers: {
      ...(csrf ? { 'x-csrf-token': csrf } : {}),
    },
  });

  if (!response.ok) {
    let errorData: ApiErrorResponse = {};
    try {
      errorData = await response.json();
    } catch {
      errorData = { message: response.statusText };
    }
    throw new ApiError(response.status, errorData);
  }

  const rawBlob = await response.blob();
  const downloadBlob = rawBlob as DownloadBlob;
  const totalPagesHeader = response.headers.get('x-total-pages');
  if (totalPagesHeader) {
    const parsed = parseInt(totalPagesHeader, 10);
    if (!isNaN(parsed) && parsed > 0) {
      downloadBlob.totalPages = parsed;
    }
  }

  return downloadBlob;
}

const API_BASE_URL = process.env['NEXT_PUBLIC_API_BASE_URL'] ?? 'http://127.0.0.1:3001/api/v1';

export function getCsrfToken(): string {
  if (typeof document === 'undefined') return '';
  const match = document.cookie.split('; ').find((row) => row.startsWith('sda_csrf='));
  return match ? decodeURIComponent(match.split('=')[1] ?? '') : '';
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
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;
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

export async function apiDownload(endpoint: string): Promise<Blob> {
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;
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

  return response.blob();
}

/**
 * Thuật toán: Chuẩn Hóa Điểm Cuối Tương Đối Cùng Nguồn & Trích Xuất Nguồn Hợp Lệ Theo RFC 6454 (Same-Origin & SSR-Safe API Origin Resolution)
 * Mục đích: Mặc định định tuyến trình duyệt qua đường dẫn tương đối `/api/v1` (cùng nguồn `'self'`), tự động rơi về `INTERNAL_API_ORIGIN` khi chạy SSR/Node không có `window`, và giải quyết `origin` an toàn không bao giờ ném ngoại lệ `TypeError` với đường dẫn tương đối.
 * Cơ chế hoạt động:
 *   - Chuẩn hóa hậu tố `/api/v1` từ cấu hình môi trường; trên trình duyệt ưu tiên `'/api/v1'`, trên môi trường Node/SSR ghép với `INTERNAL_API_ORIGIN` (hoặc `http://127.0.0.1:3001`).
 *   - Phân tích `new URL(baseUrl, baseOrigin)` với `window.location.origin` (hoặc loopback khi SSR) để trích xuất `origin` tin cậy duy nhất được nhận cookie xác thực.
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
  // CONFLICT-RESOLVED: Chuyển mặc định trình duyệt sang đường dẫn cùng nguồn '/api/v1' khớp với Next.js rewrites và CSP connect-src 'self', đồng thời giữ nhánh dự phòng INTERNAL_API_ORIGIN cho SSR/Node.
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

  if (typeof window !== 'undefined') {
    return '/api/v1';
  }
  return `${resolveInternalSsrOrigin()}/api/v1`;
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
 * Sanitizes post-login / post-MFA redirect targets to prevent Open Redirect attacks.
 * Only permits same-origin relative paths starting with a single `/` (never `//` or `/\`).
 *
 * Thuật toán: Khử Độc Đường Dẫn Chuyển Hướng Nội Bộ Chống Open Redirect (Relative-Path Allowlist Sanitizer)
 * Mục đích: Ngăn chặn kẻ tấn công lợi dụng tham số `?redirect=` để điều hướng người dùng sang tên miền lừa đảo sau khi đăng nhập hoặc xác thực MFA.
 * Cơ chế hoạt động:
 *   - Chỉ chấp nhận chuỗi bắt đầu bằng đúng một dấu `/`; từ chối tức khắc đường dẫn tương đối giao thức (`//`), dấu gạch ngược (`/\\`), mọi ký tự điều khiển Unicode (`\p{Cc}`) hoặc tiền tố giao thức URI (`scheme:`) và trả về đường dẫn an toàn `fallback`.
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

/**
 * Thuật toán: Xác Thực Ràng Buộc Nguồn Đích URL Chống SSRF & Rò Rỉ Thông Tin Xác Thực Chéo Nguồn (Origin-Pinned URL Resolver)
 * Mục đích: Đảm bảo mọi yêu cầu HTTP đính kèm cookie phiên (`credentials: 'include'`) chỉ được phép gửi tới đúng nguồn API hợp lệ.
 * Cơ chế hoạt động:
 *   - Nếu `endpoint` là URL tuyệt đối (`http://` hoặc `https://`), phân tích cú pháp qua `new URL()` và đối chiếu nghiêm ngặt `parsed.origin === allowedOrigin`; ném ngoại lệ chặn đứng nếu khác nguồn.
 *   - Nếu là đường dẫn tương đối, chuẩn hóa dấu `/` đầu chuỗi và ghép nối an toàn vào `baseUrl`.
 */
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
  const normalizedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return `${baseUrl}${normalizedEndpoint}`;
}

/**
 * Verifies that a downloaded preview Blob starts with the PDF magic header (`%PDF-`)
 * before creating a browser `blob:` URL rendered in a preview frame.
 *
 * Thuật toán: Kiểm Định Chữ Ký Tệp Nhị Phân PDF Magic Bytes (Binary File Signature Verification — ISO 32000)
 * Mục đích: Ngăn chặn tấn công MIME-Sniffing hoặc thực thi mã độc HTML/SVG giả mạo luồng xem trước PDF bên trong khung `blob:` URL.
 * Cơ chế hoạt động:
 *   - Cắt đúng 5 byte đầu tiên `O(1)` từ `Blob` sang mảng nhị phân `Uint8Array` và kiểm tra khớp tuyệt đối chuỗi mã hex `0x25 0x50 0x44 0x46 0x2D` (tương ứng ký tự ASCII `%PDF-`).
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

/**
 * Thuật toán: Trích Xuất Mã Chống Giả Mạo Yêu Cầu Chéo Trang Theo Mẫu Double-Submit Cookie (CSRF Cookie Parser)
 * Mục đích: Đọc giá trị cookie `sda_csrf` từ `document.cookie` để phản chiếu vào HTTP header `x-csrf-token` cho mọi yêu cầu từ trình duyệt.
 * Cơ chế hoạt động:
 *   - Bỏ qua an toàn khi chạy phía máy chủ (SSR `document === undefined`), tách chuỗi cookie theo dấu phân cách `'; '`, tìm tiền tố `sda_csrf=` và giải mã `decodeURIComponent` có bắt ngoại lệ dự phòng chuỗi gốc.
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

/**
 * Thuật toán: Trình Gọi HTTP Có Xác Thực Cookie HttpOnly & Tiêm Tự Động Double-Submit CSRF (Authenticated JSON Fetch Wrapper)
 * Mục đích: Thực thi thống nhất các lời gọi REST API JSON/FormData kèm cơ chế bảo vệ CSRF, truyền cookie phiên tự động mà không lưu trữ mã thông báo xác thực vào bộ nhớ Web Storage dễ bị XSS đánh cắp.
 * Cơ chế hoạt động:
 *   - Xác thực URL qua `resolveSafeApiUrl`, tự động suy diễn `Content-Type: application/json` khi thân yêu cầu không phải `FormData`, đính kèm header `x-csrf-token` và bật `credentials: 'include'`.
 *   - Xử lý mã `204 No Content`, chuẩn hóa mọi phản hồi lỗi HTTP thành đối tượng ngoại lệ có cấu trúc `ApiError`.
 */
export async function apiClient<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = resolveSafeApiUrl(endpoint);
  const csrf = getCsrfToken();

  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(options.headers as Record<string, string>),
  };

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

/**
 * Thuật toán: Tải Luồng Dữ Liệu Nhị Phân Có Đính Kèm Siêu Dữ Liệu Phân Trang (Authenticated Binary Stream & Page-Count Extractor)
 * Mục đích: Tải an toàn tệp PDF đã đóng dấu thủy ấn hoặc báo cáo kiểm toán dưới dạng `Blob` kèm tổng số trang tài liệu.
 * Cơ chế hoạt động:
 *   - Thực thi yêu cầu `GET` có ràng buộc Origin và header `x-csrf-token`, chuyển luồng phản hồi thành `Blob` và phân tích số nguyên dương từ HTTP header `x-total-pages` gắn vào thuộc tính mở rộng `totalPages`.
 */
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

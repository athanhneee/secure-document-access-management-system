import { NextResponse, type NextRequest, type ProxyConfig } from 'next/server';

/**
 * Thuật toán: Chuẩn Hóa Điểm Cuối Nội Bộ Thời Gian Thực Phục Vụ Chuyển Tiếp `/api/v1` (Runtime Internal API Upstream Resolver)
 * Mục đích: Giải quyết động địa chỉ máy chủ API hậu phương tại thời điểm xử lý yêu cầu (`next start` / container runtime / E2E cổng `:3101`) thay vì chỉ cố định lúc `next build`.
 * Cơ chế hoạt động:
 *   - Ưu tiên đọc `INTERNAL_API_ORIGIN` hoặc `API_INTERNAL_URL`; nếu vắng mặt và `NEXT_PUBLIC_API_BASE_URL` là URL tuyệt đối `http(s)://`, cắt hậu tố `/api/v1` làm nguồn dự phòng, mặc định rơi về `http://127.0.0.1:3001`.
 */
function resolveInternalApiOrigin(): string {
  const explicitInternal = (
    process.env['INTERNAL_API_ORIGIN'] ||
    process.env['API_INTERNAL_URL'] ||
    ''
  ).trim();
  if (explicitInternal) {
    return explicitInternal.replace(/\/api\/v1\/?$/u, '').replace(/\/+$/u, '');
  }

  const publicApiUrl = (
    process.env['NEXT_PUBLIC_API_BASE_URL'] ??
    process.env['NEXT_PUBLIC_API_URL'] ??
    ''
  ).trim();
  if (/^https?:\/\//iu.test(publicApiUrl)) {
    return publicApiUrl.replace(/\/api\/v1\/?$/u, '').replace(/\/+$/u, '');
  }

  return 'http://127.0.0.1:3001';
}

/**
 * Thuật toán: Tổng Hợp Tập Nguồn Kết Nối Hợp Lệ Cho Chỉ Thị `connect-src` (Dynamic Connect-Src Allowlist Builder)
 * Mục đích: Đảm bảo kết nối cùng nguồn `/api/v1` luôn hoạt động dưới `'self'` và chỉ mở rộng sang các nguồn `http(s)://` được khai báo tường minh.
 * Cơ chế hoạt động:
 *   - Khởi tạo tập `Set` chứa `'self'`, phân tích cú pháp `.origin` từ `NEXT_PUBLIC_API_BASE_URL`, `NEXT_PUBLIC_API_URL` và chuỗi danh sách `CSP_CONNECT_ORIGINS`; chỉ bổ sung cổng loopback cục bộ khi khác môi trường production.
 */
function buildConnectSrcDirective(): string {
  const allowedConnectOrigins = new Set<string>(["'self'"]);
  const rawCandidates = [
    process.env['NEXT_PUBLIC_API_BASE_URL'],
    process.env['NEXT_PUBLIC_API_URL'],
    ...(process.env['CSP_CONNECT_ORIGINS'] ?? '').split(/[\s,]+/u),
  ];

  for (const candidate of rawCandidates) {
    const trimmed = candidate?.trim();
    if (trimmed && /^https?:\/\//iu.test(trimmed)) {
      try {
        allowedConnectOrigins.add(new URL(trimmed).origin);
      } catch {
        // Fall back to self when build/runtime URL is malformed
      }
    }
  }

  if (process.env.NODE_ENV !== 'production') {
    allowedConnectOrigins.add('http://127.0.0.1:3001');
    allowedConnectOrigins.add('http://localhost:3001');
  }

  return `connect-src ${[...allowedConnectOrigins].join(' ')}`;
}

/**
 * Thuật toán: Sinh Mã Nonce Ngẫu Nhiên Mật Mã 128-Bit Theo Từng Yêu Cầu (CSPRNG Base64 Request Nonce Generator)
 * Mục đích: Cấp phát định danh dùng một lần không thể dự đoán cho các khối kịch bản và kiểu dáng hợp lệ của Next.js App Router.
 * Cơ chế hoạt động: Lấy 16 byte ngẫu nhiên từ Web Crypto API (`crypto.getRandomValues`) và mã hóa sang chuỗi ASCII Base64.
 */
function generateRequestNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/**
 * Thuật toán: Gắn Chính Sách Bảo Mật Nội Dung Động Theo Từng Yêu Cầu Trang (Per-Request Nonce CSP Proxy)
 * Mục đích: Loại bỏ hoàn toàn chỉ thị cho phép mã nội tuyến không an toàn khỏi `Content-Security-Policy` và đồng bộ `x-nonce` giữa Server Components với trình duyệt.
 * Cơ chế hoạt động:
 *   - Sinh `nonce` mới trên mọi yêu cầu điều hướng và tải trước (prefetch), chỉ bật thực thi động khi `NODE_ENV === 'development'`.
 *   - Ghi đè đồng thời `x-nonce` và `Content-Security-Policy` vào Request Headers lẫn Response Headers.
 */
export function proxy(request: NextRequest): NextResponse {
  const { pathname, search } = request.nextUrl;
  if (pathname === '/api/v1' || pathname.startsWith('/api/v1/')) {
    const upstreamOrigin = resolveInternalApiOrigin();
    return NextResponse.rewrite(new URL(`${pathname}${search}`, `${upstreamOrigin}/`));
  }

  // CONFLICT-RESOLVED: Chỉ cho phép cờ biên dịch động khi NODE_ENV === 'development', khóa chặt trên production và test.
  const isDevelopment = process.env.NODE_ENV === 'development';
  const nonce = generateRequestNonce();

  const scriptSrc = isDevelopment
    ? `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval'`
    : `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`;

  const styleSrc = `style-src 'self' 'nonce-${nonce}'`;

  const cspHeaderValue =
    [
      "default-src 'self'",
      scriptSrc,
      styleSrc,
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      buildConnectSrcDirective(),
      "frame-src 'self' blob:",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; ') + ';';

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', cspHeaderValue);

  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });
  response.headers.set('Content-Security-Policy', cspHeaderValue);
  return response;
}

// CONFLICT-RESOLVED: Gỡ bỏ bộ lọc missing prefetch headers để yêu cầu prefetch vẫn được cấp x-nonce đồng nhất, đồng thời cho phép /api/v1 đi qua proxy rewrite động theo INTERNAL_API_ORIGIN lúc runtime.
export const config: ProxyConfig = {
  matcher: [
    {
      source: '/((?!_next/static|_next/image|favicon.ico).*)',
    },
  ],
};

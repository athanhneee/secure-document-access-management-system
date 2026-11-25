import { NextResponse, type NextRequest, type ProxyConfig } from 'next/server';
import { buildConnectSrcDirective, resolveInternalApiOrigin } from './lib/csp-config';

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
 * Thuật toán: Chống Giả Mạo Header Chuyển Tiếp IP & Bảo Toàn Siêu Dữ Liệu Giao Thức Khi Rewrite `/api/v1` (`buildApiProxyHeaders`)
 * Mục đích:
 *   - Chỉ tin cậy `x-forwarded-for`, `cf-connecting-ip`, `x-real-ip` khi chạy sau Reverse Proxy biên được khai báo tường minh (`TRUSTED_EDGE_PROXY=true`).
 *   - Khi không chạy sau Reverse Proxy biên (mặc định triển khai trực tiếp hoặc local), tước bỏ hoàn toàn các header IP do client tự gắn để ngăn Burp Suite giả mạo `X-Forwarded-For` vượt rate-limit hoặc làm sai lệch IP nhật ký kiểm toán (N02).
 */
export function buildApiProxyHeaders(
  request: Pick<NextRequest, 'headers' | 'nextUrl'>,
  trustedEdgeProxy = process.env['TRUSTED_EDGE_PROXY'] === 'true',
): Headers {
  const upstreamHeaders = new Headers(request.headers);
  if (trustedEdgeProxy) {
    const existingForwardedFor = upstreamHeaders.get('x-forwarded-for')?.trim();
    if (!existingForwardedFor) {
      const edgeClientIp = (
        upstreamHeaders.get('cf-connecting-ip') ??
        upstreamHeaders.get('x-real-ip') ??
        ''
      ).trim();
      if (edgeClientIp) {
        upstreamHeaders.set('x-forwarded-for', edgeClientIp);
      }
    }
  } else {
    // CONFLICT-RESOLVED: Tước bỏ mọi header chuyển tiếp IP do client tự gửi khi Next.js không đứng sau edge proxy tin cậy (N02).
    upstreamHeaders.delete('x-forwarded-for');
    upstreamHeaders.delete('cf-connecting-ip');
    upstreamHeaders.delete('x-real-ip');
    upstreamHeaders.delete('true-client-ip');
    upstreamHeaders.delete('forwarded');
  }
  if (!trustedEdgeProxy || !upstreamHeaders.get('x-forwarded-proto')) {
    const proto = request.nextUrl.protocol.replace(/:$/u, '');
    if (proto === 'http' || proto === 'https') {
      upstreamHeaders.set('x-forwarded-proto', proto);
    }
  }
  if (!trustedEdgeProxy || !upstreamHeaders.get('x-forwarded-host')) {
    const host = upstreamHeaders.get('host');
    if (host) {
      upstreamHeaders.set('x-forwarded-host', host);
    }
  }
  return upstreamHeaders;
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
    return NextResponse.rewrite(new URL(`${pathname}${search}`, `${upstreamOrigin}/`), {
      request: {
        headers: buildApiProxyHeaders(request),
      },
    });
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
      "worker-src 'self'",
      "frame-src 'self'",
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

export const config: ProxyConfig = {
  matcher: [
    {
      source: '/((?!_next/static|_next/image|favicon.ico|icon.svg|pdf\\.worker\\.min\\.mjs).*)',
    },
  ],
};

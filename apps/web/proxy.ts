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
 * Thuật toán: Bảo Toàn Chuỗi Chuyển Tiếp Địa Chỉ IP Thực & Siêu Dữ Liệu Giao Thức Khi Rewrite `/api/v1` (`buildApiProxyHeaders`)
 * Mục đích: Đảm bảo Fastify phía sau reverse proxy (Cloudflare/Nginx/ALB) và container Next.js luôn nhận đủ
 * `x-forwarded-for`, `x-forwarded-proto`, `x-forwarded-host` và `user-agent` để ghi nhận chính xác IP thiết bị.
 */
function buildApiProxyHeaders(request: NextRequest): Headers {
  const upstreamHeaders = new Headers(request.headers);
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
  if (!upstreamHeaders.get('x-forwarded-proto')) {
    const proto = request.nextUrl.protocol.replace(/:$/u, '');
    if (proto === 'http' || proto === 'https') {
      upstreamHeaders.set('x-forwarded-proto', proto);
    }
  }
  if (!upstreamHeaders.get('x-forwarded-host')) {
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

export const config: ProxyConfig = {
  matcher: [
    {
      source: '/((?!_next/static|_next/image|favicon.ico|icon.svg).*)',
    },
  ],
};

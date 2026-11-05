import { NextResponse, type NextRequest, type ProxyConfig } from 'next/server';

/**
 * Thuật toán: Sinh Nonce Mật Mã Theo Từng Yêu Cầu & Gắn Chính Sách Bảo Mật Nội Dung Động (Per-Request Cryptographic Nonce CSP Proxy)
 * Mục đích: Loại bỏ hoàn toàn chỉ thị cho phép mã nội tuyến không an toàn khỏi `Content-Security-Policy` (`script-src` và `style-src`)
 *   trên môi trường Production, đồng thời cấp mã `nonce` ngẫu nhiên 128-bit cho các thẻ `<script>` hydration nội bộ của Next.js App Router.
 * Cơ chế hoạt động:
 *   - Sinh chuỗi `nonce` ngẫu nhiên 16 byte qua Web Crypto API (`crypto.getRandomValues`) và mã hóa Base64 cho mỗi HTTP Request.
 *   - Dựng tập nguồn kết nối hợp lệ `allowedConnectOrigins` từ `'self'` và biến môi trường API.
 *   - Đính kèm `x-nonce` và `Content-Security-Policy` vào cả Request Headers (để Server Components/RootLayout đọc và tự gán thuộc tính `nonce`)
 *     lẫn Response Headers trả về trình duyệt.
 */
function buildConnectSrcDirective(isProduction: boolean): string {
  const allowedConnectOrigins = new Set<string>(["'self'"]);
  const configuredApiUrl =
    process.env['NEXT_PUBLIC_API_BASE_URL'] ?? process.env['NEXT_PUBLIC_API_URL'];
  if (configuredApiUrl) {
    try {
      allowedConnectOrigins.add(new URL(configuredApiUrl).origin);
    } catch {
      // Fall back to self when build/runtime URL is malformed
    }
  }
  if (!isProduction) {
    allowedConnectOrigins.add('http://127.0.0.1:3001');
    allowedConnectOrigins.add('http://localhost:3001');
  }
  return `connect-src ${[...allowedConnectOrigins].join(' ')}`;
}

function generateRequestNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function proxy(request: NextRequest): NextResponse {
  const isProduction = process.env.NODE_ENV === 'production';
  const nonce = generateRequestNonce();

  const scriptSrc = isProduction
    ? `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`
    : `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval'`;

  const styleSrc = `style-src 'self' 'nonce-${nonce}'`;

  const cspHeaderValue =
    [
      "default-src 'self'",
      scriptSrc,
      styleSrc,
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      buildConnectSrcDirective(isProduction),
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
      source: '/((?!_next/static|_next/image|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};

import type { NextConfig } from 'next';
import { buildConnectSrcDirective, resolveInternalApiOrigin } from './lib/csp-config';

/**
 * Thuật toán: Cấu Hình Máy Chủ Next.js Độc Lập & Chính Sách Header Bảo Mật Phòng Thủ Sâu (`nextConfig`)
 * Mục đích: Bật chế độ đóng gói `standalone` cho container tinh gọn, định tuyến `/api/v1` cùng nguồn và gắn HSTS/CSP/XFO/COOP mặc định.
 */
const isDevelopment = process.env.NODE_ENV === 'development';
const scriptSrcDirective = isDevelopment ? "script-src 'self' 'unsafe-eval'" : "script-src 'self'";

const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value:
      [
        "default-src 'self'",
        scriptSrcDirective,
        "style-src 'self'",
        "img-src 'self' data: blob:",
        "font-src 'self' data:",
        buildConnectSrcDirective(),
        "frame-src 'self' blob:",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
      ].join('; ') + ';',
  },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains; preload',
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  {
    key: 'X-Frame-Options',
    value: 'DENY',
  },
  {
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin',
  },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), payment=()',
  },
  {
    key: 'Cross-Origin-Opener-Policy',
    value: 'same-origin',
  },
];

const nextConfig: NextConfig = {
  output: 'standalone',
  poweredByHeader: false,
  reactStrictMode: true,
  async rewrites() {
    const internalOrigin = resolveInternalApiOrigin();
    return [
      {
        source: '/api/v1/:path*',
        destination: `${internalOrigin}/api/v1/:path*`,
      },
    ];
  },
  async headers() {
    return [
      {
        source: '/:path*',
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;

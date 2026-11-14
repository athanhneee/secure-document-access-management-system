import type { NextConfig } from 'next';

/**
 * Thuật toán: Cấu Hình Máy Chủ Next.js Độc Lập, Ngưỡng Chờ Proxy 60 Giây & Header Bảo Mật Phòng Thủ Sâu (`nextConfig`)
 * Mục đích:
 *   - Bật chế độ đóng gói `standalone` cho container tinh gọn và nâng `experimental.proxyTimeout = 60_000` (kèm `proxyClientMaxBodySize = '64mb'`) để các luồng tải lên tài liệu mã hóa lên Cloudflare R2 và giao dịch PostgreSQL không bị ngắt kết nối sớm ở `~14s`.
 *   - Khử trùng lặp hoàn toàn với `proxy.ts`: để duy nhất `proxy.ts` định tuyến động `/api/v1` theo biến môi trường runtime và cấp phát `Content-Security-Policy` gắn `'nonce-...'` theo từng yêu cầu, còn `next.config.ts` quản lý tập header HSTS/XCTO/XFO/Referrer/Permissions/COOP bất biến.
 */
const securityHeaders = [
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
  experimental: {
    proxyTimeout: 60_000,
    proxyClientMaxBodySize: '64mb',
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

import type { NextConfig } from 'next';

/**
 * Thuật toán: Chuẩn Hóa Điểm Cuối Nội Bộ Phục Vụ Chuyển Tiếp Đường Dẫn `/api/v1` (Internal API Upstream Origin Resolver)
 * Mục đích: Định tuyến mọi yêu cầu cùng nguồn `/api/v1/:path*` từ trình duyệt sang máy chủ API hậu phương mà không cần mở rộng kết nối chéo nguồn.
 * Cơ chế hoạt động:
 *   - Ưu tiên đọc `INTERNAL_API_ORIGIN` hoặc `API_INTERNAL_URL`; nếu vắng mặt và `NEXT_PUBLIC_API_BASE_URL` là URL tuyệt đối `http(s)://`, cắt bỏ hậu tố `/api/v1` làm nguồn dự phòng, mặc định rơi về `http://127.0.0.1:3001`.
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
 * Thuật toán: Tổng Hợp Tập Nguồn Tin Cậy & Biên Dịch Chính Sách Bảo Mật Nội Dung CSP (Origin Allowlist & Security Headers Compiler)
 * Mục đích: Khóa chặt bề mặt tấn công trình duyệt chống XSS, Clickjacking, MIME-Sniffing và kết nối mạng trái phép ngay từ tầng HTTP Response Headers.
 * Cơ chế hoạt động:
 *   - Luôn bảo toàn `'self'` (phục vụ đường dẫn tương đối `/api/v1`), trích xuất `.origin` hợp lệ từ `NEXT_PUBLIC_API_BASE_URL`, `NEXT_PUBLIC_API_URL` và danh sách `CSP_CONNECT_ORIGINS` (phân tách bởi khoảng trắng/dấu phẩy); mở rộng loopback cục bộ khi không chạy production.
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
        // Ignore malformed URL token and preserve strict self origin
      }
    }
  }

  if (process.env.NODE_ENV !== 'production') {
    allowedConnectOrigins.add('http://127.0.0.1:3001');
    allowedConnectOrigins.add('http://localhost:3001');
  }

  return `connect-src ${[...allowedConnectOrigins].join(' ')}`;
}

// CONFLICT-RESOLVED: Chỉ cấp quyền biên dịch mã động cho môi trường phát triển cục bộ (NODE_ENV === 'development'), loại bỏ hoàn toàn trên production và test.
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

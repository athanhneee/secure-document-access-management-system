import type { NextConfig } from 'next';

const isProduction = process.env.NODE_ENV === 'production';
const configuredApiUrl =
  process.env['NEXT_PUBLIC_API_BASE_URL'] ?? process.env['NEXT_PUBLIC_API_URL'];

const allowedConnectOrigins = new Set<string>(["'self'"]);
if (configuredApiUrl) {
  try {
    allowedConnectOrigins.add(new URL(configuredApiUrl).origin);
  } catch {
    // Ignore malformed build-time URL and fall back to self
  }
}
if (!isProduction) {
  allowedConnectOrigins.add('http://127.0.0.1:3001');
  allowedConnectOrigins.add('http://localhost:3001');
}

const scriptSrcDirective = isProduction
  ? "script-src 'self' 'unsafe-inline'"
  : "script-src 'self' 'unsafe-inline' 'unsafe-eval'";

const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value:
      [
        "default-src 'self'",
        scriptSrcDirective,
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob:",
        "font-src 'self' data:",
        `connect-src ${[...allowedConnectOrigins].join(' ')}`,
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

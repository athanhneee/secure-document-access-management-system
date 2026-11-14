/**
 * Thuật toán: Chuẩn Hóa Nguồn API Nội Bộ & Tập Nguồn Kết Nối Hợp Lệ CSP (`resolveInternalApiOrigin`, `buildConnectSrcDirective`)
 * Mục đích: Dùng chung một nguồn chân lý duy nhất giữa `next.config.ts` và `proxy.ts` để định tuyến `/api/v1` và biên dịch chỉ thị `connect-src` an toàn.
 */
export function resolveInternalApiOrigin(): string {
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

export function buildConnectSrcDirective(): string {
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
        // Bỏ qua chuỗi URL sai định dạng, bảo toàn nguồn 'self' chặt chẽ
      }
    }
  }

  if (process.env.NODE_ENV !== 'production') {
    allowedConnectOrigins.add('http://127.0.0.1:3001');
    allowedConnectOrigins.add('http://localhost:3001');
    try {
      allowedConnectOrigins.add(new URL(resolveInternalApiOrigin()).origin);
    } catch {
      // Bỏ qua nếu INTERNAL_API_ORIGIN không hợp lệ
    }
  }

  return `connect-src ${[...allowedConnectOrigins].join(' ')}`;
}

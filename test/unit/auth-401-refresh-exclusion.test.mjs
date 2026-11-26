import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { isRefreshExcludedEndpoint } from '../../apps/web/lib/api-refresh.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');

/**
 * Thuật toán: Kiểm Chứng Ngoại Lệ Làm Mới Phiên `401` Cho Các Điểm Cuối Xác Thực Lại Thông Tin Đăng Nhập (`BUG-002`)
 * Mục đích: Đảm bảo `POST /auth/change-password` và `DELETE /auth/mfa` (cùng các biến thể tiền tố `/api/v1`, query string, URL đầy đủ)
 *   không bao giờ bị `apiClient` hiểu nhầm là hết hạn token dẫn tới gọi thừa `POST /auth/refresh`, lặp request đốt rate-limit
 *   hoặc phát tín hiệu `emitSessionExpired('session_revoked')` đá đăng xuất người dùng đang làm việc tại `/sessions`.
 */
describe('BUG-002 — Credential Re-Authentication 401 Exclusion & Sessions Inline Error Contract', () => {
  it('excludes /auth/change-password and exact /auth/mfa across relative, /api/v1, query, and absolute URLs', () => {
    const excludedEndpoints = [
      '/auth/change-password',
      '/auth/change-password/',
      'auth/change-password',
      '/api/v1/auth/change-password',
      'https://app.internal.test/api/v1/auth/change-password?retry=0',
      '/auth/mfa',
      '/auth/mfa/',
      'auth/mfa',
      '/auth/mfa?step=disable',
      '/api/v1/auth/mfa',
      'https://app.internal.test/api/v1/auth/mfa',
      '/auth/mfa/verify',
      '/auth/mfa/enroll',
      '/auth/mfa/enroll/verify',
      '/auth/mfa/methods',
      '/auth/mfa/webauthn/auth/verify',
      '/auth/webauthn/authenticate/verify',
      '/auth/login',
      '/auth/refresh',
      '/auth/logout',
      '/auth/logout-all',
      '/auth/logout-others',
      '/auth/forgot-password',
      '/auth/reset-password',
    ];

    for (const endpoint of excludedEndpoints) {
      assert.equal(
        isRefreshExcludedEndpoint(endpoint),
        true,
        `Expected ${endpoint} to be excluded from 401 auto-refresh & forced logout`,
      );
    }
  });

  it('keeps normal authenticated endpoints eligible for 401 token refresh and real revocation handling', () => {
    const protectedEndpoints = [
      '/users/me',
      '/documents',
      '/auth/sessions',
      '/auth/sessions/11111111-1111-4111-8111-111111111111',
      '/auth/session-posture',
      '/api/v1/auth/sessions',
      'https://app.internal.test/api/v1/users/me',
      '/auth/mfa-custom-report',
      '/auth/change-password-policy',
    ];

    for (const endpoint of protectedEndpoints) {
      assert.equal(
        isRefreshExcludedEndpoint(endpoint),
        false,
        `Expected ${endpoint} to remain eligible for 401 session refresh`,
      );
    }
  });

  it('guards both 401 refresh and forced session_revoked paths in api-client and renders inline form errors on /sessions', () => {
    const apiClientSrc = fs.readFileSync(path.join(repoRoot, 'apps/web/lib/api-client.ts'), 'utf8');
    const changePwSrc = fs.readFileSync(
      path.join(repoRoot, 'apps/web/app/sessions/change-password-card.tsx'),
      'utf8',
    );
    const mfaFactorsSrc = fs.readFileSync(
      path.join(repoRoot, 'apps/web/app/sessions/mfa-factors-card.tsx'),
      'utf8',
    );

    const exclusionMatches = apiClientSrc.match(/!isRefreshExcludedEndpoint\(endpoint\)/gu) ?? [];
    assert.ok(
      exclusionMatches.length >= 4,
      'apiClient and apiDownload must check !isRefreshExcludedEndpoint(endpoint) on both initial 401 and retried 401 branches',
    );

    assert.match(changePwSrc, /setFormError\(/u);
    assert.match(changePwSrc, /Mật khẩu hiện tại không chính xác/u);
    assert.match(changePwSrc, /<Alert variant="destructive"/u);
    assert.match(mfaFactorsSrc, /Mật khẩu hiện tại hoặc mã MFA \/ mã khôi phục không chính xác/u);
  });
});

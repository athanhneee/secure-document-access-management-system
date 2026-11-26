/**
 * Module: Shared Playwright E2E Role Session Mocking Helper
 * Thuật toán: Giả lập phiên đã xác thực theo vai trò RBAC (`SYSTEM_ADMIN`, `DOCUMENT_OWNER`, `DOCUMENT_READER`, `SECURITY_OFFICER`, `AUDITOR`)
 *   cho các bài kiểm thử trình duyệt thực thi trên cổng độc lập Next.js Standalone.
 */
import type { Page } from '@playwright/test';
import { ROLE_DEFAULT_PERMISSIONS } from '../apps/web/lib/role-permissions.js';

export type RoleName =
  'SYSTEM_ADMIN' | 'DOCUMENT_OWNER' | 'DOCUMENT_READER' | 'SECURITY_OFFICER' | 'AUDITOR';

export async function mockAuthenticatedRoleSession(page: Page, role: RoleName): Promise<void> {
  await page.context().addCookies([
    {
      name: 'sda_csrf',
      value: 'e2e-csrf-token-0000000000000000000000000000000000000000000',
      domain: '127.0.0.1',
      path: '/',
    },
  ]);

  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url());
    const pathname = url.pathname;

    if (pathname === '/api/v1/users/me') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          id: '10',
          username: `${role.toLowerCase()}_e2e`,
          fullName: `Nhân sự ${role}`,
          email: `${role.toLowerCase()}@corp.internal`,
          departmentId: '1',
          mfaEnabled: true,
          mfaVerified: true,
          status: 'ACTIVE',
          version: 1,
          roles: [role],
          permissions: [...ROLE_DEFAULT_PERMISSIONS[role]],
        }),
      });
      return;
    }

    if (pathname === '/api/v1/events/stream') {
      // Giữ kết nối SSE mở trong suốt vòng đời trang hiện tại để tránh EOF sớm kích hoạt EventSource.onerror -> POST /auth/refresh giả.
      await new Promise<void>((resolve) => {
        const done = () => {
          clearTimeout(timer);
          page.off('close', done);
          page.off('framenavigated', done);
          resolve();
        };
        const timer = setTimeout(done, 30_000);
        page.once('close', done);
        page.once('framenavigated', done);
      });
      await route.abort('aborted').catch(() => {});
      return;
    }

    if (pathname === '/api/v1/health/ready') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ status: 'ok' }),
      });
      return;
    }

    if (pathname === '/api/v1/audit-logs/verify') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          valid: true,
          checkedCount: 12,
          chainPartition: 'GLOBAL',
          issues: [],
        }),
      });
      return;
    }

    if (pathname === '/api/v1/auth/session-posture') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          mfaVerified: true,
          mfaEnabled: true,
          trustedNetwork: true,
          deviceTrust: true,
          riskScore: 0,
          sensitiveRiskScore: 0,
          riskThreshold: 80,
          highRiskBlocked: false,
          sensitiveHighRiskBlocked: false,
          topSecretRequiresMfa: false,
          riskFactors: [],
          evaluatedAt: '2026-11-05T10:05:00.000Z',
        }),
      });
      return;
    }

    if (pathname === '/api/v1/auth/sessions') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'sess-current-001',
              ipAddress: '127.0.0.1',
              userAgent: 'Playwright Chromium',
              createdAt: '2026-11-05T10:00:00.000Z',
              lastSeenAt: '2026-11-05T10:05:00.000Z',
              expiresAt: '2026-11-12T10:00:00.000Z',
              mfaVerified: true,
              isCurrent: true,
            },
          ],
        }),
      });
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: [], items: [], total: 0, page: 1, pageSize: 20 }),
    });
  });
}

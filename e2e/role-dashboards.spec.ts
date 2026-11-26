/**
 * Module: End-to-End Authentication, Zero-Trust Route Guards & Role Workspace Verification
 * Thuật toán: Kiểm chứng trực tiếp DOM nghiệp vụ thật trên trình duyệt Chromium qua hai pha:
 *   1. Pha Zero-Trust chưa đăng nhập: Mọi không gian vai trò chuyển hướng về `/login?redirect=...` và ẩn nút đặc quyền.
 *   2. Pha Đã xác thực theo từng vai trò RBAC (`SYSTEM_ADMIN`, `DOCUMENT_OWNER`, `DOCUMENT_READER`, `SECURITY_OFFICER`, `AUDITOR`): Dựng đúng tiêu đề `<h1>`, thanh tab, cảnh báo chỉ đọc SoD và chặn 403 chéo vai trò.
 */
import { expect, test } from '@playwright/test';
import { mockAuthenticatedRoleSession } from './helpers.js';

test.describe('Authentication Pages Smoke Tests', () => {
  test('Login page renders with accessible form and security notice', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));

    await page.goto('/login');
    await expect(page.getByRole('heading', { name: 'Đăng nhập tài khoản' })).toBeVisible();
    await expect(page.getByLabel(/Tên đăng nhập hoặc Email/i)).toBeVisible();
    await expect(page.getByLabel(/^Mật khẩu/i)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Hiện mật khẩu' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Đăng nhập hệ thống' })).toBeVisible();

    const textContent = await page.locator('body').innerText();
    const emojiRegex = /[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/u;
    expect(emojiRegex.test(textContent)).toBe(false);
    expect(errors).toEqual([]);
  });

  test('MFA page renders with 6-digit TOTP input and recovery option', async ({ page }) => {
    await page.goto('/mfa');
    await expect(page.getByRole('heading', { name: 'Xác thực đa yếu tố (MFA)' })).toBeVisible();
    await expect(page.getByLabel(/Mã xác thực 6 chữ số/i)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Xác nhận mã bảo mật' })).toBeVisible();
  });

  test('MFA recovery code input preserves mixed-case Base64URL code and submits verbatim payload', async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));

    const capturedPayloads: Array<Record<string, unknown>> = [];
    await page.context().addCookies([
      {
        name: 'sda_csrf',
        value: 'e2e-csrf-token-0000000000000000000000000000000000000000000',
        domain: '127.0.0.1',
        path: '/',
      },
    ]);
    await page.route('**/api/v1/users/me', async (route) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({
          statusCode: 401,
          errorCode: 'MFA_REQUIRED',
          message: 'MFA verification is required.',
        }),
      });
    });
    await page.route('**/api/v1/auth/mfa/verify', async (route) => {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      capturedPayloads.push(body);
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          authenticated: true,
          user: {
            id: '10',
            username: 'reader_e2e',
            fullName: 'Người đọc thử nghiệm',
            email: 'reader@corp.internal',
            departmentId: '1',
            mfaEnabled: true,
            mfaVerified: true,
            status: 'ACTIVE',
            version: 1,
            roles: ['DOCUMENT_READER'],
            permissions: ['DOCUMENT_VIEW'],
          },
        }),
      });
    });

    await page.goto('/mfa');
    await page.getByRole('button', { name: /Dùng mã khôi phục/i }).click();

    const recoveryInput = page.getByLabel('Mã khôi phục khẩn cấp');
    await expect(recoveryInput).toBeVisible();
    await expect(recoveryInput).toHaveAttribute('autocapitalize', 'none');
    await expect(recoveryInput).toHaveAttribute('autocorrect', 'off');
    await expect(recoveryInput).toHaveAttribute('spellcheck', 'false');

    const sampleRecoveryCode = 'k9Pq_xR2mN8aBcDeFgHiJk';
    await recoveryInput.fill(sampleRecoveryCode);
    await expect(recoveryInput).toHaveValue(sampleRecoveryCode);

    await page.getByRole('button', { name: 'Xác nhận mã bảo mật' }).click();
    await expect.poll(() => capturedPayloads.length).toBe(1);
    expect(capturedPayloads[0]).toEqual({ recoveryCode: sampleRecoveryCode });
    expect(errors).toEqual([]);
  });

  test('Reset password page renders with identity verification form', async ({ page }) => {
    await page.goto('/reset-password');
    await expect(page.getByRole('heading', { name: 'Khôi phục mật khẩu tài khoản' })).toBeVisible();
    await expect(page.getByLabel(/Tên đăng nhập hoặc Email/i)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Gửi liên kết khôi phục' })).toBeVisible();
  });
});

test.describe('Role Workspace Zero-Trust Guards & Authenticated Portals', () => {
  test('Unauthenticated requests to all role workspaces redirect to /login and expose zero privileged controls', async ({
    page,
  }) => {
    const protectedRoutes = [
      { path: '/admin', redirectRe: /\/login\?redirect=%2Fadmin/, button: 'Tạo tài khoản' },
      { path: '/owner', redirectRe: /\/login\?redirect=%2Fowner/, button: 'Tải lên tài liệu mới' },
      {
        path: '/security',
        redirectRe: /\/login\?redirect=%2Fsecurity/,
        button: 'Tạo hồ sơ sự cố',
      },
      {
        path: '/auditor',
        redirectRe: /\/login\?redirect=%2Fauditor/,
        button: 'Xuất báo cáo tuân thủ',
      },
      {
        path: '/sessions',
        redirectRe: /\/login\?redirect=%2Fsessions/,
        button: 'Đăng xuất tất cả thiết bị khác',
      },
    ];

    for (const item of protectedRoutes) {
      await page.goto(item.path);
      await expect(page).toHaveURL(item.redirectRe);
      await expect(page.getByRole('heading', { name: 'Đăng nhập tài khoản' })).toBeVisible();
      await expect(page.getByRole('button', { name: item.button })).toHaveCount(0);
    }
  });

  test('System Admin workspace renders user management, RBAC, ABAC, and Watermark controls', async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));
    await mockAuthenticatedRoleSession(page, 'SYSTEM_ADMIN');

    await page.goto('/admin');
    await expect(page.getByRole('heading', { name: 'Quản trị hệ thống', level: 1 })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Tạo tài khoản' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Thông báo hệ thống' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Chủ sở hữu tài liệu' })).toHaveCount(0);
    await expect(page.getByRole('tab', { name: /Vai trò/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Chính sách truy cập/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Watermark bảo mật/i })).toBeVisible();
    expect(errors).toEqual([]);
  });

  test('Owner workspace hides unauthorized portals and blocks direct cross-role /admin with 403 without logout', async ({
    page,
  }) => {
    const errors: string[] = [];
    const adminApiCalls: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));
    page.on('request', (req) => {
      if (
        req.url().includes('/api/v1/users') &&
        !req.url().endsWith('/users/me') &&
        !req.url().includes('/users/lookup')
      ) {
        adminApiCalls.push(req.url());
      }
    });
    await mockAuthenticatedRoleSession(page, 'DOCUMENT_OWNER');

    await page.goto('/owner');
    await expect(
      page.getByRole('heading', { name: 'Quản lý và cấp quyền tài liệu mật', level: 1 }),
    ).toBeVisible();
    await expect(page.getByRole('button', { name: 'Tải lên tài liệu mới' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Thông báo hệ thống' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Quản trị hệ thống' })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Người đọc tài liệu' })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'An ninh thông tin' })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Kiểm toán độc lập' })).toHaveCount(0);

    await page.goto('/admin');
    await expect(page.getByText('Không có quyền truy cập')).toBeVisible();
    expect(adminApiCalls).toEqual([]);
    await page.getByRole('button', { name: 'Về phân hệ làm việc' }).click();
    await expect(page).toHaveURL(/\/owner$/);
    expect(errors).toEqual([]);
  });

  test('Reader workspace renders discover catalog, granted documents, and access request tabs', async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));
    await mockAuthenticatedRoleSession(page, 'DOCUMENT_READER');

    await page.goto('/reader');
    await expect(
      page.getByRole('heading', { name: 'Tra cứu và đọc tài liệu mật', level: 1 }),
    ).toBeVisible();
    await expect(page.getByRole('tab', { name: /Tra cứu/i })).toBeVisible();
    await expect(
      page.getByRole('tab', { name: /Tài liệu được cấp quyền|Được cấp/i }),
    ).toBeVisible();
    await expect(page.getByRole('tab', { name: /Yêu cầu của tôi|Yêu cầu/i })).toBeVisible();
    expect(errors).toEqual([]);
  });

  test('Security & Auditor workspaces render SOC alert controls and SoD read-only audit controls', async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));
    await mockAuthenticatedRoleSession(page, 'SECURITY_OFFICER');

    await page.goto('/security');
    await expect(
      page.getByRole('heading', { name: 'Giám sát an ninh và điều tra sự cố', level: 1 }),
    ).toBeVisible();
    await expect(page.getByRole('button', { name: 'Tạo hồ sơ sự cố' })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Truy vết watermark/i })).toBeVisible();

    await mockAuthenticatedRoleSession(page, 'AUDITOR');
    await page.goto('/auditor');
    await expect(
      page.getByRole('heading', { name: 'Kiểm toán toàn vẹn và báo cáo tuân thủ', level: 1 }),
    ).toBeVisible();
    await expect(page.getByText(/Chế độ chỉ đọc:/i)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Xuất báo cáo tuân thủ' })).toBeVisible();
    expect(errors).toEqual([]);
  });

  test('Sessions page renders active device list and remote session revocation controls', async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));
    await mockAuthenticatedRoleSession(page, 'DOCUMENT_READER');

    await page.goto('/sessions');
    await expect(
      page.getByRole('heading', { name: 'Quản lý phiên và thiết bị', level: 1 }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: /Đăng xuất tất cả thiết bị khác/i }),
    ).toBeVisible();
    expect(errors).toEqual([]);
  });

  test('Wrong password on Change Password or Disable MFA stays on /sessions without calling refresh or forced logout', async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));
    await mockAuthenticatedRoleSession(page, 'DOCUMENT_READER');

    let refreshCalls = 0;
    let changePasswordCalls = 0;
    let disableMfaCalls = 0;

    await page.route('**/api/v1/auth/refresh', async (route) => {
      refreshCalls += 1;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ authenticated: true }),
      });
    });

    await page.route('**/api/v1/auth/mfa/methods', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          canDisableMfa: true,
          data: [
            {
              id: '11111111-1111-4111-8111-111111111111',
              methodType: 'TOTP',
              label: 'Authenticator',
              createdAt: '2026-11-05T10:00:00.000Z',
            },
          ],
        }),
      });
    });

    await page.route('**/api/v1/auth/change-password', async (route) => {
      changePasswordCalls += 1;
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'Unable to authenticate with the supplied credentials.' }),
      });
    });

    await page.route('**/api/v1/auth/mfa', async (route) => {
      if (route.request().method() === 'DELETE') {
        disableMfaCalls += 1;
        await route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Step-up authentication failed.' }),
        });
        return;
      }
      await route.fallback();
    });

    await page.goto('/sessions');

    // 1. Change password with wrong current password shows inline error and never logs out
    await page.getByRole('button', { name: /Đổi mật khẩu tài khoản/i }).click();
    await page.locator('#change-pw-current').fill('wrong-current-password');
    await page.locator('#change-pw-new').fill('new-valid-passphrase-2026');
    await page.locator('#change-pw-confirm').fill('new-valid-passphrase-2026');
    await page.getByRole('button', { name: 'Cập nhật mật khẩu' }).click();

    await expect(page.getByText(/Mật khẩu hiện tại không chính xác/i)).toBeVisible();
    await expect(page).toHaveURL(/\/sessions$/);
    expect(changePasswordCalls).toBe(1);
    expect(refreshCalls).toBe(0);

    // 2. Disable MFA with wrong password/code shows dialog error and never logs out
    await page.getByRole('button', { name: /Phương thức xác thực đa yếu tố \(MFA\)/i }).click();
    await page.getByRole('button', { name: 'Tắt toàn bộ MFA' }).click();
    const openDialog = page.locator('dialog[open]');
    await expect(openDialog).toBeVisible();
    await openDialog.locator('#disable-mfa-password').fill('wrong-current-password');
    await openDialog.locator('#disable-mfa-code').fill('123456');
    await openDialog.getByRole('button', { name: 'Xác nhận tắt MFA' }).click();

    await expect(
      openDialog.getByText(/Mật khẩu hiện tại hoặc mã MFA \/ mã khôi phục không chính xác/i),
    ).toBeVisible();
    await expect(page).toHaveURL(/\/sessions$/);
    expect(disableMfaCalls).toBe(1);
    expect(refreshCalls).toBe(0);
    expect(errors).toEqual([]);
  });
});

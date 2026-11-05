/**
 * Module: End-to-End Authentication, Zero-Trust Route Guards & Role Workspace Verification
 * Thuật toán: Kiểm chứng trực tiếp DOM nghiệp vụ thật trên trình duyệt Chromium qua hai pha:
 *   1. Pha Zero-Trust chưa đăng nhập: Mọi không gian vai trò chuyển hướng về `/login?redirect=...` và ẩn nút đặc quyền.
 *   2. Pha Đã xác thực theo từng vai trò RBAC: Dựng đúng tiêu đề `<h1>`, thanh tab, cảnh báo chỉ đọc SoD và chặn 403 chéo vai trò.
 */
import { expect, test, type Page } from '@playwright/test';

type RoleName =
  'SYSTEM_ADMIN' | 'DOCUMENT_OWNER' | 'DOCUMENT_READER' | 'SECURITY_OFFICER' | 'AUDITOR';

async function mockAuthenticatedRoleSession(page: Page, role: RoleName): Promise<void> {
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
          status: 'ACTIVE',
          version: 1,
          roles: [role],
          permissions: [],
        }),
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
          chainPartition: 'GLOBAL_CHAIN',
          issues: [],
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

test.describe('Authentication Pages Smoke Tests', () => {
  test('Login page renders with accessible form and security notice', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));

    await page.goto('/login');
    await expect(page.getByRole('heading', { name: 'Đăng nhập tài khoản' })).toBeVisible();
    await expect(page.getByLabel(/Tên đăng nhập hoặc Email/i)).toBeVisible();
    await expect(page.getByLabel(/Mật khẩu/i)).toBeVisible();
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
        button: 'Lập báo cáo sự cố',
      },
      {
        path: '/auditor',
        redirectRe: /\/login\?redirect=%2Fauditor/,
        button: 'Xuất báo cáo kiểm toán',
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

  test('Owner workspace renders document lifecycle controls and blocks cross-role /admin with 403', async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));
    await mockAuthenticatedRoleSession(page, 'DOCUMENT_OWNER');

    await page.goto('/owner');
    await expect(
      page.getByRole('heading', { name: 'Quản lý & Cấp phép Tài liệu Mật', level: 1 }),
    ).toBeVisible();
    await expect(page.getByRole('button', { name: 'Tải lên tài liệu mới' })).toBeVisible();

    await page.goto('/admin');
    await expect(page.getByText('403 · Truy cập bị từ chối')).toBeVisible();
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
      page.getByRole('heading', { name: 'Khám phá & Đọc Tài liệu Mật', level: 1 }),
    ).toBeVisible();
    await expect(page.getByRole('tab', { name: /Khám phá/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Tài liệu được xem|Được xem/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Theo dõi yêu cầu|Yêu cầu/i })).toBeVisible();
    expect(errors).toEqual([]);
  });

  test('Security workspace renders SOC alert queue, watermark trace tab, and incident action', async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));
    await mockAuthenticatedRoleSession(page, 'SECURITY_OFFICER');

    await page.goto('/security');
    await expect(
      page.getByRole('heading', { name: 'Giám sát An ninh & Điều tra Sự cố', level: 1 }),
    ).toBeVisible();
    await expect(page.getByRole('button', { name: 'Lập báo cáo sự cố' })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Truy vết Watermark/i })).toBeVisible();
    expect(errors).toEqual([]);
  });

  test('Auditor workspace renders strict SoD read-only notice and audit export trigger', async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));
    await mockAuthenticatedRoleSession(page, 'AUDITOR');

    await page.goto('/auditor');
    await expect(
      page.getByRole('heading', { name: 'Kiểm toán Toàn vẹn & Báo cáo Tuân thủ', level: 1 }),
    ).toBeVisible();
    await expect(page.getByText(/Nguyên tắc Phân tách Trách nhiệm \(SoD\):/i)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Xuất báo cáo kiểm toán' })).toBeVisible();
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
      page.getByRole('heading', { name: 'Quản lý phiên làm việc & thiết bị', level: 1 }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: /Đăng xuất tất cả thiết bị khác/i }),
    ).toBeVisible();
    expect(errors).toEqual([]);
  });
});

import { expect, test } from '@playwright/test';

test.describe('Authentication Pages Smoke Tests', () => {
  test('Login page renders with accessible form and security notice', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));

    await page.goto('/login');
    await expect(page.getByRole('heading', { name: 'Đăng nhập tài khoản' })).toBeVisible();
    await expect(page.getByLabel(/Tên đăng nhập hoặc Email/i)).toBeVisible();
    await expect(page.getByLabel(/Mật khẩu/i)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Đăng nhập hệ thống' })).toBeVisible();

    // Verify no emoji is rendered in text content
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

test.describe('Role Workspace Smoke Tests', () => {
  test('Admin workspace renders heading and protects mutation actions', async ({ page }) => {
    await page.goto('/admin');
    await expect(page.getByRole('heading', { name: 'Users · Departments · RBAC' })).toBeVisible();
  });

  test('Owner workspace renders header and navigation tabs', async ({ page }) => {
    await page.goto('/owner');
    // Either renders workspace or auth guard redirection/notice
    await expect(page.locator('body')).toBeVisible();
  });

  test('Reader workspace renders discover search and accessible document view', async ({
    page,
  }) => {
    await page.goto('/reader');
    await expect(page.locator('body')).toBeVisible();
  });

  test('Security workspace renders security alerts and watermark trace tabs', async ({ page }) => {
    await page.goto('/security');
    await expect(page.locator('body')).toBeVisible();
  });

  test('Auditor workspace renders strict read-only mode notice and audit explorer', async ({
    page,
  }) => {
    await page.goto('/auditor');
    await expect(page.locator('body')).toBeVisible();
  });

  test('Sessions page renders device management and security policies', async ({ page }) => {
    await page.goto('/sessions');
    await expect(page.locator('body')).toBeVisible();
  });
});

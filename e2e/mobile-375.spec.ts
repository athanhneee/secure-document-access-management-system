/**
 * Module: Mobile 375x667 Responsive Layout, Multi-Row TabsList & Top-Layer Dialog Error E2E Suite
 * Thuật toán: Kiểm chứng trực tiếp bố cục di động hẹp (`375x667`) trên trình duyệt thật qua hai bất biến giao diện cốt lõi:
 *   1. Không tràn ngang (`document.documentElement.scrollWidth <= 375`) trên cổng công khai và cả 5 phân hệ RBAC, đồng thời thanh `role="tablist"` đa dòng không đè lấp `role="tabpanel"`.
 *   2. Lỗi nghiệp vụ/API phát sinh khi hộp thoại `.showModal()` đang mở phải hiển thị trực tiếp bên trong `dialog[open]` (`DialogErrorContext`), không bị che khuất sau lớp phủ `::backdrop`.
 */
import { expect, test } from '@playwright/test';
import { mockAuthenticatedRoleSession } from './helpers.js';

test.use({ viewport: { width: 375, height: 667 } });

test.describe('Mobile 375x667 Layout & Top-Layer Modal Error Verification', () => {
  test('Public pages and all 5 role workspaces have zero horizontal overflow and non-overlapping multi-row TabsList', async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    for (const publicPath of ['/', '/login']) {
      await page.goto(publicPath);
      const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
      expect(scrollWidth, `Horizontal overflow on ${publicPath}`).toBeLessThanOrEqual(375);
    }

    const roleRoutes = [
      { path: '/admin', role: 'SYSTEM_ADMIN' as const },
      { path: '/owner', role: 'DOCUMENT_OWNER' as const },
      { path: '/reader', role: 'DOCUMENT_READER' as const },
      { path: '/security', role: 'SECURITY_OFFICER' as const },
      { path: '/auditor', role: 'AUDITOR' as const },
    ];

    for (const item of roleRoutes) {
      await page.unrouteAll({ behavior: 'ignoreErrors' });
      await mockAuthenticatedRoleSession(page, item.role);
      await page.goto(item.path);

      const tablist = page.getByRole('tablist').first();
      await expect(tablist).toBeVisible();

      const tabpanel = page.getByRole('tabpanel').first();
      await expect(tabpanel).toBeVisible();

      const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
      expect(scrollWidth, `Horizontal overflow on ${item.path}`).toBeLessThanOrEqual(375);

      const tablistBox = await tablist.boundingBox();
      const tabpanelBox = await tabpanel.boundingBox();
      expect(tablistBox).not.toBeNull();
      expect(tabpanelBox).not.toBeNull();
      if (tablistBox && tabpanelBox) {
        expect(tablistBox.y + tablistBox.height).toBeLessThanOrEqual(tabpanelBox.y + 4);
      }
    }

    expect(errors).toEqual([]);
  });

  test('API validation errors render visibly inside open <dialog> top-layer on 375px viewport', async ({
    page,
  }) => {
    await mockAuthenticatedRoleSession(page, 'SECURITY_OFFICER');
    await page.route('**/api/v1/incidents', async (route) => {
      if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Lỗi kiểm tra Top-Layer Modal' }),
        });
        return;
      }
      await route.fallback();
    });

    await page.goto('/security');
    await page.getByRole('button', { name: 'Tạo hồ sơ sự cố' }).click();

    const openDialog = page.locator('dialog[open]');
    await expect(openDialog).toBeVisible();

    await openDialog.locator('#inc-title').fill('Nghi vấn truy cập trái phép');
    await openDialog
      .locator('#inc-summary')
      .fill('Phát hiện nhiều truy vấn tải tài liệu mật bất thường từ dải mạng lạ.');
    await openDialog.getByRole('button', { name: 'Tạo hồ sơ sự cố' }).click();

    const modalAlert = openDialog.getByRole('alert');
    await expect(modalAlert).toBeVisible();
    await expect(modalAlert).toContainText('Lỗi kiểm tra Top-Layer Modal');

    const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(scrollWidth).toBeLessThanOrEqual(375);
  });
});

import { expect, test } from '@playwright/test';

const apiUrl = `http://127.0.0.1:${process.env['E2E_API_PORT'] ?? '3101'}`;

test('Vietnamese landing renders without browser errors', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.goto('/');
  await expect(
    page.getByRole('heading', { name: 'Hệ thống truy cập tài liệu mật', level: 1 }),
  ).toBeVisible();
  await expect(page.getByText('Kiểm soát truy cập sẵn sàng', { exact: true })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'vi');
  expect(errors).toEqual([]);
});

test('HTTP liveness contains only public health information', async ({ request }) => {
  const response = await request.get(`${apiUrl}/api/v1/health/live`);
  expect(response.status()).toBe(200);
  expect(await response.json()).toEqual({ status: 'ok' });
  expect(response.headers()['set-cookie']).toBeUndefined();
});

test('RBAC administration workspace renders and does not expose actions before authorization', async ({
  page,
}) => {
  await page.goto('/admin');
  await expect(page.getByRole('heading', { name: 'Users · Departments · RBAC' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Tạo tài khoản' })).toHaveCount(0);
});

test('unimplemented document API exposes no document data', async ({ request }) => {
  const response = await request.get(`${apiUrl}/api/v1/documents`);
  expect([401, 404]).toContain(response.status());
  const body: { statusCode?: number } = (await response.json()) as { statusCode?: number };
  expect([401, 404]).toContain(body.statusCode);
  expect(JSON.stringify(body)).not.toMatch(
    /password|encryption_key|storage_key|stack|documentContent/i,
  );
});

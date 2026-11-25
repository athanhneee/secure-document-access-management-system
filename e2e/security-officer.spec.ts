/**
 * Module: Comprehensive Playwright E2E Verification for SECURITY_OFFICER (`qa.security`) 8-Tab SOC Workspace & MFA Gate
 * Thuật toán: Kiểm chứng trực tiếp DOM, tương tác nút bấm, hộp thoại `.showModal()`, bộ lọc phân trang máy chủ, QR JSON Watermark,
 *   vòng đời sự cố `IN_REVIEW`, kiểm soát DLP fail-closed, UC32 Audit Anchors và UC09 Policy Simulator trên trình duyệt Chromium thật.
 */
import { expect, test } from '@playwright/test';
import { mockAuthenticatedRoleSession } from './helpers.js';

const SAMPLE_TOKEN_48 = `WM-${'a'.repeat(48)}`;
const SAMPLE_ALERT_ID = '324c1631-1111-4111-8111-000000000001';
const SAMPLE_INCIDENT_ID = 'inc-2026-e048be-uuid';

test.describe('qa.security (SECURITY_OFFICER) — Full 8-Tab Interactive E2E & MFA Hardening', () => {
  test('#27 — /mfa?enroll=0 hides first-time MFA enrollment option to prevent 403 MFA_ENROLLMENT_BLOCKED', async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    await page.goto('/mfa?enroll=0&redirect=%2Fsecurity');
    await expect(page.getByRole('heading', { name: 'Xác thực đa yếu tố (MFA)' })).toBeVisible();
    await expect(page.getByRole('button', { name: /Thiết lập MFA lần đầu/i })).toHaveCount(0);

    await page.goto('/mfa?redirect=%2Fsecurity');
    await expect(page.getByRole('button', { name: /Thiết lập MFA lần đầu/i })).toBeVisible();
    expect(errors).toEqual([]);
  });

  test('Full 8-tab SOC workflow: Alerts, Watermark QR JSON, Incidents IN_REVIEW, Sessions, Detection Rules, DLP Truthful Status, Audit Anchors UC32, Policy Simulator UC09', async ({
    page,
  }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    let lastDetectionRunBody: Record<string, unknown> | null = null;
    let lastStatusPatchBody: Record<string, unknown> | null = null;
    let reviewedIncidentCalled = false;
    let createdAnchorCalled = false;
    let verifiedWatermarkPath = '';

    await mockAuthenticatedRoleSession(page, 'SECURITY_OFFICER');

    // Override security endpoints with realistic live-like DTOs (Playwright LIFO route priority)
    await page.route('**/api/v1/security-alerts**', async (route) => {
      const url = new URL(route.request().url());
      const method = route.request().method();

      if (method === 'PATCH' && url.pathname.endsWith('/status')) {
        lastStatusPatchBody = route.request().postDataJSON() as Record<string, unknown>;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            id: SAMPLE_ALERT_ID,
            alertType: 'NETWORK_DLP_VIOLATION',
            severity: 'CRITICAL',
            status: lastStatusPatchBody?.['status'] ?? 'INVESTIGATING',
            title: 'Phát hiện rò rỉ dữ liệu mạng',
            description: '[Network DLP] [BLOCKED] Phát hiện từ khóa Tuyệt mật từ 10.20.30.40',
            ipAddress: '10.20.30.40',
            detectedAt: '2026-11-25T08:00:00.000Z',
            notes: [
              {
                id: 'n-1',
                authorName: 'qa.security',
                note: 'Ghi chú lịch sử ngày 14/11 đã khôi phục',
                createdAt: '2026-11-14T15:32:07.619Z',
              },
              ...(lastStatusPatchBody?.['investigationNote']
                ? [
                    {
                      id: 'n-2',
                      authorName: 'qa.security',
                      note: String(lastStatusPatchBody['investigationNote']),
                      createdAt: '2026-11-25T09:00:00.000Z',
                    },
                  ]
                : []),
            ],
          }),
        });
        return;
      }

      if (url.pathname === `/api/v1/security-alerts/${SAMPLE_ALERT_ID}`) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            id: SAMPLE_ALERT_ID,
            alertType: 'NETWORK_DLP_VIOLATION',
            severity: 'CRITICAL',
            status: 'OPEN',
            title: 'Phát hiện rò rỉ dữ liệu mạng',
            description: '[Network DLP] [BLOCKED] Phát hiện từ khóa Tuyệt mật từ 10.20.30.40',
            ipAddress: '10.20.30.40',
            detectedAt: '2026-11-25T08:00:00.000Z',
            notes: [
              {
                id: 'n-1',
                authorName: 'qa.security',
                note: 'Ghi chú lịch sử ngày 14/11 đã khôi phục',
                createdAt: '2026-11-14T15:32:07.619Z',
              },
            ],
            linkedAuditLogs: [
              {
                id: '9001',
                action: 'NETWORK_DLP_BLOCKED',
                occurredAt: '2026-11-25T08:00:00.000Z',
                outcome: 'DENIED',
                ipAddress: '10.20.30.40',
              },
            ],
          }),
        });
        return;
      }

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: SAMPLE_ALERT_ID,
              alertType: 'NETWORK_DLP_VIOLATION',
              severity: 'CRITICAL',
              status: 'OPEN',
              title: 'Phát hiện rò rỉ dữ liệu mạng',
              description: '[Network DLP] [BLOCKED] Phát hiện từ khóa Tuyệt mật từ 10.20.30.40',
              ipAddress: '10.20.30.40',
              detectedAt: '2026-11-25T08:00:00.000Z',
              notes: [
                {
                  id: 'n-1',
                  authorName: 'qa.security',
                  note: 'Ghi chú lịch sử ngày 14/11 đã khôi phục',
                  createdAt: '2026-11-14T15:32:07.619Z',
                },
              ],
            },
          ],
          total: 1,
          meta: { page: 1, pageSize: 20, total: 1 },
        }),
      });
    });

    await page.route('**/api/v1/security-operations/dlp-status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          gatewayHealth: 'ONLINE',
          workerReachable: true,
          icapEnabled: true,
          icapListening: true,
          enforcementMode: 'AUDIT_ONLY',
          totalDlpAlerts: 1,
          openDlpAlerts: 1,
          checkedAt: '2026-11-25T09:00:00.000Z',
        }),
      });
    });

    await page.route('**/api/v1/watermarks/verify/**', async (route) => {
      verifiedWatermarkPath = new URL(route.request().url()).pathname;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          verified: true,
          watermarkToken: SAMPLE_TOKEN_48,
          renderedText: 'TUYỆT MẬT | qa.reader | WM-aaaaaaaaaaaa',
          outputSha256Hash: '1'.repeat(64),
          generatedAt: '2026-11-25T08:30:00.000Z',
          document: {
            title: 'Báo cáo Chiến lược Quốc phòng',
            documentCode: 'DOC-2026-TOP',
            versionNo: 2,
            classificationName: 'TOP_SECRET',
            originalSha256Hash: '2'.repeat(64),
          },
          user: {
            fullName: 'Nguyễn Văn Đọc',
            username: 'qa.reader',
            email: 'qa.reader@sda.local',
            employeeCode: 'EMP-009',
          },
          session: {
            id: 'sess-wm-1',
            ipAddress: '10.10.10.22',
            userAgent: 'Mozilla/5.0 Chrome/130',
          },
          config: {
            name: 'Watermark Tuyệt Mật',
            opacityPercent: 30,
            includeQrCode: true,
          },
        }),
      });
    });

    await page.route('**/api/v1/incidents**', async (route) => {
      const url = new URL(route.request().url());
      const method = route.request().method();

      if (method === 'POST' && url.pathname.endsWith('/review')) {
        reviewedIncidentCalled = true;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ id: SAMPLE_INCIDENT_ID, status: 'IN_REVIEW' }),
        });
        return;
      }

      if (url.pathname === `/api/v1/incidents/${SAMPLE_INCIDENT_ID}`) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            id: SAMPLE_INCIDENT_ID,
            incidentCode: 'INC-2026-E048BE',
            title: 'Nghi vấn tải hàng loạt tài liệu mật',
            summary: 'Tóm tắt sự cố gốc từ SOC',
            closingNote: null,
            findings: 'Phát hiện tải liên tiếp 6 tệp trong 5 phút',
            impactAssessment: 'Nguy cơ rò rỉ mức Mật',
            status: reviewedIncidentCalled ? 'IN_REVIEW' : 'SUBMITTED',
            createdAt: '2026-11-25T07:00:00.000Z',
            submittedAt: '2026-11-25T07:30:00.000Z',
            actions: [
              {
                id: 'act-1',
                actionType: 'REVOKE_ACCESS',
                description: 'Thu hồi quyền truy cập khẩn cấp',
                completedAt: null,
              },
            ],
          }),
        });
        return;
      }

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: SAMPLE_INCIDENT_ID,
              incidentCode: 'INC-2026-E048BE',
              title: 'Nghi vấn tải hàng loạt tài liệu mật',
              summary: 'Tóm tắt sự cố gốc từ SOC',
              status: reviewedIncidentCalled ? 'IN_REVIEW' : 'SUBMITTED',
              createdAt: '2026-11-25T07:00:00.000Z',
              actions: [{ id: 'act-1', description: 'Thu hồi quyền', completedAt: null }],
            },
          ],
          total: 1,
          meta: { page: 1, pageSize: 20, total: 1 },
        }),
      });
    });

    await page.route('**/api/v1/access-sessions**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'sess-active-1',
              userId: '10',
              username: 'athanhnee',
              fullName: 'Anh Thành',
              documentId: 'doc-1',
              documentCode: 'DOC-2026-001',
              documentTitle: 'Kế hoạch Tài chính 2026',
              versionNo: 1,
              ipAddress: '10.0.0.15',
              userAgent: 'Chrome',
              status: 'ACTIVE',
              startedAt: '2026-11-25T08:00:00.000Z',
              lastActivityAt: '2026-11-25T08:15:00.000Z',
            },
          ],
          total: 17,
          activeCount: 1,
          meta: { page: 1, pageSize: 20, total: 17 },
        }),
      });
    });

    await page.route('**/api/v1/security-detection/**', async (route) => {
      const url = new URL(route.request().url());
      if (url.pathname.endsWith('/run')) {
        lastDetectionRunBody = route.request().postDataJSON() as Record<string, unknown>;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([]),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            ruleCode: 'OFF_HOURS_ACCESS',
            name: 'Truy cập tài liệu mật ngoài giờ',
            threshold: 1,
            windowMinutes: 60,
            cooldownMinutes: 30,
            severity: 'MEDIUM',
            isEnabled: true,
            parameters: { workStartHour: 7, workEndHour: 19, minClassificationRank: 2 },
          },
          {
            ruleCode: 'AUDIT_INTEGRITY_COMPROMISED',
            name: 'Vi phạm toàn vẹn chuỗi kiểm toán',
            threshold: 1,
            windowMinutes: 60,
            cooldownMinutes: 15,
            severity: 'CRITICAL',
            isEnabled: true,
            parameters: {},
          },
        ]),
      });
    });

    await page.route('**/api/v1/audit-logs/anchors**', async (route) => {
      if (route.request().method() === 'POST') {
        createdAnchorCalled = true;
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: '2',
            chainPartition: 'AUTH',
            anchorSequence: '55',
            entryHash: 'a'.repeat(64),
            signature: 'b'.repeat(64),
            signerKeyId: 'hmac-key-v1',
            status: 'VALID',
            anchoredAt: '2026-11-25T09:10:00.000Z',
          }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: '1',
              chainPartition: 'SECURITY_OPERATIONS',
              anchorSequence: '42',
              entryHash: 'c'.repeat(64),
              signature: 'd'.repeat(64),
              signerKeyId: 'hmac-key-v1',
              status: 'VALID',
              anchoredAt: '2026-11-25T08:00:00.000Z',
            },
          ],
        }),
      });
    });

    await page.route('**/api/v1/audit-logs?*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: '100',
              chainPartition: 'SECURITY_OPERATIONS',
              action: 'INCIDENT_REPORT_IN_REVIEW',
              actorUsername: 'qa.security',
              objectType: 'INCIDENT_REPORT',
              outcome: 'SUCCESS',
              ipAddress: '127.0.0.1',
              occurredAt: '2026-11-25T08:45:00.000Z',
            },
          ],
          pagination: { page: 1, totalPages: 1, total: 1 },
        }),
      });
    });

    await page.goto('/security');
    await expect(
      page.getByRole('heading', { name: 'Giám sát an ninh và điều tra sự cố', level: 1 }),
    ).toBeVisible();

    // Verify all 8 tabs are visible for SECURITY_OFFICER
    await expect(page.getByRole('tab', { name: /Cảnh báo/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Truy vết watermark/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Hồ sơ sự cố/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Phiên đọc/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Quy tắc phát hiện/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Giám sát DLP mạng/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Toàn vẹn & Neo Audit/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Mô phỏng ABAC/i })).toBeVisible();

    // Tab 1: Alerts Queue — real IP, Vietnamese rule label, detail modal with restored note & atomic status+note
    await expect(page.getByText('10.20.30.40')).toBeVisible();
    await expect(page.getByText('Vi phạm chống thất thoát dữ liệu mạng (DLP)')).toBeVisible();
    await page.getByRole('button', { name: 'Chi tiết' }).first().click();

    const alertDialog = page.locator('dialog[open]');
    await expect(alertDialog).toBeVisible();
    await expect(alertDialog).toContainText('Ghi chú lịch sử ngày 14/11 đã khôi phục');
    await expect(alertDialog).toContainText('[Network DLP] [BLOCKED]');
    await alertDialog.locator('#alert-status-select').selectOption('INVESTIGATING');
    await alertDialog.locator('#inv-note').fill('Đã cô lập máy trạm 10.20.30.40');
    await alertDialog.getByRole('button', { name: 'Cập nhật cảnh báo' }).click();
    await expect.poll(() => lastStatusPatchBody).not.toBeNull();
    expect(lastStatusPatchBody?.['status']).toBe('INVESTIGATING');
    expect(lastStatusPatchBody?.['investigationNote']).toBe('Đã cô lập máy trạm 10.20.30.40');
    await expect(alertDialog).toBeHidden();

    // Tab 2: Watermark Forensics — paste QR JSON & verify 8 forensic fields
    await page.getByRole('tab', { name: /Truy vết watermark/i }).click();
    const wmInput = page.locator('#wm-token-input');
    await wmInput.fill('../../etc/passwd');
    await page.getByRole('button', { name: /Đối soát nguồn gốc tài liệu/i }).click();
    await expect(page.getByText(/Mã watermark không đúng định dạng/i)).toBeVisible();

    await wmInput.fill(JSON.stringify({ token: SAMPLE_TOKEN_48, u: 'qa.reader' }));
    await page.getByRole('button', { name: /Đối soát nguồn gốc tài liệu/i }).click();
    await expect.poll(() => verifiedWatermarkPath).toContain(SAMPLE_TOKEN_48);
    await expect(page.getByText('Báo cáo Chiến lược Quốc phòng')).toBeVisible();
    await expect(page.getByText('qa.reader@sda.local')).toBeVisible();
    await expect(page.getByText('Tuyệt mật', { exact: true })).toBeVisible();
    await expect(page.getByText('Watermark Tuyệt Mật (độ mờ 30% · có mã QR)')).toBeVisible();
    await expect(page.getByText('TUYỆT MẬT | qa.reader | WM-aaaaaaaaaaaa')).toBeVisible();

    // Tab 3: Incidents — open INC-2026-E048BE, verify incomplete-action guard & transition -> IN_REVIEW
    await page.getByRole('tab', { name: /Hồ sơ sự cố/i }).click();
    await expect(page.getByText('INC-2026-E048BE')).toBeVisible();
    await page.getByRole('button', { name: 'Chi tiết' }).first().click();
    const incDialog = page.locator('dialog[open]');
    await expect(incDialog).toBeVisible();
    await expect(incDialog.locator('#inc-force-close')).toBeVisible();
    await incDialog.getByRole('button', { name: 'Chuyển xem xét' }).click();
    await expect.poll(() => reviewedIncidentCalled).toBe(true);
    await incDialog.getByRole('button', { name: 'Đóng', exact: true }).click();
    await expect(incDialog).toBeHidden();

    // Tab 4: Sessions — real activeCount / total (1 / 17)
    await page.getByRole('tab', { name: /Phiên đọc/i }).click();
    await expect(page.getByText('DOC-2026-001')).toBeVisible();
    await expect(page.getByText(/1 đang hoạt động/i)).toBeVisible();

    // Tab 5: Detection Rules — run manual detection without hardcoded windowMinutes: 60
    await page.getByRole('tab', { name: /Quy tắc phát hiện/i }).click();
    await page.getByRole('button', { name: /Quét bất thường ngay/i }).click();
    await expect.poll(() => lastDetectionRunBody).not.toBeNull();
    expect(lastDetectionRunBody?.['windowMinutes']).toBeUndefined();

    // Tab 6: Network DLP — truthful AUDIT_ONLY mode from /dlp-status (not hardcoded BLOCK!)
    await page.getByRole('tab', { name: /Giám sát DLP mạng/i }).click();
    await expect(page.getByText('Chỉ ghi nhận & cảnh báo')).toBeVisible();

    // Tab 7: Audit Integrity & Anchors (UC32)
    await page.getByRole('tab', { name: /Toàn vẹn & Neo Audit/i }).click();
    await expect(page.getByText('hmac-key-v1')).toBeVisible();
    await page.getByRole('button', { name: 'Tạo điểm neo HMAC' }).click();
    await expect.poll(() => createdAnchorCalled).toBe(true);

    // Tab 8: Policy Simulator (UC09) inside /security without losing SoD on /admin
    await page.getByRole('tab', { name: /Mô phỏng ABAC/i }).click();
    await expect(page.getByRole('tabpanel')).toBeVisible();

    // Confirm SoD: /admin stays strictly 403 without logging out
    await page.goto('/admin');
    await expect(page.getByText('Không có quyền truy cập')).toBeVisible();
    expect(errors).toEqual([]);
  });
});

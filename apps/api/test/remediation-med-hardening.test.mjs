import 'reflect-metadata';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import {
  BadRequestException,
  ForbiddenException,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { resolveActiveDetectionRules } from '../dist/modules/security-operations/detection-rule-defaults.js';
import { stageAndScanQuarantineUpload } from '../dist/modules/documents/ingestion-quarantine.helper.js';
import { stripForbiddenDownloadPermissions } from '../dist/modules/documents/document-classification-cascade.helper.js';
import { UsersService } from '../dist/modules/users/users.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';
import {
  formatForensicWatermarkText,
  resolveWatermarkConfig,
} from '../dist/modules/watermarks/watermark-crypto.helper.js';

test('[MED-03, MED-05, MED-07] Detection rules merge, watermark DB fallback & <=1000 slice, self-lock/disabled-unlock blocks, scan FAILED -> 503 & empty grant cascade', async () => {
  const mergedRules = await resolveActiveDetectionRules({
    detectionRuleConfig: {
      findMany: async () => [
        {
          rule_code: 'MASS_DOWNLOAD',
          name: 'Custom Mass Download',
          description: 'Overridden',
          is_enabled: false,
          severity: 'CRITICAL',
          threshold: 20,
          window_minutes: 5,
          cooldown_minutes: 60,
          parameters: {},
        },
      ],
    },
  });
  assert.equal(mergedRules.length, 6);
  assert.equal(mergedRules.find((r) => r.ruleCode === 'MASS_DOWNLOAD').threshold, 20);

  let callNo = 0;
  const wmCfg = await resolveWatermarkConfig(
    {
      watermarkConfig: {
        findFirst: async () =>
          ++callNo === 3
            ? {
                id: 77n,
                template_text: '{username}',
                opacity_percent: 30,
                rotation_degrees: -30,
                font_size: 12,
                color_hex: '#808080',
                include_qr_code: true,
                is_visible: true,
              }
            : null,
      },
    },
    9n,
  );
  assert.equal(wmCfg.id, 77n);
  const longText = formatForensicWatermarkText(
    `${'{username}-'.repeat(200)}`,
    { id: 1n, username: 'long.user.account' },
    { id: randomUUID(), title: 'Doc', requireWatermark: true },
    'WM-1234567890abcdef',
  );
  assert.ok(longText.length <= 1000);

  const usersMap = new Map([
    [
      1n,
      {
        id: 1n,
        username: 'admin',
        full_name: 'Admin',
        department_id: 1n,
        status: 'ACTIVE',
        version: 0,
      },
    ],
    [
      2n,
      {
        id: 2n,
        username: 'disabled.u',
        full_name: 'Disabled',
        department_id: 1n,
        status: 'DISABLED',
        version: 1,
      },
    ],
  ]);
  const usersSvc = new UsersService(
    { hasPermission: async () => true, assertPermission: async () => {}, invalidateUser: () => {} },
    new PasswordService(),
    { record: async () => {} },
    {
      user: { findUnique: async ({ where }) => usersMap.get(where.id) ?? null },
      $transaction: async (fn) =>
        fn({ user: { findUnique: async ({ where }) => usersMap.get(where.id) ?? null } }),
    },
  );
  const adminActor = {
    userId: 1n,
    sessionId: 's',
    username: 'admin',
    roles: ['SYSTEM_ADMIN'],
    mfa: true,
  };
  assert.throws(
    () => usersSvc.lock(adminActor, 1n, 0, { ip: '127.0.0.1', correlationId: 'c1' }),
    ForbiddenException,
  );
  await assert.rejects(
    () => usersSvc.unlock(adminActor, 2n, 1, { ip: '127.0.0.1', correlationId: 'c2' }),
    BadRequestException,
  );

  const spoolFile = path.join(os.tmpdir(), `sda-spool-${randomUUID()}.pdf`);
  fs.writeFileSync(spoolFile, Buffer.from('%PDF-1.4 mock'));
  let compensated = false;
  try {
    await assert.rejects(
      () =>
        stageAndScanQuarantineUpload({
          database: {},
          logger: new Logger('ScanTest'),
          storage: { quarantineBucket: 'q', putObject: async () => {} },
          antivirus: { scan: async () => ({ status: 'FAILED', durationMs: 5 }) },
          audit: { record: async () => {} },
          compensation: {
            compensate: async () => {
              compensated = true;
            },
          },
          session: { storageKeysToDelete: [] },
          input: { principal: adminActor, context: { ip: '127.0.0.1', correlationId: 'c-scan' } },
          targetDocId: randomUUID(),
          spoolFilePath: spoolFile,
          validatedInfo: {
            extension: '.pdf',
            mimeType: 'application/pdf',
            sanitizedFilename: 'a.pdf',
          },
          totalBytes: 13,
          sha256Hash: 'a'.repeat(64),
        }),
      ServiceUnavailableException,
    );
    assert.equal(compensated, true);
  } finally {
    fs.rmSync(spoolFile, { force: true });
  }

  let permFindCall = 0;
  let revokedEmptyGrantIds = [];
  await stripForbiddenDownloadPermissions(
    {
      accessGrantPermission: {
        findMany: async () =>
          ++permFindCall === 1 ? [{ access_grant_id: 'grant-download-only' }] : [],
        deleteMany: async () => ({ count: 1 }),
      },
      accessGrant: {
        findMany: async () => [{ id: 'grant-download-only' }],
        update: async ({ where }) => {
          revokedEmptyGrantIds.push(where.id);
          return {};
        },
      },
      accessSession: { updateMany: async () => ({ count: 1 }) },
    },
    randomUUID(),
    1n,
    new Date(),
  );
  assert.deepEqual(revokedEmptyGrantIds, ['grant-download-only']);
});

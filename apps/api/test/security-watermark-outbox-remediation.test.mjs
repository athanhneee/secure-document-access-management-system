/**
 * @module SecurityWatermarkOutboxRemediationTests
 * Thuật toán: Kiểm chứng truy vết watermark 15 ký tự `WM-<12-hex>` (1 khớp thành công, 2 khớp báo `AMBIGUOUS_WATERMARK_TOKEN`),
 * khóa tắt QR cho `SECRET`/`TOP_SECRET`, làm phẳng biểu mẫu PDF, khử trùng lặp 5 phút và bộ đệm Epoch ABAC.
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { BadRequestException, ConflictException } from '@nestjs/common';
import { PDFDocument } from 'pdf-lib';
import { PolicyCache } from '../dist/modules/abac/policy-cache.js';
import { NotificationsService } from '../dist/modules/notifications/notifications.service.js';
import { WatermarkEngineService } from '../dist/modules/watermarks/watermark-engine.service.js';
import { WatermarksController } from '../dist/modules/watermarks/watermarks.controller.js';
import {
  assertHighClassificationWatermarkIntegrity,
  WatermarksService,
} from '../dist/modules/watermarks/watermarks.service.js';

test('Watermarks shortToken trace, SECRET QR guard, PDF flatten, Notifications 5m bucket & PolicyCache epoch', async () => {
  const fullToken = 'WM-aabbccddeeff00112233445566778899aabbccddeeff0011';
  const baseInst = {
    id: 1n,
    watermark_token: fullToken,
    rendered_text: 'trace',
    output_sha256_hash: 'h'.repeat(64),
    generated_at: new Date('2026-10-01T00:00:00Z'),
    users: {
      id: 9n,
      username: 'bob',
      full_name: 'Bob',
      employee_code: 'E9',
      email: 'bob@corp.test',
    },
    access_sessions: {
      id: 'sess-9',
      started_at: new Date('2026-10-01T00:00:00Z'),
      ip_address: '10.0.0.9',
      user_agent: 'UA',
    },
    document_versions: {
      version_no: 1,
      sha256_hash: 's'.repeat(64),
      document: { id: 'doc-9', title: 'Secret', document_code: 'D9' },
    },
    watermark_configs: { name: 'Cfg', opacity_percent: 25, font_size: 14, include_qr_code: true },
  };

  let matchRows = [baseInst];
  const wmService = new WatermarksService({
    watermarkInstance: {
      findMany: async ({ where, take }) => {
        assert.equal(where.watermark_token.startsWith, 'WM-aabbccddeeff');
        assert.equal(take, 2);
        return matchRows;
      },
      findUnique: async () => null,
    },
  });

  const singleTrace = await wmService.verifyWatermarkToken('WM-aabbccddeeff');
  assert.equal(singleTrace.watermarkToken, fullToken);

  matchRows = [
    baseInst,
    { ...baseInst, id: 2n, watermark_token: 'WM-aabbccddeeff999999999999999999999999999999999999' },
  ];
  await assert.rejects(
    () => wmService.verifyWatermarkToken('WM-aabbccddeeff'),
    (err) =>
      err instanceof ConflictException && err.getResponse()?.code === 'AMBIGUOUS_WATERMARK_TOKEN',
  );

  assert.throws(
    () =>
      assertHighClassificationWatermarkIntegrity({
        classificationCode: 'SECRET',
        includeQrCode: false,
        templateText: '{username} {shortToken}',
      }),
    BadRequestException,
  );
  assert.doesNotThrow(() =>
    assertHighClassificationWatermarkIntegrity({
      classificationCode: 'TOP_SECRET',
      includeQrCode: false,
      templateText: '{username} {watermarkToken}',
    }),
  );

  const pdfWithForm = await PDFDocument.create();
  const page = pdfWithForm.addPage([400, 300]);
  const textField = pdfWithForm.getForm().createTextField('coverField');
  textField.setText('Overlay');
  textField.addToPage(page, { x: 10, y: 10, width: 200, height: 50 });
  const stamped = await new WatermarkEngineService().applyWatermarkToPdf(
    Buffer.from(await pdfWithForm.save()),
    { id: 1n, username: 'u1' },
    { id: randomUUID(), title: 'Doc', requireWatermark: true },
    {
      id: 1n,
      template_text: '{username} {watermarkToken}',
      opacity_percent: 25,
      rotation_degrees: 30,
      font_size: 12,
      color_hex: '#333333',
      include_qr_code: true,
      is_visible: true,
    },
    fullToken,
  );
  const reloadedPdf = await PDFDocument.load(stamped.watermarkedBuffer);
  assert.equal(reloadedPdf.getForm().getFields().length, 0, 'PDF form fields must be flattened');

  const outboxKeys = new Set();
  const notifSvc = new NotificationsService({
    notification: { create: async ({ data }) => data },
    notificationOutbox: {
      findUnique: async ({ where }) =>
        outboxKeys.has(where.deduplication_key) ? { id: 'dup' } : null,
      create: async ({ data }) => {
        outboxKeys.add(data.deduplication_key);
        return data;
      },
    },
  });
  const firstAlert = await notifSvc.sendNotification({
    recipientId: 7n,
    notificationType: 'SOC',
    title: 'A',
    body: 'B',
    nowMs: 600_000,
  });
  const sameBucket = await notifSvc.sendNotification({
    recipientId: 7n,
    notificationType: 'SOC',
    title: 'A',
    body: 'B',
    nowMs: 600_000 + 60_000,
  });
  const nextBucket = await notifSvc.sendNotification({
    recipientId: 7n,
    notificationType: 'SOC',
    title: 'A',
    body: 'B',
    nowMs: 600_000 + 300_000,
  });
  assert.equal(firstAlert.isDuplicate, false);
  assert.equal(sameBucket.isDuplicate, true);
  assert.equal(nextBucket.isDuplicate, false);

  const policyCache = new PolicyCache();
  await policyCache.setCachedPolicyEpoch(12n, 2_000);
  assert.equal(await policyCache.getCachedPolicyEpoch(), 12n);
  await policyCache.invalidate('12');
  assert.equal(await policyCache.getCachedPolicyEpoch(), null);

  // Verify {shortToken} keeps WM-<12hex>, 16-hex prefix trace works, 404 writes DENIED WATERMARK_TRACE_PERFORMED audit,
  // controller normalizes bare hex, and stamped PDF contains ASCII WM-<48hex> for ICAP DLP detection
  assert.ok(stamped.watermarkedBuffer.toString('utf8').includes(fullToken));
  const engineText = new WatermarkEngineService().formatWatermarkText(
    '{username} | {shortToken}',
    { id: 1n, username: 'u1' },
    { id: randomUUID(), title: 'Doc', requireWatermark: true },
    fullToken,
  );
  assert.ok(engineText.includes('WM-aabbccddeeff'));

  const deniedAudits = [];
  const wm404Svc = new WatermarksService(
    {
      watermarkInstance: {
        findMany: async () => [],
        findUnique: async () => null,
      },
    },
    { writeLog: async (ev) => deniedAudits.push(ev) },
  );
  await assert.rejects(() =>
    wm404Svc.verifyWatermarkToken('WM-aabbccddeeff0011', {
      userId: 5n,
      sessionId: 's-5',
      username: 'sec.officer',
      roles: ['SECURITY_OFFICER'],
      mfa: true,
    }),
  );
  assert.equal(deniedAudits.length, 1);
  assert.equal(deniedAudits[0].action, 'WATERMARK_TRACE_PERFORMED');
  assert.equal(deniedAudits[0].outcome, 'DENIED');
  assert.equal(deniedAudits[0].reasonCode, 'WATERMARK_TOKEN_NOT_FOUND');

  let receivedVerifyToken = null;
  const wmCtrl = new WatermarksController(
    {
      verifyWatermarkToken: async (tok) => {
        receivedVerifyToken = tok;
        return { verified: true };
      },
    },
    { assertRequest: () => {} },
  );
  await wmCtrl.verifyWatermarkToken('AABBCCDDEEFF0011', {
    auth: { userId: 5n, sessionId: 's-5', username: 'sec', roles: ['SECURITY_OFFICER'], mfa: true },
    ip: '127.0.0.1',
    headers: {},
  });
  assert.equal(receivedVerifyToken, 'WM-aabbccddeeff0011');
  await assert.rejects(
    () =>
      wmCtrl.verifyWatermarkToken('WM-short', {
        auth: {
          userId: 5n,
          sessionId: 's-5',
          username: 'sec',
          roles: ['SECURITY_OFFICER'],
          mfa: true,
        },
        ip: '127.0.0.1',
        headers: {},
      }),
    BadRequestException,
  );
});

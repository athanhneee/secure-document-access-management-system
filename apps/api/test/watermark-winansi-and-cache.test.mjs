/**
 * @module WatermarkWinAnsiAndCacheTests
 * Thuật toán: Kiểm Chứng Chuyển Tự WinAnsi ASCII Không Sinh Ký Tự `?` Cho Dấu Chấm Giữa `·` / Gạch Ngang Typo
 * Và Cơ Chế Vô Hiệu Hóa Tức Thời Bộ Đệm Xem Trước PDF 30 Phút Khi Cập Nhật Cấu Hình Watermark.
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { PDFDocument } from 'pdf-lib';
import {
  storeCachedSessionPdf,
  tryLoadCachedSessionPdf,
} from '../dist/modules/documents/derivative-pdf-cache.helper.js';
import { toWinAnsiSafeText } from '../dist/modules/watermarks/watermark-crypto.helper.js';
import { WatermarkEngineService } from '../dist/modules/watermarks/watermark-engine.service.js';
import { WatermarksService } from '../dist/modules/watermarks/watermarks.service.js';

test('toWinAnsiSafeText transliterates middle dot, bullets, dashes, quotes, ellipsis & Vietnamese without turning punctuation into ?', () => {
  const input =
    'Nguyễn Văn Đạt · NV-001 | “Tài liệu Tối mật” — Mục 1…2 × 3\u00A0(‘Nội bộ’)\nDòng 2';
  const safe = toWinAnsiSafeText(input);

  assert.equal(
    safe,
    'Nguyen Van Dat - NV-001 | "Tai lieu Toi mat" - Muc 1...2 x 3 (\'Noi bo\') Dong 2',
  );
  assert.ok(!safe.includes('?'), 'Common punctuation and Vietnamese must never produce "?"');

  // Unmappable symbols (e.g. emoji) still degrade safely to "?" (1 code point via /u) so pdf-lib never throws
  assert.equal(toWinAnsiSafeText('OK \u{1F512}'), 'OK ?');
});

test('WatermarkEngine stamps PDF cleanly when template contains middle dot · and Vietnamese fullName', async () => {
  const engine = new WatermarkEngineService();
  const pdfDoc = await PDFDocument.create();
  pdfDoc.addPage([600, 400]);
  const originalBytes = Buffer.from(await pdfDoc.save());

  const result = await engine.applyWatermarkToPdf(
    originalBytes,
    {
      id: 12n,
      username: 'admin.vn',
      fullName: 'Đặng Minh Thành',
      employeeCode: 'NV-012',
    },
    {
      id: randomUUID(),
      documentCode: 'DOC-VN-01',
      title: 'Báo cáo mật',
      classificationName: 'Tuyệt mật',
      requireWatermark: true,
    },
    {
      id: 1n,
      template_text: '{fullName} · {employeeCode} — {classification} | {shortToken}',
      opacity_percent: 30,
      rotation_degrees: -35,
      font_size: 12,
      color_hex: '#991B1B',
      include_qr_code: true,
      is_visible: true,
    },
    'WM-abcdef0123456789abcdef0123456789abcdef0123456789',
  );

  assert.equal(result.pageCount, 1);
  assert.ok(result.watermarkedBuffer.length > originalBytes.length);
  const safeRendered = toWinAnsiSafeText(result.renderedText);
  assert.ok(safeRendered.includes('Dang Minh Thanh - NV-012 - Tuyet mat'));
  assert.ok(!safeRendered.includes('?'));
});

test('WatermarksService.updateConfig bumps cache epoch and immediately invalidates 30-minute derivative preview cache', async () => {
  const storeMap = new Map();
  const objectMap = new Map();

  const mockStateStore = {
    async getJson(ns, key) {
      return storeMap.get(`${ns}:${key}`) ?? null;
    },
    async putEphemeral(ns, key, val) {
      storeMap.set(`${ns}:${key}`, val);
    },
    async deleteKey(ns, key) {
      storeMap.delete(`${ns}:${key}`);
    },
  };
  const mockStorage = {
    derivativesBucket: 'derivatives',
    async putObject(bucket, key, buf) {
      objectMap.set(`${bucket}/${key}`, Buffer.from(buf));
    },
    async getObject(bucket, key) {
      const found = objectMap.get(`${bucket}/${key}`);
      if (!found) throw new Error('missing');
      return found;
    },
  };

  const sessionId = randomUUID();
  const versionId = 77n;
  const pdfPayload = Buffer.from('%PDF-1.7 sample-watermarked-content');

  // 1. Store preview PDF in derivative cache -> subsequent read is a HIT
  await storeCachedSessionPdf({
    storage: mockStorage,
    stateStore: mockStateStore,
    config: undefined,
    accessSessionId: sessionId,
    documentVersionId: versionId,
    pdfBuffer: pdfPayload,
    pageCount: 3,
    watermarkToken: 'WM-0123456789abcdef0123456789abcdef0123456789abcdef',
    outputSha256Hash: 'a'.repeat(64),
  });
  const hitBeforeUpdate = await tryLoadCachedSessionPdf({
    storage: mockStorage,
    stateStore: mockStateStore,
    config: undefined,
    accessSessionId: sessionId,
    documentVersionId: versionId,
  });
  assert.ok(hitBeforeUpdate, 'Expected derivative preview cache HIT before config update');
  assert.deepEqual(hitBeforeUpdate.pdfBuffer, pdfPayload);

  // 2. Admin updates watermark config -> bumps epoch in DistributedStateService
  const updatedAt = new Date('2026-11-25T16:00:00.000Z');
  const mockDb = {
    watermarkConfig: {
      findUnique: async () => ({
        id: 1n,
        name: 'Default',
        classification_level_id: null,
        include_qr_code: true,
        template_text: 'CONFIDENTIAL | {username}',
      }),
      update: async ({ data }) => ({
        id: 1n,
        name: 'Default',
        opacity_percent: data.opacity_percent ?? 35,
        font_size: data.font_size ?? 14,
        include_qr_code: data.include_qr_code ?? true,
        color_hex: data.color_hex ?? '#C13515',
        rotation_degrees: data.rotation_degrees ?? -45,
        template_text: data.template_text ?? 'CONFIDENTIAL | {username}',
        is_visible: true,
        updated_at: updatedAt,
      }),
    },
  };
  const wmService = new WatermarksService(mockDb, undefined, undefined, mockStateStore);
  const updated = await wmService.updateConfig(1n, {
    opacityPercent: 35,
    fontSize: 14,
    colorHex: '#C13515',
    rotationDegrees: -45,
  });
  assert.equal(updated.colorHex, '#C13515');
  assert.equal(updated.rotationDegrees, -45);

  // 3. Previously cached preview PDF is now invalidated (cache MISS)
  const missAfterUpdate = await tryLoadCachedSessionPdf({
    storage: mockStorage,
    stateStore: mockStateStore,
    config: undefined,
    accessSessionId: sessionId,
    documentVersionId: versionId,
  });
  assert.equal(
    missAfterUpdate,
    null,
    'Stale 30-minute preview cache entry must invalidate immediately after watermark config update',
  );

  // 4. Re-storing fresh PDF under new epoch hits cache again
  const refreshedPdf = Buffer.from('%PDF-1.7 refreshed-watermark-content');
  await storeCachedSessionPdf({
    storage: mockStorage,
    stateStore: mockStateStore,
    config: undefined,
    accessSessionId: sessionId,
    documentVersionId: versionId,
    pdfBuffer: refreshedPdf,
    pageCount: 3,
    watermarkToken: 'WM-0123456789abcdef0123456789abcdef0123456789abcdef',
    outputSha256Hash: 'b'.repeat(64),
  });
  const hitAfterRefresh = await tryLoadCachedSessionPdf({
    storage: mockStorage,
    stateStore: mockStateStore,
    config: undefined,
    accessSessionId: sessionId,
    documentVersionId: versionId,
  });
  assert.ok(hitAfterRefresh);
  assert.deepEqual(hitAfterRefresh.pdfBuffer, refreshedPdf);
});

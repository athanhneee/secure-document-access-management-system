import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { PDFDocument } from 'pdf-lib';
import { WatermarkEngineService } from '../dist/modules/watermarks/watermark-engine.service.js';
import { createSamplePdf } from './helpers/zip-builder.mjs';

test('WatermarkEngine — generates CSPRNG token matching WM-<48 hex chars>', () => {
  const engine = new WatermarkEngineService();
  const token1 = engine.generateWatermarkToken();
  const token2 = engine.generateWatermarkToken();

  assert.match(token1, /^WM-[0-9a-f]{48}$/);
  assert.match(token2, /^WM-[0-9a-f]{48}$/);
  assert.notEqual(token1, token2, 'Watermark tokens must be cryptographically unique');
});

test('WatermarkEngine — formats visible watermark text according to Prompt 13 requirement 4', () => {
  const engine = new WatermarkEngineService();
  const now = new Date('2026-09-23T10:00:00Z');
  const text = engine.formatWatermarkText(
    '{classification} | {fullName} ({employeeCode}) | {documentCode} | {timestamp} | {shortToken}',
    {
      id: 100n,
      username: 'alice',
      fullName: 'Alice Nguyen',
      employeeCode: 'EMP-0042',
    },
    {
      id: randomUUID(),
      documentCode: 'DOC-SEC-2026-001',
      title: 'Strategic Security Plan',
      classificationName: 'CONFIDENTIAL',
      requireWatermark: true,
    },
    'WM-abcdef0123456789abcdef0123456789abcdef0123456789',
    now,
  );

  assert.ok(text.includes('CONFIDENTIAL'), 'Must contain classification');
  assert.ok(text.includes('Alice Nguyen'), 'Must contain full name');
  assert.ok(text.includes('EMP-0042'), 'Must contain employee code');
  assert.ok(text.includes('DOC-SEC-2026-001'), 'Must contain document code');
  assert.ok(text.includes('2026-09-23 10:00:00 UTC'), 'Must contain UTC timestamp');
  assert.ok(text.includes('abcdef012345'), 'Must contain short token');
});

test('WatermarkEngine — applies visible watermark overlay and QR code to multi-page PDF', async () => {
  const engine = new WatermarkEngineService();
  const originalPdf = await createSamplePdf(3);

  const user = {
    id: 1n,
    username: 'bob_agent',
    fullName: 'Bob Security Officer',
    employeeCode: 'SEC-999',
  };
  const document = {
    id: randomUUID(),
    documentCode: 'DOC-CONF-777',
    title: 'Executive Financial Audit',
    classificationName: 'TOP_SECRET',
    requireWatermark: true,
  };
  const config = {
    id: 1n,
    template_text: 'TOP SECRET | {fullName} ({employeeCode}) | {timestamp} | {shortToken}',
    opacity_percent: 25,
    rotation_degrees: -35,
    font_size: 16,
    color_hex: '#cc0000',
    include_qr_code: true,
    is_visible: true,
  };

  const result = await engine.applyWatermarkToPdf(originalPdf, user, document, config);

  assert.equal(result.pageCount, 3, 'Must retain all 3 pages');
  assert.ok(result.watermarkedBuffer.length > 0, 'Derivative buffer must not be empty');
  assert.match(result.watermarkToken, /^WM-[0-9a-f]{48}$/);
  assert.match(result.outputSha256Hash, /^[0-9a-f]{64}$/);

  const loadedWatermarked = await PDFDocument.load(result.watermarkedBuffer);
  assert.equal(loadedWatermarked.getPageCount(), 3);
});

test('WatermarkEngine — extractPdfPage extracts exact page and rejects out-of-bounds', async () => {
  const engine = new WatermarkEngineService();
  const multiPagePdf = await createSamplePdf(5);

  const page2Buffer = await engine.extractPdfPage(multiPagePdf, 2);
  const loadedPage2 = await PDFDocument.load(page2Buffer);
  assert.equal(loadedPage2.getPageCount(), 1, 'Extracted page must have exactly 1 page');

  await assert.rejects(
    async () => {
      await engine.extractPdfPage(multiPagePdf, 10);
    },
    (err) => err.getStatus?.() === 400,
  );
});

test('WatermarkEngine — fail-closed security: watermark failure on required doc throws ForbiddenException', async () => {
  const engine = new WatermarkEngineService();
  const corruptPdf = Buffer.from('NOT A VALID PDF CONTENT');

  const user = { id: 1n, username: 'test_user' };
  const document = {
    id: randomUUID(),
    title: 'Important File',
    requireWatermark: true,
  };
  const config = {
    id: 1n,
    template_text: 'TEST',
    opacity_percent: 20,
    rotation_degrees: 0,
    font_size: 14,
    color_hex: '#000000',
    include_qr_code: false,
    is_visible: true,
  };

  await assert.rejects(
    async () => {
      await engine.applyWatermarkToPdf(corruptPdf, user, document, config);
    },
    (err) => err.getStatus?.() === 403,
  );
});

test('Concurrent Access — parallel watermark rendering operates safely without race conditions', async () => {
  const engine = new WatermarkEngineService();
  const pdfBuffer = await createSamplePdf(2);

  const concurrency = 8;
  const promises = [];

  for (let i = 0; i < concurrency; i++) {
    const user = {
      id: BigInt(i + 1),
      username: `user_${i}`,
      fullName: `User Number ${i}`,
      employeeCode: `EMP-000${i}`,
    };
    const document = {
      id: randomUUID(),
      documentCode: `DOC-PAR-${i}`,
      title: `Concurrent Document ${i}`,
      requireWatermark: true,
    };
    const config = {
      id: 1n,
      template_text: 'CONFIDENTIAL | {fullName} | {documentCode} | {shortToken}',
      opacity_percent: 20,
      rotation_degrees: -45,
      font_size: 14,
      color_hex: '#333333',
      include_qr_code: true,
      is_visible: true,
    };

    promises.push(engine.applyWatermarkToPdf(pdfBuffer, user, document, config));
  }

  const results = await Promise.all(promises);
  assert.equal(results.length, concurrency);

  const tokenSet = new Set(results.map((r) => r.watermarkToken));
  assert.equal(tokenSet.size, concurrency, 'All tokens generated concurrently must be distinct');

  for (const r of results) {
    assert.equal(r.pageCount, 2);
    assert.match(r.outputSha256Hash, /^[0-9a-f]{64}$/);
    assert.ok(r.watermarkedBuffer.length > 0);
  }
});

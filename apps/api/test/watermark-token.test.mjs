import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { PDFDocument } from 'pdf-lib';
import { WatermarkEngineService } from '../dist/modules/watermarks/watermark-engine.service.js';
import { WatermarksService } from '../dist/modules/watermarks/watermarks.service.js';

test('Watermark Token — generates cryptographically strong tokens with WM- prefix and high entropy', () => {
  const engine = new WatermarkEngineService();
  const token = engine.generateWatermarkToken();

  assert.ok(token.startsWith('WM-'));
  // WM- + 48 hex chars = 51 characters
  assert.equal(token.length, 51);
  assert.match(token, /^WM-[0-9a-f]{48}$/);
});

test('Watermark Token — generates 500 unique tokens with zero collisions', () => {
  const engine = new WatermarkEngineService();
  const tokenSet = new Set();
  const count = 500;

  for (let i = 0; i < count; i++) {
    const token = engine.generateWatermarkToken();
    tokenSet.add(token);
  }

  assert.equal(tokenSet.size, count, 'Expected zero collisions across 500 generated tokens.');
});

test('Watermark Text Formatter — accurately interpolates all metadata placeholders', () => {
  const engine = new WatermarkEngineService();
  const template =
    'CONFIDENTIAL: {fullName} ({employeeCode}) - {documentCode} - {timestamp} [{shortToken}] - {classification}';
  const token = 'WM-abcdef1234567890abcdef1234567890abcdef12345678';
  const fixedDate = new Date('2026-09-23T15:30:00.000Z');

  const formatted = engine.formatWatermarkText(
    template,
    {
      id: 42n,
      username: 'alice',
      fullName: 'Alice Nguyen',
      employeeCode: 'EMP-0042',
    },
    {
      id: '11111111-2222-3333-4444-555555555555',
      documentCode: 'DOC-CONF-2026',
      title: 'Bao Cao Mat Quy 3',
      classificationName: 'MAT',
      requireWatermark: true,
    },
    token,
    fixedDate,
  );

  assert.ok(formatted.includes('Alice Nguyen'));
  assert.ok(formatted.includes('EMP-0042'));
  assert.ok(formatted.includes('DOC-CONF-2026'));
  assert.ok(formatted.includes('2026-09-23 15:30:00 UTC'));
  assert.ok(formatted.includes('abcdef123456'));
  assert.ok(formatted.includes('MAT'));
});

test('Watermark Text Formatter — falls back gracefully when optional fields are omitted', () => {
  const engine = new WatermarkEngineService();
  const template = '{username} | {employeeCode} | {documentCode} | {classification}';
  const token = 'WM-1234567890123456';
  const docId = '99999999-8888-7777-6666-555555555555';

  const formatted = engine.formatWatermarkText(
    template,
    {
      id: 99n,
      username: 'bob',
    },
    {
      id: docId,
      title: 'Tai lieu khong ma',
      requireWatermark: true,
    },
    token,
  );

  assert.ok(formatted.includes('bob'));
  assert.ok(formatted.includes('UID:99'));
  assert.ok(formatted.includes(docId.slice(0, 8)));
  assert.ok(formatted.includes('CONFIDENTIAL'));
});

test('Watermark Engine — stamps visible watermark on a real PDF document', async () => {
  const engine = new WatermarkEngineService();

  // Create minimal valid 1-page PDF
  const pdfDoc = await PDFDocument.create();
  pdfDoc.addPage([600, 400]);
  const originalBytes = Buffer.from(await pdfDoc.save());

  const token = engine.generateWatermarkToken();
  const result = await engine.applyWatermarkToPdf(
    originalBytes,
    {
      id: 10n,
      username: 'carol',
      fullName: 'Carol Tran',
      employeeCode: 'EMP-0010',
    },
    {
      id: randomUUID(),
      title: 'Chien luoc nghiep vu',
      documentCode: 'DOC-BIZ-01',
      classificationName: 'TOI_MAT',
      requireWatermark: true,
    },
    {
      id: 1n,
      template_text: '{fullName} - {documentCode} - {timestamp}',
      opacity_percent: 30,
      rotation_degrees: 45,
      font_size: 14,
      color_hex: '#808080',
      include_qr_code: false,
      is_visible: true,
    },
    token,
  );

  assert.ok(result.watermarkedBuffer instanceof Buffer);
  assert.equal(result.watermarkToken, token);
  assert.equal(result.pageCount, 1);
  assert.ok(result.outputSha256Hash.length === 64);
  assert.notEqual(result.watermarkedBuffer.length, originalBytes.length);
});

test('Watermark Engine — fails closed if input PDF is corrupted or invalid', async () => {
  const engine = new WatermarkEngineService();
  const corruptBuffer = Buffer.from('NOT_A_VALID_PDF_STREAM_HEADER');

  await assert.rejects(
    async () =>
      engine.applyWatermarkToPdf(
        corruptBuffer,
        { id: 1n, username: 'test' },
        { id: randomUUID(), title: 'Test', requireWatermark: true },
        {
          id: 1n,
          template_text: '{username}',
          opacity_percent: 20,
          rotation_degrees: 0,
          font_size: 12,
          color_hex: '#000000',
          include_qr_code: false,
          is_visible: true,
        },
        'WM-test',
      ),
    /Failed to generate required security watermark/u,
  );
});

test('Watermark Forensic Tracing — verifyWatermarkToken returns complete forensic audit context', async () => {
  const token = 'WM-test-forensic-token-12345';
  const mockInstance = {
    id: 999n,
    watermark_token: token,
    rendered_text: 'Dave Miller (EMP-55) - DOC-01 - 2026-09-23 10:00:00 UTC',
    output_sha256_hash: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    generated_at: new Date('2026-09-23T10:00:00Z'),
    users: {
      id: 55n,
      username: 'dave',
      full_name: 'Dave Miller',
      employee_code: 'EMP-55',
      email: 'dave@corp.test',
    },
    access_sessions: {
      id: 'session-uuid-1',
      started_at: new Date('2026-09-23T09:55:00Z'),
      ip_address: '192.168.1.100',
      user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    },
    document_versions: {
      version_no: 2,
      sha256_hash: 'original-file-hash-64chars',
      document: {
        id: 'doc-uuid-1',
        title: 'Bao Cao Doanh Thu 2026',
        document_code: 'DOC-REV-2026',
      },
    },
    watermark_configs: {
      name: 'Default Confidential',
      opacity_percent: 25,
      font_size: 14,
      include_qr_code: true,
    },
  };

  const mockDb = {
    watermarkInstance: {
      findUnique: async ({ where }) => (where.watermark_token === token ? mockInstance : null),
    },
  };

  const service = new WatermarksService(mockDb);
  const verified = await service.verifyWatermarkToken(token);

  assert.equal(verified.watermarkToken, token);
  assert.equal(verified.user.username, 'dave');
  assert.equal(verified.user.employeeCode, 'EMP-55');
  assert.equal(verified.session.ipAddress, '192.168.1.100');
  assert.equal(verified.document.title, 'Bao Cao Doanh Thu 2026');
  assert.equal(verified.document.versionNo, 2);

  // Non-existent token throws NotFoundException
  await assert.rejects(
    async () => service.verifyWatermarkToken('WM-non-existent'),
    /Watermark token was not found/u,
  );
});

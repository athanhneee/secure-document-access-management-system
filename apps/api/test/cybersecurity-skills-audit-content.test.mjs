import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';
import { PDFDocument, StandardFonts } from 'pdf-lib';

process.env.STORAGE_MOCK = 'true';
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgresql://localhost:5432/secure_docs?schema=public';
process.env.APP_ENCRYPTION_MASTER_KEY = 'test-master-key-32-chars-long-000000000';

import { AppConfigService } from '../dist/config/config.service.js';
import { ZipBombGuardService } from '../dist/modules/documents/zip-bomb-guard.service.js';
import { WatermarkEngineService } from '../dist/modules/watermarks/watermark-engine.service.js';
import { WatermarksService } from '../dist/modules/watermarks/watermarks.service.js';
import { evaluatePolicy } from '../dist/modules/abac/policy-engine.js';
import { sanitizeCsvCell } from '../dist/modules/reports/csv-formula-sanitizer.js';
import { createZipBuffer } from './helpers/zip-builder.mjs';

function createTestConfig(overrides = {}) {
  return new AppConfigService({
    NODE_ENV: 'test',
    APP_ENCRYPTION_MASTER_KEY: 'test-master-key-32-chars-long-000000000',
    ZIP_MAX_TOTAL_UNCOMPRESSED_SIZE: 1_048_576,
    ZIP_MAX_ENTRIES: 50,
    ZIP_MAX_DEPTH: 5,
    ZIP_MAX_COMPRESSION_RATIO: 20,
    ...overrides,
  });
}

test('ZipBombGuardService blocks XXE DOCTYPE, external .rels TargetMode="External", and spoofed header size', async () => {
  const guard = new ZipBombGuardService(createTestConfig());

  const xxeDocx = createZipBuffer([
    { name: '[Content_Types].xml', content: '<?xml version="1.0"?><Types></Types>' },
    {
      name: 'word/document.xml',
      content:
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><w:document>&xxe;</w:document>',
    },
  ]);
  await assert.rejects(
    () => guard.inspectOfficeZip(xxeDocx, '.docx'),
    (err) => err instanceof BadRequestException,
  );

  const externalRelsDocx = createZipBuffer([
    { name: '[Content_Types].xml', content: '<?xml version="1.0"?><Types></Types>' },
    { name: 'word/document.xml', content: '<?xml version="1.0"?><w:document>Safe</w:document>' },
    {
      name: 'word/_rels/document.xml.rels',
      content:
        '<?xml version="1.0"?><Relationships><Relationship Id="rId1" Target="http://169.254.169.254/latest/meta-data" TargetMode="External"/></Relationships>',
    },
  ]);
  await assert.rejects(
    () => guard.inspectOfficeZip(externalRelsDocx, '.docx'),
    (err) => err instanceof BadRequestException,
  );

  const spoofedBomb = createZipBuffer(
    [
      { name: '[Content_Types].xml', content: '<?xml version="1.0"?><Types></Types>' },
      { name: 'word/document.xml', content: 'A'.repeat(4096) },
    ],
    { spoofUncompressedZero: true },
  );
  await assert.rejects(
    () => guard.inspectOfficeZip(spoofedBomb, '.docx', { maxTotalUncompressedSize: 1024 }),
    (err) => err instanceof BadRequestException,
  );
});

test('WatermarkEngineService renders Vietnamese diacritics cleanly and WatermarksService blocks disabling visibility', async () => {
  const pdfDoc = await PDFDocument.create();
  const page = pdfDoc.addPage([600, 800]);
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  page.drawText('Top Secret Test PDF', { x: 50, y: 700, size: 16, font });
  const rawPdfBytes = Buffer.from(await pdfDoc.save());

  const engine = new WatermarkEngineService({});
  const wmConfig = {
    id: 1n,
    template_text: '{{fullName}} - {{documentCode}} - {{token}}',
    opacity_percent: 30,
    rotation_degrees: -45,
    font_size: 24,
    color_hex: '#808080',
    include_qr_code: true,
    is_visible: true,
  };

  const watermarked = await engine.applyWatermarkToPdf(
    rawPdfBytes,
    {
      id: 12n,
      username: 'nguyenvandoc',
      fullName: 'Nguyễn Văn Đọc — Phòng Kỹ Thuật Đặc Biệt',
      employeeCode: 'NV-009',
    },
    {
      id: randomUUID(),
      documentCode: 'TL-ĐẶC-BIỆT-01',
      title: 'Báo cáo mật',
      classificationName: 'TUYỆT MẬT',
      requireWatermark: true,
    },
    wmConfig,
  );

  assert.ok(watermarked.watermarkedBuffer.subarray(0, 5).toString('ascii') === '%PDF-');
  assert.equal(watermarked.pageCount, 1);

  const watermarksService = new WatermarksService({});
  await assert.rejects(
    () => watermarksService.updateConfig(1n, { isVisible: false }),
    (err) => err instanceof BadRequestException,
  );
  await assert.rejects(
    () => watermarksService.updateConfig(1n, { opacityPercent: 2 }),
    (err) => err instanceof BadRequestException,
  );
});

test('evaluatePolicy matches IPv4-mapped IPv6 addresses against IPv4 CIDR and sanitizeCsvCell neutralizes pipe/whitespace formulas', () => {
  const nowIso = new Date().toISOString();
  const policy = {
    version: 'v1',
    requiredAttributes: ['environment.ip'],
    rules: [
      {
        id: '1',
        code: 'CORP-NET-PERMIT',
        effect: 'PERMIT',
        priority: 10,
        targetResource: 'DOCUMENT',
        targetAction: 'VIEW',
        combiningAlgorithm: 'DENY_OVERRIDES',
        validFrom: new Date(Date.now() - 60_000).toISOString(),
        validTo: null,
        obligations: [],
        groups: [
          {
            id: 1,
            conditions: [
              {
                id: 'c1',
                attribute: 'environment.ip',
                operator: 'CIDR_MATCH',
                expected: '10.10.0.0/16',
              },
            ],
          },
        ],
      },
    ],
  };

  const evalResult = evaluatePolicy(policy, {
    action: 'VIEW',
    resourceType: 'DOCUMENT',
    subject: {
      clearanceRank: 3,
      departmentId: '1',
      employmentStatus: 'ACTIVE',
      projects: [],
    },
    resource: {
      classificationRank: 2,
      ownerId: '10',
      departmentId: '1',
      category: 'GEN',
      status: 'ACTIVE',
    },
    environment: {
      currentTime: nowIso,
      ip: '::ffff:10.10.42.19',
      trustedNetwork: true,
      deviceTrust: true,
      mfa: true,
      riskScore: 0,
    },
  });

  assert.equal(evalResult.decision, 'PERMIT');

  assert.equal(sanitizeCsvCell('|cmd|/c calc'), "'|cmd|/c calc");
  assert.equal(sanitizeCsvCell('   =SUM(A1:A2)'), "'   =SUM(A1:A2)");
  assert.equal(sanitizeCsvCell('\n=HYPERLINK("http://evil")'), '\'\n=HYPERLINK("http://evil")');
  assert.equal(sanitizeCsvCell('Safe Normal Cell'), 'Safe Normal Cell');
});

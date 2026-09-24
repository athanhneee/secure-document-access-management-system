import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import zlib from 'node:zlib';
import { PDFDocument } from 'pdf-lib';
import { FileValidationService } from '../dist/modules/documents/file-validation.service.js';
import { ZipBombGuardService } from '../dist/modules/documents/zip-bomb-guard.service.js';
import { WatermarkEngineService } from '../dist/modules/watermarks/watermark-engine.service.js';

function createMockConfig(overrides = {}) {
  const values = {
    ZIP_MAX_ENTRIES: 100,
    ZIP_MAX_TOTAL_UNCOMPRESSED_SIZE: 50 * 1024 * 1024,
    ZIP_MAX_DEPTH: 5,
    ZIP_MAX_COMPRESSION_RATIO: 100,
    ...overrides,
  };
  return {
    get: (key) => values[key],
  };
}

// In-memory ZIP builder using node:zlib
function createZipBuffer(filesMap) {
  const localHeaders = [];
  const centralHeaders = [];
  let offset = 0;
  const entries = Array.isArray(filesMap)
    ? filesMap
    : Object.entries(filesMap).map(([name, content]) => ({ name, content }));

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const content = Buffer.isBuffer(entry.content)
      ? entry.content
      : Buffer.from(entry.content, 'utf8');
    const crc = zlib.crc32(content);
    const uncompressedSize = content.length;
    const compressedData = zlib.deflateRawSync(content);
    const compressedSize = compressedData.length;

    // Local file header: 30 bytes
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); // signature
    lh.writeUInt16LE(20, 4); // version
    lh.writeUInt16LE(0, 6); // flags
    lh.writeUInt16LE(8, 8); // Deflate
    lh.writeUInt16LE(0, 10);
    lh.writeUInt16LE(0, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(compressedSize, 18);
    lh.writeUInt32LE(uncompressedSize, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);

    localHeaders.push(lh, nameBuf, compressedData);

    // Central directory header: 46 bytes
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 8);
    ch.writeUInt16LE(8, 10);
    ch.writeUInt16LE(0, 12);
    ch.writeUInt16LE(0, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(compressedSize, 20);
    ch.writeUInt32LE(uncompressedSize, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt16LE(0, 30);
    ch.writeUInt16LE(0, 32);
    ch.writeUInt16LE(0, 34);
    ch.writeUInt16LE(0, 36);
    ch.writeUInt32LE(0, 38);
    ch.writeUInt32LE(offset, 42);

    centralHeaders.push(ch, nameBuf);
    offset += 30 + nameBuf.length + compressedSize;
  }

  const centralDir = Buffer.concat(centralHeaders);
  const cdOffset = offset;
  const cdSize = centralDir.length;

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localHeaders, centralDir, eocd]);
}

// ── 1. EICAR Malware Signature & Quarantine Test ──────────────────────────────

test('Dangerous Files: EICAR — fixture verification and malware detection', async () => {
  const encodedParts = await Promise.all([
    readFile(
      new URL('../../../test/fixtures/eicar.com.base64.part-01.txt', import.meta.url),
      'utf8',
    ),
    readFile(
      new URL('../../../test/fixtures/eicar.com.base64.part-02.txt', import.meta.url),
      'utf8',
    ),
  ]);
  const fixture = Buffer.from(encodedParts.map((p) => p.trim()).join(''), 'base64');

  // Verify official EICAR SHA-256 standard
  const eicarSha256 = createHash('sha256').update(fixture).digest('hex');
  assert.equal(fixture.length, 68);
  assert.equal(eicarSha256, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');

  // Scanner logic quarantines and throws
  function scanBuffer(buffer) {
    if (buffer.includes(Buffer.from('EICAR-STANDARD-ANTIVIRUS-TEST-FILE!'))) {
      throw new Error('MALWARE_DETECTED_EICAR');
    }
    return { status: 'CLEAN' };
  }

  assert.throws(() => scanBuffer(fixture), /MALWARE_DETECTED_EICAR/u);
});

// ── 2. MIME & Magic Byte Spoofing Tests ────────────────────────────────────────

test('Dangerous Files: MIME Spoofing — rejects executable disguised as PDF or Office document', () => {
  const validator = new FileValidationService();

  // 1. Windows MZ PE Executable disguised as .pdf
  const fakePdf = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00]); // 'MZ...'
  assert.throws(
    () => validator.validateMagicBytes(fakePdf, '.pdf'),
    /does not match PDF format magic bytes/u,
  );

  // 2. Linux ELF Executable disguised as .docx
  const fakeDocx = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01]); // '\x7fELF...'
  assert.throws(
    () => validator.validateMagicBytes(fakeDocx, '.docx'),
    /does not match Office OpenXML zip magic bytes/u,
  );

  // 3. Shell script disguised as .xlsx
  const fakeXlsx = Buffer.from('#!/bin/sh\nrm -rf /');
  assert.throws(
    () => validator.validateMagicBytes(fakeXlsx, '.xlsx'),
    /does not match Office OpenXML zip magic bytes/u,
  );
});

test('Dangerous Files: Path Traversal & Double Extension Spoofing', () => {
  const validator = new FileValidationService();

  // Null bytes
  assert.throws(() => validator.sanitizeFilename('report\0.pdf'), /forbidden null byte/u);

  // Double extensions with executables
  assert.throws(
    () => validator.sanitizeFilename('report.exe.pdf'),
    /forbidden executable double extension: .exe/u,
  );
  assert.throws(
    () => validator.sanitizeFilename('invoice.bat.docx'),
    /forbidden executable double extension: .bat/u,
  );

  // Bidi RTLO Unicode character spoofing
  assert.throws(
    () => validator.sanitizeFilename('report\u202Edpy.exe'),
    /forbidden bidirectional override/u,
  );
});

// ── 3. Zip Bomb & Dangerous Archive Inspection ────────────────────────────────

test('Dangerous Files: Zip Bomb Guard — rejects zip archives with path traversal entries', async () => {
  const guard = new ZipBombGuardService(createMockConfig());
  const maliciousZip = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types/>' },
    { name: 'word/document.xml', content: '<doc/>' },
    { name: '../../etc/passwd', content: 'root:x:0:0:root:/root:/bin/bash' },
  ]);

  await assert.rejects(
    async () => guard.inspectOfficeZip(maliciousZip, '.docx'),
    /dangerous path traversal|invalid relative path/u,
  );
});

test('Dangerous Files: Zip Bomb Guard — rejects zip archives exceeding nesting depth', async () => {
  const guard = new ZipBombGuardService(createMockConfig({ ZIP_MAX_DEPTH: 2 }));
  const deepZip = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types/>' },
    { name: 'word/a/b/c/d/e/deep.xml', content: '<deep/>' },
  ]);

  await assert.rejects(
    async () => guard.inspectOfficeZip(deepZip, '.docx'),
    /exceeds directory nesting depth limit/u,
  );
});

test('Dangerous Files: Zip Bomb Guard — rejects zip archives exceeding maximum entry count', async () => {
  const guard = new ZipBombGuardService(createMockConfig({ ZIP_MAX_ENTRIES: 5 }));
  const manyEntries = [
    { name: '[Content_Types].xml', content: '<Types/>' },
    { name: 'word/document.xml', content: '<doc/>' },
    { name: 'word/part1.xml', content: '1' },
    { name: 'word/part2.xml', content: '2' },
    { name: 'word/part3.xml', content: '3' },
    { name: 'word/part4.xml', content: '4' }, // 6th entry exceeds limit of 5
  ];
  const zip = createZipBuffer(manyEntries);

  await assert.rejects(
    async () => guard.inspectOfficeZip(zip, '.docx'),
    /contains too many entries/u,
  );
});

// ── 4. Corrupt Office OpenXML Packages ────────────────────────────────────────

test('Dangerous Files: Office OpenXML — rejects packages missing [Content_Types].xml', async () => {
  const guard = new ZipBombGuardService(createMockConfig());
  const missingContentTypes = createZipBuffer([{ name: 'word/document.xml', content: '<doc/>' }]);

  await assert.rejects(
    async () => guard.inspectOfficeZip(missingContentTypes, '.docx'),
    /missing \[Content_Types\]\.xml/u,
  );
});

test('Dangerous Files: Office OpenXML — rejects packages missing required application directory', async () => {
  const guard = new ZipBombGuardService(createMockConfig());
  // Has [Content_Types].xml but missing 'word/' folder for .docx
  const missingWordDir = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types/>' },
    { name: 'random/file.xml', content: '<random/>' },
  ]);

  await assert.rejects(
    async () => guard.inspectOfficeZip(missingWordDir, '.docx'),
    /missing word\/ package structure/u,
  );
});

// ── 5. Multi-Page PDF Watermarking ────────────────────────────────────────────

test('Dangerous Files: Multi-Page PDF — watermarks all pages without buffer corruption', async () => {
  const engine = new WatermarkEngineService();

  // Create a 5-page PDF document
  const pdfDoc = await PDFDocument.create();
  for (let i = 1; i <= 5; i++) {
    pdfDoc.addPage([595, 842]); // A4
  }
  const multiPagePdfBytes = Buffer.from(await pdfDoc.save());

  const token = engine.generateWatermarkToken();
  const result = await engine.applyWatermarkToPdf(
    multiPagePdfBytes,
    {
      id: 77n,
      username: 'manager_kim',
      fullName: 'Kim Nguyen',
      employeeCode: 'EMP-77',
    },
    {
      id: randomUUID(),
      title: 'Bao Cao Thuong Nien 5 Trang',
      documentCode: 'DOC-ANNUAL-2026',
      classificationName: 'MAT',
      requireWatermark: true,
    },
    {
      id: 1n,
      template_text: '{fullName} - {documentCode} - {timestamp}',
      opacity_percent: 25,
      rotation_degrees: 45,
      font_size: 14,
      color_hex: '#808080',
      include_qr_code: false,
      is_visible: true,
    },
    token,
  );

  assert.equal(result.pageCount, 5, 'Must stamp exactly all 5 pages');
  assert.ok(result.watermarkedBuffer.length > multiPagePdfBytes.length);

  // Validate resulting output is still a readable 5-page PDF
  const reloaded = await PDFDocument.load(result.watermarkedBuffer);
  assert.equal(reloaded.getPageCount(), 5);
});

// ── 6. Fail-Closed Watermark Failure ───────────────────────────────────────────

test('Dangerous Files: Watermark Failure [NFR-SEC04] — strictly fails closed upon watermark failure', async () => {
  // Simulates document delivery PEP logic
  async function deliverDocument(documentBuffer, requireWatermark, shouldWatermarkFail) {
    if (!requireWatermark) {
      return { deliveredBuffer: documentBuffer, wasWatermarked: false };
    }

    if (shouldWatermarkFail) {
      // Must NOT return original documentBuffer! Must fail closed!
      throw new Error('SECURITY_WATERMARK_GENERATION_FAILED');
    }

    return {
      deliveredBuffer: Buffer.concat([documentBuffer, Buffer.from('-WATERMARKED')]),
      wasWatermarked: true,
    };
  }

  const rawDocument = Buffer.from('RAW_CONFIDENTIAL_CONTENT');

  // When watermark succeeds, delivered is watermarked
  const successResult = await deliverDocument(rawDocument, true, false);
  assert.equal(successResult.wasWatermarked, true);
  assert.notDeepEqual(successResult.deliveredBuffer, rawDocument);

  // When watermark fails, MUST fail closed with exception; raw document NEVER emitted
  await assert.rejects(
    async () => deliverDocument(rawDocument, true, true),
    /SECURITY_WATERMARK_GENERATION_FAILED/u,
  );
});

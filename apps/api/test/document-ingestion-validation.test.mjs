import assert from 'node:assert/strict';
import { test } from 'node:test';
import { FileValidationService } from '../dist/modules/documents/file-validation.service.js';
import { ZipBombGuardService } from '../dist/modules/documents/zip-bomb-guard.service.js';
import { AntivirusScannerService } from '../dist/modules/documents/antivirus-scanner.service.js';
import {
  createZipBuffer,
  createSamplePdfBuffer,
  createSampleDocxBuffer,
  createSampleXlsxBuffer,
} from './helpers/zip-builder.mjs';
import { createMockConfig } from './helpers/document-ingestion-mocks.mjs';

test('FileValidationService: sanitizes filename, strips path traversal, null bytes, and Unicode spoofing', () => {
  const validator = new FileValidationService();

  assert.equal(validator.sanitizeFilename('annual_report_2026.pdf'), 'annual_report_2026.pdf');
  assert.equal(validator.sanitizeFilename('../../etc/passwd.pdf'), 'passwd.pdf');
  assert.equal(validator.sanitizeFilename('..\\..\\Windows\\System32\\secret.docx'), 'secret.docx');

  assert.throws(() => validator.sanitizeFilename('evil.pdf\0.docx'), /null byte/i);
  assert.throws(() => validator.sanitizeFilename('test\u0000.pdf'), /null byte/i);
  assert.throws(() => validator.sanitizeFilename('test\u202Efdp.exe'), /bidirectional override/i);

  const sanitized = validator.sanitizeFilename('report\u200B\uFEFF_q3.pdf');
  assert.equal(sanitized, 'report_q3.pdf');

  assert.throws(
    () => validator.sanitizeFilename('memo.exe.pdf'),
    /forbidden executable double extension/i,
  );
  assert.throws(
    () => validator.sanitizeFilename('script.sh.docx'),
    /forbidden executable double extension/i,
  );
  assert.throws(
    () => validator.sanitizeFilename('payload.php.xlsx'),
    /forbidden executable double extension/i,
  );
});

test('FileValidationService: strictly validates allowed extensions and declared MIME types', () => {
  const validator = new FileValidationService();

  assert.doesNotThrow(() => validator.validateExtensionAndMime('doc.pdf', 'application/pdf'));
  assert.doesNotThrow(() =>
    validator.validateExtensionAndMime(
      'doc.docx',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ),
  );
  assert.doesNotThrow(() =>
    validator.validateExtensionAndMime(
      'sheet.xlsx',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ),
  );
  assert.doesNotThrow(() =>
    validator.validateExtensionAndMime(
      'pres.pptx',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    ),
  );

  assert.throws(
    () => validator.validateExtensionAndMime('doc.doc', 'application/msword'),
    /unsupported file extension/i,
  );
  assert.throws(
    () => validator.validateExtensionAndMime('file.exe', 'application/x-msdownload'),
    /unsupported file extension/i,
  );
  assert.throws(
    () => validator.validateExtensionAndMime('image.png', 'image/png'),
    /unsupported file extension/i,
  );

  assert.throws(
    () => validator.validateExtensionAndMime('evil.pdf', 'text/html'),
    /MIME type 'text\/html' does not match expected/i,
  );
  assert.throws(
    () => validator.validateExtensionAndMime('fake.docx', 'application/octet-stream'),
    /does not match expected MIME/i,
  );
});

test('FileValidationService: rejects files when magic bytes do not match declared format', () => {
  const validator = new FileValidationService();

  const validPdf = Buffer.from('%PDF-1.4 sample');
  assert.doesNotThrow(() => validator.validateMagicBytes(validPdf, '.pdf'));

  const fakePdf = Buffer.from('<html><body>Not a PDF</body></html>');
  assert.throws(() => validator.validateMagicBytes(fakePdf, '.pdf'), /magic bytes/i);

  const validZipHeader = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00]);
  assert.doesNotThrow(() => validator.validateMagicBytes(validZipHeader, '.docx'));

  const fakeDocx = Buffer.from('MZ\x90\x00 This is an EXE');
  assert.throws(
    () => validator.validateMagicBytes(fakeDocx, '.docx'),
    /Office OpenXML zip magic bytes/i,
  );
});

test('ZipBombGuardService: accepts valid Office OpenXML package and rejects invalid zip or zip bombs', async () => {
  const config = createMockConfig({
    ZIP_MAX_ENTRIES: 10,
    ZIP_MAX_TOTAL_UNCOMPRESSED_SIZE: 100_000,
    ZIP_MAX_DEPTH: 3,
    ZIP_MAX_COMPRESSION_RATIO: 10,
  });
  const guard = new ZipBombGuardService(config);

  const validDocx = createSampleDocxBuffer('Executive briefing');
  await assert.doesNotReject(async () => {
    await guard.inspectOfficeZip(validDocx, '.docx');
  });

  const validXlsx = createSampleXlsxBuffer();
  await assert.doesNotReject(async () => {
    await guard.inspectOfficeZip(validXlsx, '.xlsx');
  });

  const genericZip = createZipBuffer([
    { name: 'hello.txt', content: 'World' },
    { name: 'data.json', content: '{}' },
  ]);
  await assert.rejects(async () => {
    await guard.inspectOfficeZip(genericZip, '.docx');
  }, /missing \[Content_Types\]\.xml/i);

  const zipMissingWordDir = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types></Types>' },
    { name: 'other/file.txt', content: 'test' },
  ]);
  await assert.rejects(async () => {
    await guard.inspectOfficeZip(zipMissingWordDir, '.docx');
  }, /missing word\/ package structure/i);

  const traversalZip = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types></Types>' },
    { name: 'word/document.xml', content: '<w:document></w:document>' },
    { name: 'word/../../etc/passwd', content: 'root:x:0:0' },
  ]);
  await assert.rejects(async () => {
    await guard.inspectOfficeZip(traversalZip, '.docx');
  }, /invalid relative path|dangerous path traversal/i);

  const tooManyEntries = [];
  for (let i = 0; i < 15; i++) {
    tooManyEntries.push({ name: `word/entry${i}.xml`, content: `data ${i}` });
  }
  tooManyEntries.push({ name: '[Content_Types].xml', content: '<Types></Types>' });
  const entryBombZip = createZipBuffer(tooManyEntries);
  await assert.rejects(async () => {
    await guard.inspectOfficeZip(entryBombZip, '.docx');
  }, /too many entries/i);

  const deepZip = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types></Types>' },
    { name: 'word/sub1/sub2/sub3/sub4/deep.xml', content: 'deep' },
  ]);
  await assert.rejects(async () => {
    await guard.inspectOfficeZip(deepZip, '.docx');
  }, /directory nesting depth limit/i);
});

test('AntivirusScannerService: reliably detects EICAR test string and reports INFECTED', async () => {
  const config = createMockConfig();
  const scanner = new AntivirusScannerService(config);

  const cleanPdf = createSamplePdfBuffer();
  const cleanResult = await scanner.scan(cleanPdf);
  assert.equal(cleanResult.status, 'CLEAN');

  const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
  const infectedBuffer = Buffer.from(`%PDF-1.4\n${eicarString}\n%%EOF`);
  const infectedResult = await scanner.scan(infectedBuffer);

  assert.equal(infectedResult.status, 'INFECTED');
  assert.match(infectedResult.virusName ?? '', /Eicar/i);
});

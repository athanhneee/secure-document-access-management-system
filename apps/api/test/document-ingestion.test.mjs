import assert from 'node:assert/strict';
import { test } from 'node:test';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { Readable } from 'node:stream';

process.env.STORAGE_MOCK = 'true';
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgresql://localhost:5432/secure_docs?schema=public';
process.env.APP_ENCRYPTION_MASTER_KEY = 'test-master-key-32-chars-long-000000000';

import { AppConfigService } from '../dist/config/config.service.js';
import { FileValidationService } from '../dist/modules/documents/file-validation.service.js';
import { ZipBombGuardService } from '../dist/modules/documents/zip-bomb-guard.service.js';
import { ObjectStorageService } from '../dist/modules/documents/object-storage.service.js';
import { AntivirusScannerService } from '../dist/modules/documents/antivirus-scanner.service.js';
import { LocalKmsService } from '../dist/modules/documents/kms.service.js';
import { DocumentEncryptionService } from '../dist/modules/documents/document-encryption.service.js';
import { DocumentIngestionService } from '../dist/modules/documents/document-ingestion.service.js';
import { OrphanCompensationService } from '../dist/modules/documents/orphan-compensation.service.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

function createMockConfig(overrides = {}) {
  const env = {
    NODE_ENV: 'test',
    APP_ENCRYPTION_MASTER_KEY: 'test-master-key-32-chars-long-000000000',
    STORAGE_ENDPOINT: '127.0.0.1',
    STORAGE_PORT: 9000,
    STORAGE_ACCESS_KEY: 'test-access-key',
    STORAGE_SECRET_KEY: 'test-secret-key',
    STORAGE_BUCKET_DOCUMENTS: 'test-documents',
    STORAGE_BUCKET_QUARANTINE: 'test-quarantine',
    STORAGE_BUCKET_DERIVATIVES: 'test-derivatives',
    STORAGE_USE_SSL: false,
    CLAMAV_HOST: '127.0.0.1',
    CLAMAV_PORT: 3310,
    UPLOAD_MAX_FILE_SIZE_BYTES: 1_048_576, // 1MB limit for tests
    ZIP_MAX_TOTAL_UNCOMPRESSED_SIZE: 5_242_880, // 5MB
    ZIP_MAX_ENTRIES: 50,
    ZIP_MAX_DEPTH: 5,
    ZIP_MAX_COMPRESSION_RATIO: 20,
    DOCUMENT_AUDIT_HMAC_KEY: 'test-document-audit-hmac-key-0000000000',
    ...overrides,
  };
  return new AppConfigService(env);
}

/**
 * Constructs a valid in-memory zip archive.
 */
function createZipBuffer(entries) {
  const localHeaders = [];
  const centralHeaders = [];
  let offset = 0;

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
    lh.writeUInt16LE(20, 4); // version needed
    lh.writeUInt16LE(0, 6); // flags
    lh.writeUInt16LE(8, 8); // compression: 8 = Deflate
    lh.writeUInt16LE(0, 10); // mod time
    lh.writeUInt16LE(0, 12); // mod date
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(compressedSize, 18);
    lh.writeUInt32LE(uncompressedSize, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28); // extra len

    localHeaders.push(lh, nameBuf, compressedData);

    // Central directory header: 46 bytes
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); // signature
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
    ch.writeUInt16LE(0, 30); // extra len
    ch.writeUInt16LE(0, 32); // comment len
    ch.writeUInt16LE(0, 34); // disk start
    ch.writeUInt16LE(0, 36); // internal attrs
    ch.writeUInt32LE(0, 38); // external attrs
    ch.writeUInt32LE(offset, 42); // relative offset

    centralHeaders.push(ch, nameBuf);
    offset += 30 + nameBuf.length + compressedSize;
  }

  const centralDir = Buffer.concat(centralHeaders);
  const cdOffset = offset;
  const cdSize = centralDir.length;

  // End of central directory record: 22 bytes
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // signature
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localHeaders, centralDir, eocd]);
}

function createSamplePdfBuffer(content = 'Confidential Government Memo') {
  return Buffer.from(`%PDF-1.5\n%Sample Document\n${content}\n%%EOF`);
}

function createSampleDocxBuffer(content = 'Sensitive Project Plan') {
  return createZipBuffer([
    { name: '[Content_Types].xml', content: '<?xml version="1.0"?><Types></Types>' },
    {
      name: 'word/document.xml',
      content: `<?xml version="1.0"?><w:document>${content}</w:document>`,
    },
  ]);
}

function createSampleXlsxBuffer() {
  return createZipBuffer([
    { name: '[Content_Types].xml', content: '<?xml version="1.0"?><Types></Types>' },
    { name: 'xl/workbook.xml', content: '<?xml version="1.0"?><workbook></workbook>' },
  ]);
}

// ── Tests ────────────────────────────────────────────────────────────────────

test('FileValidationService: sanitizes filename, strips path traversal, null bytes, and Unicode spoofing', () => {
  const validator = new FileValidationService();

  // 1. Normal clean name
  assert.equal(validator.sanitizeFilename('annual_report_2026.pdf'), 'annual_report_2026.pdf');

  // 2. Path traversal: strips leading paths
  assert.equal(validator.sanitizeFilename('../../etc/passwd.pdf'), 'passwd.pdf');
  assert.equal(validator.sanitizeFilename('..\\..\\Windows\\System32\\secret.docx'), 'secret.docx');

  // 3. Null bytes: rejected
  assert.throws(() => validator.sanitizeFilename('evil.pdf\0.docx'), /null byte/i);
  assert.throws(() => validator.sanitizeFilename('test\u0000.pdf'), /null byte/i);

  // 4. Unicode RTL override (RTLO): rejected
  assert.throws(() => validator.sanitizeFilename('test\u202Efdp.exe'), /bidirectional override/i);

  // 5. Zero-width spaces stripped
  const sanitized = validator.sanitizeFilename('report\u200B\uFEFF_q3.pdf');
  assert.equal(sanitized, 'report_q3.pdf');

  // 6. Double extensions with dangerous types: rejected
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

  // 1. Valid allowlist types
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

  // 2. Disallowed extensions rejected
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

  // 3. MIME spoofing rejected (extension says PDF, but MIME says text/html)
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

  // 1. Valid PDF magic bytes (%PDF-)
  const validPdf = Buffer.from('%PDF-1.4 sample');
  assert.doesNotThrow(() => validator.validateMagicBytes(validPdf, '.pdf'));

  // 2. Invalid PDF magic bytes (fake PDF)
  const fakePdf = Buffer.from('<html><body>Not a PDF</body></html>');
  assert.throws(() => validator.validateMagicBytes(fakePdf, '.pdf'), /magic bytes/i);

  // 3. Valid Office zip magic bytes (PK\x03\x04)
  const validZipHeader = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00]);
  assert.doesNotThrow(() => validator.validateMagicBytes(validZipHeader, '.docx'));

  // 4. Fake DOCX (plain text or EXE disguised as docx)
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

  // 1. Valid DOCX
  const validDocx = createSampleDocxBuffer('Executive briefing');
  await assert.doesNotReject(async () => {
    await guard.inspectOfficeZip(validDocx, '.docx');
  });

  const validXlsx = createSampleXlsxBuffer();
  await assert.doesNotReject(async () => {
    await guard.inspectOfficeZip(validXlsx, '.xlsx');
  });

  // 2. Zip without Office structure ([Content_Types].xml missing)
  const genericZip = createZipBuffer([
    { name: 'hello.txt', content: 'World' },
    { name: 'data.json', content: '{}' },
  ]);
  await assert.rejects(async () => {
    await guard.inspectOfficeZip(genericZip, '.docx');
  }, /missing \[Content_Types\]\.xml/i);

  // 3. DOCX missing word/ directory
  const zipMissingWordDir = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types></Types>' },
    { name: 'other/file.txt', content: 'test' },
  ]);
  await assert.rejects(async () => {
    await guard.inspectOfficeZip(zipMissingWordDir, '.docx');
  }, /missing word\/ package structure/i);

  // 4. Zip entry path traversal (../ in entry)
  const traversalZip = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types></Types>' },
    { name: 'word/document.xml', content: '<w:document></w:document>' },
    { name: 'word/../../etc/passwd', content: 'root:x:0:0' },
  ]);
  await assert.rejects(async () => {
    await guard.inspectOfficeZip(traversalZip, '.docx');
  }, /invalid relative path|dangerous path traversal/i);

  // 5. Zip bomb: excessive entries
  const tooManyEntries = [];
  for (let i = 0; i < 15; i++) {
    tooManyEntries.push({ name: `word/entry${i}.xml`, content: `data ${i}` });
  }
  tooManyEntries.push({ name: '[Content_Types].xml', content: '<Types></Types>' });
  const entryBombZip = createZipBuffer(tooManyEntries);
  await assert.rejects(async () => {
    await guard.inspectOfficeZip(entryBombZip, '.docx');
  }, /too many entries/i);

  // 6. Zip bomb: directory depth limit exceeded
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

  // Clean document
  const cleanPdf = createSamplePdfBuffer();
  const cleanResult = await scanner.scan(cleanPdf);
  assert.equal(cleanResult.status, 'CLEAN');

  // EICAR infected document
  const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
  const infectedBuffer = Buffer.from(`%PDF-1.4\n${eicarString}\n%%EOF`);
  const infectedResult = await scanner.scan(infectedBuffer);

  assert.equal(infectedResult.status, 'INFECTED');
  assert.match(infectedResult.virusName ?? '', /Eicar/i);
});

test('LocalKmsService: wraps and unwraps 256-bit DEK using AES-256-GCM and KEK without storing KEK in DB', async () => {
  const config = createMockConfig();
  const kms = new LocalKmsService(config);

  const rawDek = crypto.randomBytes(32); // 256-bit DEK

  // 1. Wrap DEK
  const wrapResult = await kms.wrapKey(rawDek);
  assert.equal(wrapResult.keyRef, 'local-kms:v1');
  assert.ok(wrapResult.wrappedDek.length > 40);
  assert.ok(wrapResult.combinedRef.startsWith('local-kms:v1:'));

  // 2. Unwrap DEK and verify byte identity
  const unwrapped = await kms.unwrapCombinedRef(wrapResult.combinedRef);
  assert.equal(unwrapped.length, 32);
  assert.deepEqual(unwrapped, rawDek);

  // 3. Tampering wrapped DEK string causes unwrap failure
  const tamperedBytes = Buffer.from(wrapResult.wrappedDek, 'base64url');
  tamperedBytes[tamperedBytes.length - 1] ^= 0xff; // flip last byte
  const tamperedWrapped = tamperedBytes.toString('base64url');

  await assert.rejects(async () => {
    await kms.unwrapKey(tamperedWrapped, 'local-kms:v1');
  }, /authentication tag mismatch|corrupted/i);
});

test('DocumentEncryptionService: AES-256-GCM envelope encryption with 33-byte header and tag authentication', async () => {
  const config = createMockConfig();
  const kms = new LocalKmsService(config);
  const encryption = new DocumentEncryptionService(kms);

  const plaintext = Buffer.from('TOP SECRET: Strategic Defence Operational Blueprint 2026');
  const originalSha256 = crypto.createHash('sha256').update(plaintext).digest('hex');

  // 1. Encrypt plaintext
  const encrypted = await encryption.encryptBuffer(plaintext);
  assert.equal(encrypted.sha256Hash, originalSha256);
  assert.equal(encrypted.encryptedBuffer.length, plaintext.length + 33);

  // Header verification: Magic 'SDAE' + Version 0x01
  assert.equal(encrypted.encryptedBuffer.subarray(0, 4).toString('utf8'), 'SDAE');
  assert.equal(encrypted.encryptedBuffer.readUInt8(4), 0x01);

  // 2. Decrypt to private temp file and verify exact SHA-256 hash match
  const decrypted = await encryption.decryptToTempFile(
    encrypted.encryptedBuffer,
    encrypted.dekReference,
  );
  try {
    assert.equal(decrypted.sha256Hash, originalSha256);
    const readBack = await fsp.readFile(decrypted.tempFilePath);
    assert.deepEqual(readBack, plaintext);
  } finally {
    await decrypted.cleanup();
  }
  // Verify temp file is cleaned up
  assert.equal(fs.existsSync(decrypted.tempFilePath), false);

  // 3. Criterion: Two uploads of identical plaintext produce DIFFERENT ciphertexts (due to fresh DEK & IV)
  const encrypted2 = await encryption.encryptBuffer(plaintext);
  assert.notDeepEqual(encrypted.encryptedBuffer, encrypted2.encryptedBuffer);
  assert.notEqual(encrypted.dekReference, encrypted2.dekReference);

  // 4. Criterion: Tampering a single byte of ciphertext causes tag verification failure (NO plaintext emitted)
  const tampered = Buffer.from(encrypted.encryptedBuffer);
  // Header is 33 bytes; flip a byte in the ciphertext body
  tampered[34] ^= 0x01;

  await assert.rejects(async () => {
    await encryption.decryptToTempFile(tampered, encrypted.dekReference);
  }, /Authentication tag verification failed or ciphertext tampered/i);
});

test('OrphanCompensationService: rolls back tracked storage objects and deletes temporary files', async () => {
  const config = createMockConfig();
  const storage = new ObjectStorageService(config);
  const compensation = new OrphanCompensationService(storage);

  const session = compensation.createSession();

  // Create temporary file
  const tempDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-test-'));
  const tempFile = path.join(tempDir, 'test-file.tmp');
  await fsp.writeFile(tempFile, 'data');
  session.tempFilesToDelete.push(tempFile);
  session.tempFilesToDelete.push(tempDir);

  // Put object into storage
  await storage.putObject(storage.quarantineBucket, 'quarantine/orphan-test', Buffer.from('data'));
  session.storageKeysToDelete.push({
    bucket: storage.quarantineBucket,
    key: 'quarantine/orphan-test',
  });

  assert.equal(
    await storage.objectExists(storage.quarantineBucket, 'quarantine/orphan-test'),
    true,
  );
  assert.equal(fs.existsSync(tempFile), true);

  // Execute compensation rollback
  await compensation.compensate(session);

  assert.equal(
    await storage.objectExists(storage.quarantineBucket, 'quarantine/orphan-test'),
    false,
  );
  assert.equal(fs.existsSync(tempFile), false);
  assert.equal(fs.existsSync(tempDir), false);
});

test('DocumentIngestionService: streaming upload enforces file size limit and aborts immediately', async () => {
  const config = createMockConfig({ UPLOAD_MAX_FILE_SIZE_BYTES: 1024 }); // 1KB limit
  const fileValidation = new FileValidationService();
  const zipBombGuard = new ZipBombGuardService(config);
  const storage = new ObjectStorageService(config);
  const antivirus = new AntivirusScannerService(config);
  const kms = new LocalKmsService(config);
  const encryption = new DocumentEncryptionService(kms);
  const compensation = new OrphanCompensationService(storage);

  // Mock audit service
  const recordedAudits = [];
  const mockAudit = {
    record: async (event) => recordedAudits.push(event),
  };

  const mockDb = {
    $transaction: async (fn) =>
      fn({
        document: {
          findUnique: async () => null,
          create: async () => ({}),
        },
        documentVersion: {
          create: async () => ({}),
        },
      }),
  };

  const ingestion = new DocumentIngestionService(
    config,
    fileValidation,
    zipBombGuard,
    storage,
    antivirus,
    encryption,
    mockAudit,
    compensation,
    mockDb,
  );

  // Stream with 2KB data (exceeds 1KB limit)
  const largeData = Buffer.alloc(2048, 'A');
  const stream = Readable.from([largeData]);

  const principal = {
    userId: 100n,
    sessionId: 'session-1',
    username: 'test_officer',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const context = { ip: '127.0.0.1', correlationId: crypto.randomUUID() };

  await assert.rejects(async () => {
    await ingestion.ingestDocument({
      fileStream: stream,
      rawFilename: 'large_memo.pdf',
      declaredMime: 'application/pdf',
      principal,
      context,
    });
  }, /File size exceeds allowed limit/i);

  // Verify failed audit was logged
  const failedAudit = recordedAudits.find((a) => a.action === 'DOCUMENT_UPLOAD_FAILED');
  assert.ok(failedAudit);
  assert.equal(failedAudit.outcome, 'FAILED');
});

test('DocumentIngestionService: EICAR infected file is quarantined and NEVER becomes ACTIVE', async () => {
  const config = createMockConfig();
  const fileValidation = new FileValidationService();
  const zipBombGuard = new ZipBombGuardService(config);
  const storage = new ObjectStorageService(config);
  const antivirus = new AntivirusScannerService(config);
  const kms = new LocalKmsService(config);
  const encryption = new DocumentEncryptionService(kms);
  const compensation = new OrphanCompensationService(storage);

  const recordedAudits = [];
  const mockAudit = {
    record: async (event) => recordedAudits.push(event),
  };

  const mockDb = {
    $transaction: async (fn) =>
      fn({
        document: {
          findUnique: async () => null,
          create: async () => ({}),
        },
        documentVersion: {
          create: async () => ({}),
        },
      }),
  };

  const ingestion = new DocumentIngestionService(
    config,
    fileValidation,
    zipBombGuard,
    storage,
    antivirus,
    encryption,
    mockAudit,
    compensation,
    mockDb,
  );

  const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
  const infectedData = Buffer.from(`%PDF-1.4\n${eicarString}\n%%EOF`);
  const stream = Readable.from([infectedData]);

  const principal = {
    userId: 101n,
    sessionId: 'session-2',
    username: 'test_officer',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const context = { ip: '127.0.0.1', correlationId: crypto.randomUUID() };

  await assert.rejects(async () => {
    await ingestion.ingestDocument({
      fileStream: stream,
      rawFilename: 'infected_memo.pdf',
      declaredMime: 'application/pdf',
      principal,
      context,
    });
  }, /Malware detected/i);

  // Verify audit events
  const scanAudit = recordedAudits.find((a) => a.action === 'DOCUMENT_SCAN_RESULT');
  assert.ok(scanAudit);
  assert.equal(scanAudit.details?.scanStatus, 'INFECTED');

  const failedAudit = recordedAudits.find((a) => a.action === 'DOCUMENT_UPLOAD_FAILED');
  assert.ok(failedAudit);
  assert.equal(failedAudit.reasonCode, 'MALWARE_DETECTED');

  // Verify that quarantined object exists in quarantine bucket
  const quarantineKey = failedAudit.details?.quarantineKey;
  assert.ok(quarantineKey);
  const existsInQuarantine = await storage.objectExists(storage.quarantineBucket, quarantineKey);
  assert.equal(existsInQuarantine, true);

  // Verify audit log did NOT leak file contents or secrets
  for (const log of recordedAudits) {
    const serialized = JSON.stringify(log, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
    assert.equal(serialized.includes(eicarString), false);
    assert.equal(serialized.includes('dek'), false);
  }
});

test('Audit log details do not log DEK, IV, or plaintext file contents', async () => {
  const config = createMockConfig();
  const fileValidation = new FileValidationService();
  const zipBombGuard = new ZipBombGuardService(config);
  const storage = new ObjectStorageService(config);
  const antivirus = new AntivirusScannerService(config);
  const kms = new LocalKmsService(config);
  const encryption = new DocumentEncryptionService(kms);
  const compensation = new OrphanCompensationService(storage);

  const recordedAudits = [];
  const mockAudit = {
    record: async (event) => recordedAudits.push(event),
  };

  const mockDb = {
    $transaction: async (fn) =>
      fn({
        document: {
          findUnique: async () => null,
          create: async () => ({}),
        },
        documentVersion: {
          create: async () => ({}),
        },
      }),
  };

  const ingestion = new DocumentIngestionService(
    config,
    fileValidation,
    zipBombGuard,
    storage,
    antivirus,
    encryption,
    mockAudit,
    compensation,
    mockDb,
  );

  const secretPlaintext = 'TOP SECRET CLEARANCE LEVEL 4 INTELLIGENCE REPORT';
  const cleanPdf = createSamplePdfBuffer(secretPlaintext);
  const stream = Readable.from([cleanPdf]);

  const principal = {
    userId: 102n,
    sessionId: 'session-3',
    username: 'test_officer',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const context = { ip: '127.0.0.1', correlationId: crypto.randomUUID() };

  // In test environment without DB, ingestion throws on DB transaction, but audit logs are recorded
  try {
    await ingestion.ingestDocument({
      fileStream: stream,
      rawFilename: 'classified_brief.pdf',
      declaredMime: 'application/pdf',
      principal,
      context,
    });
  } catch {
    // DB transaction may fail without postgres connection in unit test, expected
  }

  // Verify audit logs
  assert.ok(recordedAudits.length >= 2);
  for (const log of recordedAudits) {
    const serialized = JSON.stringify(log, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
    assert.equal(
      serialized.includes(secretPlaintext),
      false,
      'Plaintext secret must not appear in audit log',
    );
    assert.equal(serialized.includes('"dek"'), false, 'DEK must not appear in audit log');
  }
});

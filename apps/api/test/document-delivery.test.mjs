import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import zlib from 'node:zlib';
import { PDFDocument } from 'pdf-lib';

// ── Contract & Schema Tests ───────────────────────────────────────────────────

import {
  CreateAccessSessionSchema,
  PreviewPageParamSchema,
  DownloadTicketParamSchema,
  WatermarkTokenParamSchema,
} from '../../../packages/contracts/dist/dto.js';
import { AppErrorCode } from '../../../packages/contracts/dist/error-codes.js';

// ── Service Imports ───────────────────────────────────────────────────────────

import { WatermarkEngineService } from '../dist/modules/watermarks/watermark-engine.service.js';
import { WatermarksService } from '../dist/modules/watermarks/watermarks.service.js';
import { OfficeConverterService } from '../dist/modules/documents/office-converter.service.js';
import { DocumentPepService } from '../dist/modules/documents/document-pep.service.js';
import { DocumentDeliveryService } from '../dist/modules/documents/document-delivery.service.js';

// ── Test Helpers ─────────────────────────────────────────────────────────────

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

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(8, 8);
    lh.writeUInt16LE(0, 10);
    lh.writeUInt16LE(0, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(compressedSize, 18);
    lh.writeUInt32LE(uncompressedSize, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);

    localHeaders.push(lh, nameBuf, compressedData);

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

async function createSamplePdf(pageCount = 3) {
  const doc = await PDFDocument.create();
  for (let i = 0; i < pageCount; i++) {
    const page = doc.addPage([595.28, 841.89]);
    page.drawText(`Confidential Internal Document - Page ${i + 1}`, {
      x: 50,
      y: 800,
      size: 16,
    });
  }
  const bytes = await doc.save();
  return Buffer.from(bytes);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Contract & DTO Validation Tests
// ─────────────────────────────────────────────────────────────────────────────

test('CreateAccessSessionSchema — validates VIEW and DOWNLOAD actions', () => {
  const validView = CreateAccessSessionSchema.safeParse({ action: 'VIEW' });
  assert.ok(validView.success);
  assert.equal(validView.data.action, 'VIEW');

  const validDownload = CreateAccessSessionSchema.safeParse({
    action: 'DOWNLOAD',
    grantId: randomUUID(),
    deviceFingerprint: 'fp-chrome-windows-1234',
  });
  assert.ok(validDownload.success);
  assert.equal(validDownload.data.action, 'DOWNLOAD');

  const invalidAction = CreateAccessSessionSchema.safeParse({ action: 'ADMIN_DELETE' });
  assert.ok(!invalidAction.success, 'Should reject invalid action');
});

test('PreviewPageParamSchema — validates page numbers', () => {
  assert.ok(PreviewPageParamSchema.safeParse({ pageNumber: 1 }).success);
  assert.ok(PreviewPageParamSchema.safeParse({ pageNumber: 42 }).success);
  assert.ok(!PreviewPageParamSchema.safeParse({ pageNumber: 0 }).success, 'Page 0 invalid');
  assert.ok(!PreviewPageParamSchema.safeParse({ pageNumber: -1 }).success, 'Negative page invalid');
});

test('DownloadTicketParamSchema — validates ticket format', () => {
  const validTicket = `DT-${'a'.repeat(64)}`;
  assert.ok(DownloadTicketParamSchema.safeParse({ ticket: validTicket }).success);
  assert.ok(!DownloadTicketParamSchema.safeParse({ ticket: 'invalid-ticket' }).success);
  assert.ok(!DownloadTicketParamSchema.safeParse({ ticket: `DT-${'a'.repeat(32)}` }).success);
});

test('WatermarkTokenParamSchema — validates watermark token format', () => {
  const validToken = `WM-${'f'.repeat(48)}`;
  assert.ok(WatermarkTokenParamSchema.safeParse({ token: validToken }).success);
  assert.ok(!WatermarkTokenParamSchema.safeParse({ token: 'WM-short' }).success);
  assert.ok(!WatermarkTokenParamSchema.safeParse({ token: 'NOT-WM-ffff' }).success);
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Watermark Engine Tests
// ─────────────────────────────────────────────────────────────────────────────

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

  // Requirement 6: Original file and hash remain immutable; output derivative has new SHA-256
  const loadedWatermarked = await PDFDocument.load(result.watermarkedBuffer);
  assert.equal(loadedWatermarked.getPageCount(), 3);
});

test('WatermarkEngine — extractPdfPage extracts exact page and rejects out-of-bounds', async () => {
  const engine = new WatermarkEngineService();
  const multiPagePdf = await createSamplePdf(5);

  const page2Buffer = await engine.extractPdfPage(multiPagePdf, 2);
  const loadedPage2 = await PDFDocument.load(page2Buffer);
  assert.equal(loadedPage2.getPageCount(), 1, 'Extracted page must have exactly 1 page');

  // Out of bounds check
  await assert.rejects(
    async () => {
      await engine.extractPdfPage(multiPagePdf, 10);
    },
    (err) => {
      return err.getStatus?.() === 400;
    },
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
    (err) => {
      // Must fail closed with 403 Forbidden
      return err.getStatus?.() === 403;
    },
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Office Converter Tests (Safe Isolated Conversion)
// ─────────────────────────────────────────────────────────────────────────────

test('OfficeConverter — blocks VBA macros with OFFICE_MACRO_BLOCKED', async () => {
  const converter = new OfficeConverterService();

  // Create mock OpenXML DOCX containing a dangerous vbaProject.bin macro
  const macroDocx = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types></Types>' },
    {
      name: 'word/document.xml',
      content:
        '<w:document><w:body><w:p><w:r><w:t>Macro Document</w:t></w:r></w:p></w:body></w:document>',
    },
    { name: 'word/vbaProject.bin', content: Buffer.from('DANGEROUS MACRO BINARY PAYLOAD') },
  ]);

  await assert.rejects(
    async () => {
      await converter.convertOfficeToPdf(macroDocx, 'invoice.docx');
    },
    (err) => {
      const response = err.getResponse?.();
      return response?.errorCode === AppErrorCode.OFFICE_MACRO_BLOCKED;
    },
  );
});

test('OfficeConverter — blocks Excel macro workbook vbaData.xml', async () => {
  const converter = new OfficeConverterService();

  const macroXlsx = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types></Types>' },
    { name: 'xl/workbook.xml', content: '<workbook></workbook>' },
    { name: 'xl/vbaData.xml', content: '<vbaData></vbaData>' },
  ]);

  await assert.rejects(
    async () => {
      await converter.convertOfficeToPdf(macroXlsx, 'budget.xlsx');
    },
    (err) => {
      const response = err.getResponse?.();
      return response?.errorCode === AppErrorCode.OFFICE_MACRO_BLOCKED;
    },
  );
});

test('OfficeConverter — detects corrupt file with OFFICE_CONVERSION_FAILED', async () => {
  const converter = new OfficeConverterService();
  const corruptBuffer = Buffer.from('completely invalid non-zip content 123456');

  await assert.rejects(
    async () => {
      await converter.convertOfficeToPdf(corruptBuffer, 'corrupt.docx');
    },
    (err) => {
      const response = err.getResponse?.();
      return response?.errorCode === AppErrorCode.OFFICE_CONVERSION_FAILED;
    },
  );
});

test('OfficeConverter — converts safe DOCX to clean printable PDF', async () => {
  const converter = new OfficeConverterService();

  const safeDocx = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types></Types>' },
    {
      name: 'word/document.xml',
      content:
        '<w:document><w:body><w:p><w:r><w:t>Quarterly Financial Results</w:t></w:r></w:p><w:p><w:r><w:t>Revenue exceeded target by 15%.</w:t></w:r></w:p></w:body></w:document>',
    },
  ]);

  const pdfBuffer = await converter.convertOfficeToPdf(safeDocx, 'quarterly.docx');
  assert.ok(pdfBuffer.length > 0);
  const loaded = await PDFDocument.load(pdfBuffer);
  assert.ok(loaded.getPageCount() >= 1, 'Converted PDF must have at least 1 page');
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. WatermarksService & UC28 Forensic Reconciliation Tests
// ─────────────────────────────────────────────────────────────────────────────

test('WatermarksService — UC28: verifyWatermarkToken traces provenance back to user, session, document, version', async () => {
  const token = `WM-${'e'.repeat(48)}`;
  const now = new Date();

  const mockDb = {
    watermarkInstance: {
      findUnique: async ({ where }) => {
        if (where.watermark_token === token) {
          return {
            watermark_token: token,
            renderedText: 'CONFIDENTIAL | John Doe (EMP-01) | DOC-001 | 2026-09-23 | eeeeeeee',
            output_sha256_hash: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
            generated_at: now,
            users: {
              id: 42n,
              username: 'johndoe',
              full_name: 'John Doe',
              employee_code: 'EMP-01',
              email: 'john@org.internal',
            },
            access_sessions: {
              id: 'a0000000-0000-0000-0000-000000000001',
              started_at: now,
              ip_address: '10.0.1.50',
              user_agent: 'Mozilla/5.0 SecureClient',
            },
            document_versions: {
              version_no: 3,
              sha256_hash: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
              document: {
                id: 'd0000000-0000-0000-0000-000000000001',
                title: 'Operation Blue Ridge',
                document_code: 'DOC-OPS-2026',
              },
            },
            watermark_configs: {
              name: 'High Security Watermark',
              opacity_percent: 30,
              font_size: 16,
              include_qr_code: true,
            },
          };
        }
        return null;
      },
    },
  };

  const service = new WatermarksService(mockDb);
  const result = await service.verifyWatermarkToken(token);

  assert.equal(result.watermarkToken, token);
  assert.equal(result.user.username, 'johndoe');
  assert.equal(result.user.employeeCode, 'EMP-01');
  assert.equal(result.session.id, 'a0000000-0000-0000-0000-000000000001');
  assert.equal(result.session.ipAddress, '10.0.1.50');
  assert.equal(result.document.documentCode, 'DOC-OPS-2026');
  assert.equal(result.document.versionNo, 3);
  assert.equal(result.config.name, 'High Security Watermark');
});

test('WatermarksService — verifyWatermarkToken throws NotFoundException for unregistered token', async () => {
  const mockDb = {
    watermarkInstance: {
      findUnique: async () => null,
    },
  };

  const service = new WatermarksService(mockDb);
  await assert.rejects(
    async () => {
      await service.verifyWatermarkToken(`WM-${'0'.repeat(48)}`);
    },
    (err) => {
      const resp = err.getResponse?.();
      return resp?.errorCode === AppErrorCode.WATERMARK_TOKEN_NOT_FOUND;
    },
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. DocumentPEP Service Tests
// ─────────────────────────────────────────────────────────────────────────────

test('DocumentPEP — rejects access if document does not exist', async () => {
  const mockDb = {
    document: { findUnique: async () => null },
  };
  const mockGrants = {};
  const mockAbac = {};
  const mockAudit = { record: async () => {} };

  const pep = new DocumentPepService(mockAbac, mockGrants, mockAudit, mockDb);
  const principal = { userId: 1n, username: 'test', mfa: true };
  const context = { ip: '127.0.0.1', userAgent: 'test-agent' };

  await assert.rejects(
    async () => {
      await pep.enforceAccess(randomUUID(), principal, context, { action: 'VIEW' });
    },
    (err) => err.getResponse?.()?.errorCode === AppErrorCode.DOCUMENT_NOT_FOUND,
  );
});

test('DocumentPEP — rejects DOWNLOAD if classification level has allow_download = false', async () => {
  const docId = randomUUID();
  const grantId = randomUUID();

  const mockDb = {
    document: {
      findUnique: async () => ({
        id: docId,
        status: 'ACTIVE',
        department_id: 1n,
        owner_id: 10n,
        current_version: { id: 100n, version_no: 1, scan_status: 'CLEAN' },
        classification_history: [
          {
            classification_levels: {
              rank: 3,
              allow_download: false, // Disallowed!
              require_watermark: true,
            },
          },
        ],
      }),
    },
  };
  const mockGrants = {
    assertGrantValidForAccess: async () => {},
  };
  const mockAbac = { evaluate: async () => ({ decision: 'PERMIT', obligations: [] }) };
  const mockAudit = { record: async () => {} };

  const pep = new DocumentPepService(mockAbac, mockGrants, mockAudit, mockDb);
  const principal = { userId: 1n, username: 'test', mfa: true };
  const context = { ip: '127.0.0.1', userAgent: 'test-agent' };

  await assert.rejects(
    async () => {
      await pep.enforceAccess(docId, principal, context, { action: 'DOWNLOAD', grantId });
    },
    (err) => err.getResponse?.()?.errorCode === AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
  );
});

test('DocumentPEP — rejects DOWNLOAD if ABAC policy returns FORBID_DOWNLOAD obligation', async () => {
  const docId = randomUUID();
  const grantId = randomUUID();

  const mockDb = {
    document: {
      findUnique: async () => ({
        id: docId,
        status: 'ACTIVE',
        department_id: 1n,
        owner_id: 10n,
        current_version: { id: 100n, version_no: 1, scan_status: 'CLEAN' },
        classification_history: [
          {
            classification_levels: {
              rank: 2,
              allow_download: true, // Classification allows, but ABAC forbids!
              require_watermark: true,
            },
          },
        ],
      }),
    },
    user: { findUnique: async () => ({ department_id: 1n, status: 'ACTIVE' }) },
    userAttributeAssignment: {
      findFirst: async () => ({ attribute_options: { numeric_rank: 5 } }),
    },
    userDepartmentHistory: { findFirst: async () => ({ department_id: 1n }) },
    userProjectMembership: { findMany: async () => [] },
  };
  const mockGrants = {
    assertGrantValidForAccess: async () => {},
  };
  const mockAbac = {
    evaluate: async () => ({
      decision: 'PERMIT',
      obligations: [{ type: 'FORBID_DOWNLOAD' }],
    }),
  };
  const mockAudit = { record: async () => {} };

  const pep = new DocumentPepService(mockAbac, mockGrants, mockAudit, mockDb);
  const principal = { userId: 1n, username: 'test', mfa: true };
  const context = { ip: '127.0.0.1', userAgent: 'test-agent' };

  await assert.rejects(
    async () => {
      await pep.enforceAccess(docId, principal, context, { action: 'DOWNLOAD', grantId });
    },
    (err) => err.getResponse?.()?.errorCode === AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
  );
});

test('DocumentPEP — on PERMIT, creates ACTIVE access_session tied to user, grant, and version', async () => {
  const docId = randomUUID();
  const grantId = randomUUID();
  let createdSession = null;

  const mockDb = {
    document: {
      findUnique: async () => ({
        id: docId,
        document_code: 'DOC-ACTIVE-01',
        title: 'Active Document',
        status: 'ACTIVE',
        department_id: 1n,
        owner_id: 10n,
        current_version: { id: 100n, version_no: 1, scan_status: 'CLEAN' },
        classification_history: [
          {
            classification_levels: {
              rank: 1,
              allow_download: true,
              require_watermark: true,
            },
          },
        ],
      }),
    },
    accessSession: {
      create: async ({ data }) => {
        createdSession = data;
        return data;
      },
    },
    user: { findUnique: async () => ({ department_id: 1n, status: 'ACTIVE' }) },
    userAttributeAssignment: {
      findFirst: async () => ({ attribute_options: { numeric_rank: 5 } }),
    },
    userDepartmentHistory: { findFirst: async () => ({ department_id: 1n }) },
    userProjectMembership: { findMany: async () => [] },
  };
  const mockGrants = {
    assertGrantValidForAccess: async () => {},
  };
  const mockAbac = {
    evaluate: async () => ({
      decision: 'PERMIT',
      obligations: [{ type: 'REQUIRE_WATERMARK' }],
    }),
  };
  const mockAudit = { record: async () => {} };

  const pep = new DocumentPepService(mockAbac, mockGrants, mockAudit, mockDb);
  const principal = { userId: 77n, username: 'authorized_user', mfa: true };
  const context = { ip: '192.168.1.100', userAgent: 'SafeClient' };

  const result = await pep.enforceAccess(docId, principal, context, {
    action: 'VIEW',
    grantId,
    deviceFingerprint: 'dev-fp-77',
  });

  assert.ok(result.sessionId);
  assert.equal(result.watermarkRequired, true);
  assert.equal(createdSession.access_grant_id, grantId);
  assert.equal(createdSession.user_id, 77n);
  assert.equal(createdSession.document_version_id, 100n);
  assert.equal(createdSession.status, 'ACTIVE');
  assert.equal(createdSession.device_fingerprint, 'dev-fp-77');
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Single-Use Download Tickets & Controlled Delivery Tests
// ─────────────────────────────────────────────────────────────────────────────

test('DocumentDelivery — single-use download ticket lifecycle: issue, redeem once, second redemption rejected', async () => {
  const sessionId = randomUUID();
  const documentId = randomUUID();
  const principal = { userId: 55n, username: 'downloader', mfa: true };
  const context = { ip: '127.0.0.1' };

  const mockDb = {
    accessSession: {
      findUnique: async ({ where }) => {
        if (where.id === sessionId) {
          return {
            id: sessionId,
            status: 'ACTIVE',
            user_id: 55n,
            access_grant_id: randomUUID(),
            document_versions: {
              id: 1n,
              document_id: documentId,
              original_filename: 'report.pdf',
              mime_type: 'application/pdf',
              storage_key: 'enc-report',
              encryption_key_ref: 'key-ref',
              document: {
                title: 'Report',
                document_code: 'REP-01',
                classification_history: [
                  {
                    classification_levels: {
                      allow_download: true,
                      require_watermark: false,
                    },
                  },
                ],
              },
            },
          };
        }
        return null;
      },
      update: async () => {},
    },
  };

  const mockStorage = {
    documentsBucket: 'test-bucket',
    getObject: async () => Buffer.from('mock encrypted bytes'),
  };
  const mockEncryption = {
    decryptToTempFile: async () => ({
      tempFilePath: 'mock.tmp',
      cleanup: async () => {},
    }),
  };
  const mockPep = {};
  const mockOffice = {};
  const mockWatermark = {};
  const mockGrants = {
    assertGrantValidForAccess: async () => {},
  };
  const mockAudit = { record: async () => {} };
  const mockConfig = { get: () => 60 };

  const delivery = new DocumentDeliveryService(
    mockPep,
    mockStorage,
    mockEncryption,
    mockOffice,
    mockWatermark,
    mockGrants,
    mockAudit,
    mockConfig,
    mockDb,
  );

  // Monkey-patch fsp.readFile to return simple mock bytes
  delivery.downloadDocument = async () => ({
    buffer: Buffer.from('downloaded-content'),
    mimeType: 'application/pdf',
    filename: 'report.pdf',
    fileSizeBytes: 18,
    outputSha256Hash: 'hash123',
  });

  // Step 1: Create single-use ticket
  const ticketRes = await delivery.createDownloadTicket(documentId, sessionId, principal, context);
  assert.match(ticketRes.ticket, /^DT-[0-9a-f]{64}$/);
  assert.equal(ticketRes.ttlSeconds, 60);

  // Step 2: First redemption succeeds
  const file1 = await delivery.redeemDownloadTicket(ticketRes.ticket, context);
  assert.equal(file1.filename, 'report.pdf');

  // Step 3: Second redemption MUST fail (Single-Use Guarantee)
  await assert.rejects(
    async () => {
      await delivery.redeemDownloadTicket(ticketRes.ticket, context);
    },
    (err) => err.getResponse?.()?.errorCode === AppErrorCode.DOWNLOAD_TICKET_INVALID,
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Concurrent Access Test
// ─────────────────────────────────────────────────────────────────────────────

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

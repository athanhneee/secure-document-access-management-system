import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import {
  CreateAccessSessionSchema,
  PreviewPageParamSchema,
  DownloadTicketParamSchema,
  WatermarkTokenParamSchema,
} from '../../../packages/contracts/dist/dto.js';
import { AppErrorCode } from '../../../packages/contracts/dist/error-codes.js';
import { WatermarksService } from '../dist/modules/watermarks/watermarks.service.js';
import { DocumentDeliveryService } from '../dist/modules/documents/document-delivery.service.js';

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
    (err) => err.getResponse?.()?.errorCode === AppErrorCode.WATERMARK_TOKEN_NOT_FOUND,
  );
});

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
  const mockGrants = { assertGrantValidForAccess: async () => {} };
  const mockAudit = { record: async () => {} };
  const mockConfig = { get: () => 60 };

  const mockPep = {
    enforceSessionPolicy: async () => ({
      grantedAction: 'DOWNLOAD',
      forbidDownload: false,
      expiresAtMs: null,
    }),
  };

  const delivery = new DocumentDeliveryService(
    mockPep,
    mockStorage,
    mockEncryption,
    {},
    {},
    mockGrants,
    mockAudit,
    mockConfig,
    mockDb,
  );

  delivery.downloadDocument = async () => ({
    buffer: Buffer.from('downloaded-content'),
    mimeType: 'application/pdf',
    filename: 'report.pdf',
    fileSizeBytes: 18,
    outputSha256Hash: 'hash123',
  });

  const ticketRes = await delivery.createDownloadTicket(documentId, sessionId, principal, context);
  assert.match(ticketRes.ticket, /^DT-[0-9a-f]{64}$/);
  assert.equal(ticketRes.ttlSeconds, 60);

  const file1 = await delivery.redeemDownloadTicket(ticketRes.ticket, context);
  assert.equal(file1.filename, 'report.pdf');

  await assert.rejects(
    async () => {
      await delivery.redeemDownloadTicket(ticketRes.ticket, context);
    },
    (err) => err.getResponse?.()?.errorCode === AppErrorCode.DOWNLOAD_TICKET_INVALID,
  );
});

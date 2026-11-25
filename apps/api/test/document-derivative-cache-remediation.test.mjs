/**
 * Module: Unit Tests for Bounded PEP Session Policies & Encrypted Derivative Session PDF Cache
 * Thuật toán: Kiểm chứng TTL hữu hạn bắt buộc của chính sách phiên PEP (30–60 phút) và bộ đệm dẫn xuất mã hóa
 *   `STORAGE_BUCKET_DERIVATIVES` giúp xem trang 2 không tải lại bản gốc S3 hay chạy lại KMS/watermark.
 */
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { PDFDocument } from 'pdf-lib';
import { DistributedStateService } from '../dist/modules/concurrency/distributed-state.service.js';
import { DocumentDeliveryService } from '../dist/modules/documents/document-delivery.service.js';
import { DocumentEncryptionService } from '../dist/modules/documents/document-encryption.service.js';
import { LocalKmsService } from '../dist/modules/documents/kms.service.js';
import { ObjectStorageService } from '../dist/modules/documents/object-storage.service.js';
import { computeBoundedSessionPolicyTtlMs } from '../dist/modules/documents/pep-context-builder.js';
import { createMockConfig } from './helpers/document-ingestion-mocks.mjs';

test('[HIGH 1.3 & 1.5.1] Bounded PEP TTL + STORAGE_BUCKET_DERIVATIVES cache eliminates Page 2 KMS/watermark calls', async () => {
  assert.equal(computeBoundedSessionPolicyTtlMs(null), 30 * 60_000);
  assert.equal(computeBoundedSessionPolicyTtlMs(120), 60 * 60_000);

  const config = createMockConfig();
  const stateStore = new DistributedStateService();
  const storage = new ObjectStorageService(config);
  const encryption = new DocumentEncryptionService(new LocalKmsService(config));

  const srcPdf = await PDFDocument.create();
  srcPdf.addPage([400, 400]);
  srcPdf.addPage([400, 400]);
  const pdfBytes = Buffer.from(await srcPdf.save());
  const docId = randomUUID();
  const sessionId = randomUUID();
  const encrypted = await encryption.encryptBuffer(pdfBytes, docId);
  await storage.putObject(storage.documentsBucket, 'docs/two-page.enc', encrypted.encryptedBuffer);

  let sourceGets = 0;
  const origGetObject = storage.getObject.bind(storage);
  storage.getObject = async (bucket, key) => {
    if (bucket === storage.documentsBucket) sourceGets += 1;
    return await origGetObject(bucket, key);
  };

  let watermarkCalls = 0;
  const mockWatermark = {
    getWatermarkConfig: async () => ({ id: 1n }),
    applyWatermarkToPdf: async (buf) => {
      watermarkCalls += 1;
      return {
        watermarkedBuffer: buf,
        watermarkToken: `WM-${'a'.repeat(48)}`,
        renderedText: 'CONFIDENTIAL WM',
        outputSha256Hash: 'hash-wm',
        pageCount: 2,
      };
    },
    recordWatermarkInstance: async () => {},
    extractPdfPage: async (buf, pageNo) => {
      const loaded = await PDFDocument.load(buf);
      const single = await PDFDocument.create();
      const [copied] = await single.copyPages(loaded, [pageNo - 1]);
      single.addPage(copied);
      return Buffer.from(await single.save());
    },
  };

  const sessionRow = {
    id: sessionId,
    status: 'ACTIVE',
    user_id: 7n,
    access_grant_id: randomUUID(),
    ip_address: '127.0.0.1',
    user_agent: 'Viewer/1.0',
    started_at: new Date(),
    document_versions: {
      id: 202n,
      version_no: 1,
      document_id: docId,
      original_filename: 'brief.pdf',
      mime_type: 'application/pdf',
      storage_key: 'docs/two-page.enc',
      encryption_key_ref: encrypted.dekReference,
      sha256_hash: encrypted.sha256Hash,
      document: {
        id: docId,
        title: 'Brief',
        document_code: 'DOC-BRIEF',
        classification_history: [
          {
            classification_level_id: 3n,
            classification_levels: {
              code: 'SECRET',
              name: 'Mật',
              require_watermark: true,
              allow_download: false,
            },
          },
        ],
      },
    },
  };

  const delivery = new DocumentDeliveryService(
    { enforceSessionPolicy: async () => ({ grantedAction: 'VIEW', forbidDownload: true }) },
    storage,
    encryption,
    {
      convertOfficeToPdf: async () => {
        throw new Error('Should not convert PDF');
      },
    },
    mockWatermark,
    { assertGrantValidForAccess: async () => {} },
    { record: async () => {} },
    config,
    {
      accessSession: { findUnique: async () => sessionRow, update: async () => {} },
      watermarkInstance: { findFirst: async () => null },
      user: {
        findUnique: async () => ({
          id: 7n,
          username: 'u7',
          full_name: 'User 7',
          employee_code: 'E7',
        }),
      },
    },
    stateStore,
  );

  const principal = { userId: 7n, sessionId: 's-7', username: 'u7', roles: ['USER'], mfa: true };
  const context = { ip: '127.0.0.1', userAgent: 'Viewer/1.0' };
  const p1 = await delivery.getPreviewPdf(docId, sessionId, 1, principal, context);
  assert.equal(p1.totalPages, 2);
  assert.equal(sourceGets, 1);
  assert.equal(watermarkCalls, 1);

  const p2 = await delivery.getPreviewPdf(docId, sessionId, 2, principal, context);
  assert.equal(p2.totalPages, 2);
  assert.equal(sourceGets, 1, 'Page 2 must hit STORAGE_BUCKET_DERIVATIVES with 0 source fetches');
  assert.equal(watermarkCalls, 1, 'Page 2 must not re-run watermark stamping');
});

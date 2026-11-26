/**
 * Module: Regression Tests for BUG-009 ABAC `REQUIRE_WATERMARK` Obligation Enforcement
 * Verifies `watermarkRequired` is persisted in `ActiveSessionPolicy`, survives cache-miss
 * re-hydration (audit log + live ABAC + legacy cache upgrade), and is enforced in both
 * `executeWatermarkedPreview` (including derivative cache guard) and `executeControlledDownload`
 * / `redeemDownloadTicket` even when `classification_levels.require_watermark === false`.
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { PDFDocument } from 'pdf-lib';
import { DistributedStateService } from '../dist/modules/concurrency/distributed-state.service.js';
import { DocumentDeliveryService } from '../dist/modules/documents/document-delivery.service.js';
import { DocumentEncryptionService } from '../dist/modules/documents/document-encryption.service.js';
import { DocumentPepService } from '../dist/modules/documents/document-pep.service.js';
import { LocalKmsService } from '../dist/modules/documents/kms.service.js';
import { ObjectStorageService } from '../dist/modules/documents/object-storage.service.js';
import { SESSION_POLICY_NAMESPACE } from '../dist/modules/documents/pep-obligations.helper.js';
import { resolveAndEnforceSessionPolicy } from '../dist/modules/documents/session-policy-resolver.helper.js';
import { storeCachedSessionPdf } from '../dist/modules/documents/derivative-pdf-cache.helper.js';
import { WatermarkEngineService } from '../dist/modules/watermarks/watermark-engine.service.js';
import { createMockConfig } from './helpers/document-ingestion-mocks.mjs';

async function createSamplePdfBytes() {
  const pdf = await PDFDocument.create();
  pdf.addPage([400, 400]);
  return Buffer.from(await pdf.save());
}

async function setupDeliveryHarness({
  classRequireWatermark,
  abacObligations,
  originalFilename = 'public-brief.pdf',
  mimeType = 'application/pdf',
  rawBytesOverride,
}) {
  const config = createMockConfig();
  const stateStore = new DistributedStateService();
  const storage = new ObjectStorageService(config);
  const encryption = new DocumentEncryptionService(new LocalKmsService(config));
  const pdfBytes = await createSamplePdfBytes();
  const sourceBytes = rawBytesOverride ?? pdfBytes;

  const docId = randomUUID();
  const grantId = randomUUID();
  const versionId = 501n;
  const encrypted = await encryption.encryptBuffer(sourceBytes, docId);
  const storageKey = `docs/${docId}/v1.enc`;
  await storage.putObject(storage.documentsBucket, storageKey, encrypted.encryptedBuffer);

  const sessions = new Map();
  const auditLogs = [];
  const recordedWatermarks = [];
  let officeConversions = 0;

  const documentRow = {
    id: docId,
    title: 'Public Policy Memo',
    document_code: 'DOC-PUB-009',
    owner_id: 99n,
    department_id: 10n,
    status: 'ACTIVE',
    current_version_id: versionId,
    current_version: {
      id: versionId,
      version_no: 1,
      document_id: docId,
      original_filename: originalFilename,
      mime_type: mimeType,
      storage_key: storageKey,
      encryption_key_ref: encrypted.dekReference,
      sha256_hash: encrypted.sha256Hash,
      scan_status: 'CLEAN',
    },
    classification_history: [
      {
        effective_to: null,
        classification_level_id: 1n,
        classification_levels: {
          id: 1n,
          code: 'PUBLIC',
          name: 'Công khai',
          rank: 1,
          allow_download: true,
          require_watermark: classRequireWatermark,
        },
        business_categories: { id: 1n, code: 'GENERAL' },
      },
    ],
  };

  const mockDb = {
    document: {
      findUnique: async ({ where }) => (where.id === docId ? documentRow : null),
    },
    user: {
      findUnique: async ({ where }) => ({
        id: where.id,
        username: 'staff.reader',
        full_name: 'Staff Reader',
        employee_code: 'EMP-009',
        department_id: 10n,
        status: 'ACTIVE',
      }),
    },
    userAttributeAssignment: {
      findFirst: async () => ({
        attribute_definitions: { is_active: true },
        attribute_options: { numeric_rank: 3, is_active: true },
      }),
      findMany: async () => [],
    },
    accessGrant: {
      findUnique: async ({ where }) =>
        where.id === grantId
          ? {
              id: grantId,
              document_id: docId,
              status: 'ACTIVE',
              valid_from: new Date(Date.now() - 60_000),
              valid_until: new Date(Date.now() + 3_600_000),
            }
          : null,
    },
    accessSession: {
      create: async ({ data }) => {
        const stored = {
          ...data,
          document_versions: {
            ...documentRow.current_version,
            document: documentRow,
          },
        };
        sessions.set(data.id, stored);
        return stored;
      },
      findUnique: async ({ where }) => sessions.get(where.id) ?? null,
      update: async ({ where, data }) => {
        const existing = sessions.get(where.id);
        if (existing) Object.assign(existing, data);
        return existing;
      },
      updateMany: async ({ where, data }) => {
        const existing = sessions.get(where.id);
        if (existing && (!where.status || existing.status === where.status)) {
          Object.assign(existing, data);
          return { count: 1 };
        }
        return { count: 0 };
      },
    },
    watermarkConfig: {
      findFirst: async () => null,
    },
    watermarkInstance: {
      findFirst: async ({ where }) =>
        recordedWatermarks.find(
          (w) =>
            w.access_session_id === where.access_session_id &&
            w.document_version_id === where.document_version_id,
        ) ?? null,
      create: async ({ data }) => {
        recordedWatermarks.push(data);
        return data;
      },
    },
    auditLog: {
      findFirst: async ({ where }) => {
        const match = [...auditLogs]
          .reverse()
          .find(
            (entry) =>
              entry.sessionId === where.access_session_id &&
              entry.action === where.action &&
              entry.outcome === where.outcome,
          );
        return match ? { details: match.details } : null;
      },
    },
  };

  const mockAbac = {
    evaluate: async () => ({
      decision: 'PERMIT',
      reasonCode: 'POLICY_PERMIT',
      obligations: abacObligations,
    }),
  };
  const mockGrants = { assertGrantValidForAccess: async () => {} };
  const mockAudit = {
    record: async (entry) => {
      auditLogs.push(entry);
    },
  };
  const officeConverter = {
    convertOfficeToPdf: async () => {
      officeConversions += 1;
      return pdfBytes;
    },
  };

  const watermarkEngine = new WatermarkEngineService(mockDb);
  const pep = new DocumentPepService(mockAbac, mockGrants, mockAudit, mockDb, config, stateStore);
  const delivery = new DocumentDeliveryService(
    pep,
    storage,
    encryption,
    officeConverter,
    watermarkEngine,
    mockGrants,
    mockAudit,
    config,
    mockDb,
    stateStore,
  );

  const principal = {
    userId: 77n,
    sessionId: randomUUID(),
    username: 'staff.reader',
    departmentId: 10n,
    roles: ['DOCUMENT_READER'],
    mfa: true,
  };
  const context = {
    ip: '127.0.0.1',
    userAgent: 'SecureViewer/1.0',
    correlationId: randomUUID(),
  };

  return {
    config,
    stateStore,
    storage,
    docId,
    grantId,
    versionId,
    pdfBytes,
    pep,
    delivery,
    principal,
    context,
    auditLogs,
    recordedWatermarks,
    getOfficeConversions: () => officeConversions,
  };
}

test('BUG-009 — ABAC REQUIRE_WATERMARK forces watermark on preview & download even when classification require_watermark is false', async () => {
  // 1. Preview pipeline with require_watermark = false + POL-PERMIT-CLEARED-ACTIVE-STAFF REQUIRE_WATERMARK
  const previewHarness = await setupDeliveryHarness({
    classRequireWatermark: false,
    abacObligations: [{ type: 'REQUIRE_WATERMARK' }, { type: 'NO_CACHE' }],
  });

  const viewSession = await previewHarness.delivery.createSession(
    previewHarness.docId,
    { action: 'VIEW', grantId: previewHarness.grantId },
    previewHarness.principal,
    previewHarness.context,
  );
  assert.equal(viewSession.watermarkRequired, true);

  const storedPolicy = await previewHarness.pep.getSessionPolicy(viewSession.sessionId);
  assert.equal(storedPolicy?.watermarkRequired, true);

  const previewRes = await previewHarness.delivery.getPreviewPdf(
    previewHarness.docId,
    viewSession.sessionId,
    undefined,
    previewHarness.principal,
    previewHarness.context,
  );
  assert.match(previewRes.watermarkToken ?? '', /^WM-[0-9a-f]{48}$/);
  assert.equal(
    previewRes.buffer.toString('latin1').includes(previewRes.watermarkToken),
    true,
    'Preview PDF must contain embedded forensic watermark token',
  );
  assert.equal(previewHarness.recordedWatermarks.length, 1);
  assert.ok(
    previewHarness.auditLogs.some((e) => e.action === 'WATERMARK_GENERATED'),
    'Preview must record WATERMARK_GENERATED audit event',
  );

  // Page 1 extraction also returns the same watermark token and preserves uncompressed ICAP DLP forensic metadata
  const page1Res = await previewHarness.delivery.getPreviewPdf(
    previewHarness.docId,
    viewSession.sessionId,
    1,
    previewHarness.principal,
    previewHarness.context,
  );
  assert.equal(page1Res.watermarkToken, previewRes.watermarkToken);
  assert.equal(
    page1Res.buffer.toString('latin1').includes(`ForensicWatermark:${page1Res.watermarkToken}`),
    true,
    'Extracted preview page PDF must preserve uncompressed ForensicWatermark token for ICAP DLP',
  );

  // 2. Download ticket & download pipeline with require_watermark = false + ABAC REQUIRE_WATERMARK (Office .docx -> watermarked PDF)
  const downloadHarness = await setupDeliveryHarness({
    classRequireWatermark: false,
    abacObligations: [{ type: 'REQUIRE_WATERMARK' }, { type: 'NO_CACHE' }],
    originalFilename: 'memo.docx',
    mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    rawBytesOverride: Buffer.from('PK-mock-docx-bytes'),
  });

  const dlSession = await downloadHarness.delivery.createSession(
    downloadHarness.docId,
    { action: 'DOWNLOAD', grantId: downloadHarness.grantId },
    downloadHarness.principal,
    downloadHarness.context,
  );
  assert.equal(dlSession.watermarkRequired, true);
  const dlPolicy = await downloadHarness.pep.getSessionPolicy(dlSession.sessionId);
  assert.equal(dlPolicy?.watermarkRequired, true);

  const ticket = await downloadHarness.delivery.createDownloadTicket(
    downloadHarness.docId,
    dlSession.sessionId,
    downloadHarness.principal,
    downloadHarness.context,
  );
  const dlRes = await downloadHarness.delivery.redeemDownloadTicket(
    ticket.ticket,
    downloadHarness.context,
  );
  assert.equal(downloadHarness.getOfficeConversions(), 1);
  assert.equal(dlRes.mimeType, 'application/pdf');
  assert.equal(dlRes.filename, 'DOC-PUB-009-watermarked.pdf');
  assert.match(dlRes.watermarkToken ?? '', /^WM-[0-9a-f]{48}$/);
  assert.equal(
    dlRes.buffer.toString('latin1').includes(dlRes.watermarkToken),
    true,
    'Downloaded derivative PDF must contain embedded forensic watermark token',
  );
  assert.equal(downloadHarness.recordedWatermarks.length, 1);
});

test('BUG-009 — omits watermark cleanly when neither classification nor ABAC requires it', async () => {
  const harness = await setupDeliveryHarness({
    classRequireWatermark: false,
    abacObligations: [],
    originalFilename: 'open-handout.pdf',
  });

  const viewSession = await harness.delivery.createSession(
    harness.docId,
    { action: 'VIEW', grantId: harness.grantId },
    harness.principal,
    harness.context,
  );
  assert.equal(viewSession.watermarkRequired, false);
  const policy = await harness.pep.getSessionPolicy(viewSession.sessionId);
  assert.equal(policy?.watermarkRequired, false);

  const previewRes = await harness.delivery.getPreviewPdf(
    harness.docId,
    viewSession.sessionId,
    1,
    harness.principal,
    harness.context,
  );
  assert.equal(previewRes.watermarkToken, undefined);
  assert.equal(harness.recordedWatermarks.length, 0);

  const dlSession = await harness.delivery.createSession(
    harness.docId,
    { action: 'DOWNLOAD', grantId: harness.grantId },
    harness.principal,
    harness.context,
  );
  const dlRes = await harness.delivery.downloadDocument(
    harness.docId,
    dlSession.sessionId,
    harness.principal,
    harness.context,
  );
  assert.equal(dlRes.watermarkToken, undefined);
  assert.equal(dlRes.filename, 'open-handout.pdf');
  assert.equal(harness.recordedWatermarks.length, 0);
});

test('BUG-009 — re-hydrates watermarkRequired after cache miss or legacy cache entry & blocks stale unwatermarked derivative cache', async () => {
  const harness = await setupDeliveryHarness({
    classRequireWatermark: false,
    abacObligations: [{ type: 'REQUIRE_WATERMARK' }],
  });

  const viewSession = await harness.delivery.createSession(
    harness.docId,
    { action: 'VIEW', grantId: harness.grantId },
    harness.principal,
    harness.context,
  );

  // Simulate rolling-deploy legacy cache entry missing `watermarkRequired` AND stale unwatermarked derivative PDF cache
  await harness.stateStore.putEphemeral(
    SESSION_POLICY_NAMESPACE,
    viewSession.sessionId,
    {
      grantedAction: 'VIEW',
      forbidDownload: false,
      expiresAtMs: Date.now() + 1_800_000,
      ipAddress: '127.0.0.1',
      userAgent: 'SecureViewer/1.0',
    },
    1_800_000,
  );
  await storeCachedSessionPdf({
    storage: harness.storage,
    stateStore: harness.stateStore,
    config: harness.config,
    accessSessionId: viewSession.sessionId,
    documentVersionId: harness.versionId,
    pdfBuffer: harness.pdfBytes,
    pageCount: 1,
    watermarkToken: undefined,
    outputSha256Hash: 'stale-unwatermarked-hash',
  });

  // Preview must re-hydrate watermarkRequired=true, ignore unwatermarked cache entry, and stamp watermark
  const previewRes = await harness.delivery.getPreviewPdf(
    harness.docId,
    viewSession.sessionId,
    1,
    harness.principal,
    harness.context,
  );
  assert.match(previewRes.watermarkToken ?? '', /^WM-[0-9a-f]{48}$/);
  assert.equal(harness.recordedWatermarks.length, 1);

  const upgradedPolicy = await harness.pep.getSessionPolicy(viewSession.sessionId);
  assert.equal(upgradedPolicy?.watermarkRequired, true);

  // Direct unit check on resolveAndEnforceSessionPolicy: audit_logs obligations token alone restores watermarkRequired=true
  const resolvedFromAuditOnly = await resolveAndEnforceSessionPolicy({
    session: { id: randomUUID(), status: 'ACTIVE', started_at: new Date() },
    requiredAction: 'VIEW',
    principal: harness.principal,
    context: harness.context,
    now: new Date(),
    stateStore: new DistributedStateService(),
    database: {
      auditLog: {
        findFirst: async () => ({
          details: {
            grantedAction: 'VIEW',
            forbidDownload: false,
            obligations: 'REQUIRE_WATERMARK,NO_CACHE',
          },
        }),
      },
    },
    abac: undefined,
    config: harness.config,
  });
  assert.equal(resolvedFromAuditOnly.watermarkRequired, true);
});

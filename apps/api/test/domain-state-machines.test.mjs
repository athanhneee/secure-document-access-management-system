import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { AppErrorCode, CreateDocumentDraftSchema } from '@sda/contracts';
import { AuthorizationCache } from '../dist/modules/rbac/authorization-cache.js';
import { DocumentsService } from '../dist/modules/documents/documents.service.js';

const ownerPrincipal = {
  userId: 10n,
  sessionId: 'sess-owner',
  username: 'owner.alpha',
  roles: ['DOCUMENT_OWNER'],
  mfa: true,
};
const ctx = { ip: '10.0.0.12', correlationId: 'corr-state-machine' };

test('Document State Machine — validates draft creation schema invariants', () => {
  const validDraft = {
    title: 'Ke Hoach Bao Mat Thong Tin 2026',
    departmentId: '1',
    description: 'Bao mat tai lieu phong Ke Hoach',
    documentCode: 'DOC-SEC-2026-001',
    classificationLevelId: '3',
    businessCategoryId: '1',
  };
  const parsed = CreateDocumentDraftSchema.safeParse(validDraft);
  assert.ok(parsed.success);
  assert.equal(parsed.data.departmentId, 1n);
  assert.equal(parsed.data.classificationLevelId, 3n);

  assert.ok(!CreateDocumentDraftSchema.safeParse({ ...validDraft, title: '   ' }).success);
  assert.ok(
    !CreateDocumentDraftSchema.safeParse({ ...validDraft, retentionUntil: '23/09/2026' }).success,
  );
  assert.ok(
    CreateDocumentDraftSchema.safeParse({ ...validDraft, retentionUntil: '2026-12-31' }).success,
  );
});

test('Document State Machine — real DocumentsService enforces DRAFT -> ACTIVE -> ARCHIVED and blocks invalid transitions', async () => {
  const docId = randomUUID();
  let docState = {
    id: docId,
    document_code: 'DOC-SM-1',
    title: 'State Machine Spec',
    description: null,
    owner_id: 10n,
    department_id: 1n,
    current_version_id: 1n,
    status: 'DRAFT',
    discoverable: true,
    retention_until: null,
    archived_at: null,
    version: 0,
    created_at: new Date(),
    updated_at: new Date(),
    users: { id: 10n, status: 'ACTIVE', username: 'owner.alpha', full_name: 'Owner Alpha' },
    departments: { id: 1n, is_active: true, code: 'SEC', name: 'Security' },
    current_version: {
      id: 1n,
      version_no: 1,
      original_filename: 'spec.pdf',
      mime_type: 'application/pdf',
      file_size_bytes: 1024n,
      sha256_hash: 'a'.repeat(64),
      scan_status: 'CLEAN',
      created_at: new Date(),
    },
    classification_history: [
      {
        id: 1n,
        classification_level_id: 2n,
        business_category_id: 1n,
        effective_from: new Date(),
        effective_to: null,
        classification_levels: {
          id: 2n,
          code: 'CONFIDENTIAL',
          name: 'Mật',
          rank: 2,
          allow_download: true,
          require_watermark: true,
        },
        business_categories: { id: 1n, code: 'LEGAL', name: 'Pháp chế' },
      },
    ],
  };

  const mockDb = {
    document: {
      findUnique: async () => docState,
      update: async ({ data }) => {
        docState = {
          ...docState,
          status: data.status ?? docState.status,
          archived_at: data.archived_at ?? docState.archived_at,
          version: docState.version + 1,
        };
        return docState;
      },
    },
    accessGrant: {
      findFirst: async () => null,
      findMany: async () => [],
      create: async () => ({ id: randomUUID() }),
      updateMany: async () => ({ count: 0 }),
    },
    documentVersion: {
      findMany: async () => [{ id: 1n }],
    },
    accessSession: {
      updateMany: async () => ({ count: 0 }),
    },
    $transaction: async (fn) => fn(mockDb),
  };

  const service = new DocumentsService(
    { record: async () => {} },
    { hasPermission: async () => true },
    new AuthorizationCache(),
    mockDb,
  );

  await service.activateDocument(docId, ownerPrincipal, ctx);
  assert.equal(docState.status, 'ACTIVE');

  await assert.rejects(
    () => service.activateDocument(docId, ownerPrincipal, ctx),
    (err) => err.response?.errorCode === AppErrorCode.DOCUMENT_ALREADY_ACTIVE,
  );

  await service.archiveDocument(docId, { reason: 'End of fiscal cycle' }, ownerPrincipal, ctx);
  assert.equal(docState.status, 'ARCHIVED');

  await assert.rejects(
    () => service.activateDocument(docId, ownerPrincipal, ctx),
    (err) => err.response?.errorCode === AppErrorCode.DOCUMENT_ARCHIVED,
  );
});

test('Document State Machine — real DocumentsService SCD Type 2 reclassification closes prior row and cascades rank increase', async () => {
  const docId = randomUUID();
  const historyRows = [
    {
      id: 1n,
      document_id: docId,
      classification_level_id: 2n,
      business_category_id: 1n,
      reason: 'Initial',
      classified_by: 10n,
      effective_from: new Date('2026-01-01T00:00:00Z'),
      effective_to: null,
      classification_levels: { id: 2n, code: 'CONFIDENTIAL', name: 'Mật', rank: 2 },
      business_categories: { id: 1n, code: 'LEGAL', name: 'Pháp chế' },
    },
  ];
  const docRow = {
    id: docId,
    document_code: 'DOC-SCD2',
    title: 'SCD2 Doc',
    description: null,
    owner_id: 10n,
    department_id: 1n,
    current_version_id: null,
    status: 'ACTIVE',
    discoverable: true,
    retention_until: null,
    archived_at: null,
    version: 1,
    created_at: new Date(),
    updated_at: new Date(),
    users: { id: 10n, username: 'owner.alpha', full_name: 'Owner Alpha' },
    departments: { id: 1n, code: 'SEC', name: 'Security' },
    current_version: null,
    get classification_history() {
      return historyRows.filter((r) => r.effective_to === null);
    },
  };

  const mockDb = {
    document: { findUnique: async () => docRow },
    classificationLevel: {
      findUnique: async ({ where }) =>
        where.id === 4n
          ? {
              id: 4n,
              code: 'TOP_SECRET',
              name: 'Tuyệt mật',
              rank: 4,
              is_active: true,
              allow_download: false,
            }
          : null,
    },
    businessCategory: {
      findUnique: async () => ({ id: 1n, code: 'LEGAL', name: 'Pháp chế', is_active: true }),
    },
    documentClassificationHistory: {
      findFirst: async () => historyRows.find((r) => r.effective_to === null) ?? null,
      update: async ({ where, data }) => {
        const found = historyRows.find((r) => r.id === where.id);
        if (found) found.effective_to = data.effective_to;
      },
      create: async ({ data }) => {
        historyRows.push({
          id: 2n,
          ...data,
          classification_levels: { id: 4n, code: 'TOP_SECRET', name: 'Tuyệt mật', rank: 4 },
          business_categories: { id: 1n, code: 'LEGAL', name: 'Pháp chế' },
        });
      },
    },
    accessGrant: { findMany: async () => [] },
    accessGrantPermission: { deleteMany: async () => ({ count: 0 }) },
    $executeRawUnsafe: async () => 1,
    $transaction: async (fn) => fn(mockDb),
  };

  const service = new DocumentsService(
    { record: async () => {} },
    { hasPermission: async () => true },
    new AuthorizationCache(),
    mockDb,
  );

  await service.reclassifyDocument(
    docId,
    { classificationLevelId: 4n, businessCategoryId: 1n, reason: 'Upgraded to TOP_SECRET' },
    ownerPrincipal,
    ctx,
  );

  assert.equal(historyRows.length, 2);
  assert.ok(historyRows[0].effective_to instanceof Date);
  assert.equal(historyRows[1].effective_to, null);
  assert.equal(historyRows[1].classification_level_id, 4n);
});

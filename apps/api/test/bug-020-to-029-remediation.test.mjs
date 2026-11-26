import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { DocumentPepService } from '../dist/modules/documents/document-pep.service.js';
import { persistCleanIngestedVersion } from '../dist/modules/documents/ingestion-version.helper.js';
import { mapAccessRequestDetail } from '../dist/modules/access-requests/access-request-validation.helper.js';
import { createActivePepDocumentRow } from './helpers/document-delivery-mocks.mjs';
import { buildService, READER_PRINCIPAL, TEST_CONTEXT } from './helpers/document-search-mocks.mjs';

test('[BUG-020] persistCleanIngestedVersion preserves changeNote and falls back to "Initial version" for v1 vs "Version N" for v2+', async () => {
  const createdVersions = [];
  let existingDoc = null;

  const mockDb = {
    $transaction: async (fn) =>
      fn({
        document: {
          findUnique: async () => existingDoc,
          create: async ({ data }) => {
            existingDoc = {
              ...data,
              versions: [],
              classification_history: [{ id: 1n }],
              current_version_id: null,
            };
            return existingDoc;
          },
          update: async ({ data }) => {
            existingDoc = { ...existingDoc, ...data };
            return existingDoc;
          },
        },
        documentVersion: {
          create: async ({ data }) => {
            const ver = { id: BigInt(createdVersions.length + 1), ...data };
            createdVersions.push(ver);
            existingDoc.versions.push({ version_no: data.version_no });
            return ver;
          },
        },
        documentClassificationHistory: {
          findFirst: async () => ({
            id: 1n,
            classification_levels: { rank: 2 },
          }),
          create: async ({ data }) => data,
        },
        userAttributeAssignment: {
          findFirst: async () => ({
            attribute_definitions: { is_active: true },
            attribute_options: { is_active: true, numeric_rank: 3 },
          }),
        },
      }),
    classificationLevel: {
      findUnique: async () => ({ id: 2n, rank: 2, is_active: true }),
    },
    businessCategory: {
      findUnique: async () => ({ id: 1n, is_active: true }),
    },
  };

  const targetDocId = randomUUID();
  const principal = {
    userId: 10n,
    sessionId: randomUUID(),
    username: 'owner.demo',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const validatedInfo = {
    sanitizedFilename: 'financial-report.pdf',
    mimeType: 'application/pdf',
  };

  // v1 without changeNote -> 'Initial version'
  const v1 = await persistCleanIngestedVersion({
    database: mockDb,
    input: {
      fileStream: Readable.from([]),
      rawFilename: 'financial-report.pdf',
      declaredMime: 'application/pdf',
      title: 'Financial Report',
      classificationLevelId: 2n,
      businessCategoryId: 1n,
      principal,
      context: { ip: '127.0.0.1', correlationId: randomUUID() },
    },
    targetDocId,
    validatedInfo,
    documentStorageKey: 'docs/v1',
    totalBytes: 1024,
    sha256Hash: 'a'.repeat(64),
    dekReference: 'dek-v1',
  });
  assert.equal(v1, 1);
  assert.equal(createdVersions[0].change_note, 'Initial version');

  // v2 without changeNote -> 'Version 2' (never 'Initial version')
  const v2 = await persistCleanIngestedVersion({
    database: mockDb,
    input: {
      fileStream: Readable.from([]),
      rawFilename: 'financial-report-v2.pdf',
      declaredMime: 'application/pdf',
      documentId: targetDocId,
      principal,
      context: { ip: '127.0.0.1', correlationId: randomUUID() },
    },
    targetDocId,
    validatedInfo,
    documentStorageKey: 'docs/v2',
    totalBytes: 2048,
    sha256Hash: 'b'.repeat(64),
    dekReference: 'dek-v2',
  });
  assert.equal(v2, 2);
  assert.equal(createdVersions[1].change_note, 'Version 2');

  // v3 with explicit changeNote -> preserves trimmed changeNote
  const v3 = await persistCleanIngestedVersion({
    database: mockDb,
    input: {
      fileStream: Readable.from([]),
      rawFilename: 'financial-report-v3.pdf',
      declaredMime: 'application/pdf',
      documentId: targetDocId,
      changeNote: 'Bổ sung phụ lục kiểm toán Q4',
      principal,
      context: { ip: '127.0.0.1', correlationId: randomUUID() },
    },
    targetDocId,
    validatedInfo,
    documentStorageKey: 'docs/v3',
    totalBytes: 3072,
    sha256Hash: 'c'.repeat(64),
    dekReference: 'dek-v3',
  });
  assert.equal(v3, 3);
  assert.equal(createdVersions[2].change_note, 'Bổ sung phụ lục kiểm toán Q4');
});

test('[BUG-021] DocumentPepService.enforceAccess intersects classAllowDownload with grant DOWNLOAD permission and FORBID_DOWNLOAD obligation', async () => {
  const docId = randomUUID();
  const viewOnlyGrantId = randomUUID();
  const downloadGrantId = randomUUID();

  const makeDb = () => ({
    document: {
      findUnique: async () =>
        createActivePepDocumentRow(docId, {
          rank: 2,
          allow_download: true,
          require_watermark: true,
        }),
    },
    accessSession: {
      create: async ({ data }) => ({ id: randomUUID(), ...data }),
    },
    user: { findUnique: async () => ({ department_id: 1n, status: 'ACTIVE' }) },
    userAttributeAssignment: {
      findFirst: async () => ({
        attribute_definitions: { is_active: true },
        attribute_options: { is_active: true, numeric_rank: 4 },
      }),
    },
    userDepartmentHistory: { findFirst: async () => ({ department_id: 1n }) },
    userProjectMembership: { findMany: async () => [] },
    accessGrant: {
      findFirst: async () => ({
        id: viewOnlyGrantId,
        access_grant_permissions: [{ permission: 'VIEW' }],
      }),
      create: async ({ data }) => ({ id: randomUUID(), ...data }),
    },
    userRole: { findMany: async () => [] },
  });

  // 1. Reader with VIEW-only explicit grant on downloadable classification -> allowDownload MUST be false
  const pepViewOnly = new DocumentPepService(
    { evaluate: async () => ({ decision: 'PERMIT', obligations: [] }) },
    {
      assertGrantValidForAccess: async () => ({
        grant: { id: viewOnlyGrantId, document_id: docId, principal_type: 'USER' },
        permissions: ['VIEW'],
        documentRank: 2,
      }),
    },
    { record: async () => {} },
    makeDb(),
  );
  const viewSession = await pepViewOnly.enforceAccess(
    docId,
    { userId: 77n, username: 'reader_view_only', mfa: true },
    { ip: '127.0.0.1', userAgent: 'TestAgent' },
    { action: 'VIEW', grantId: viewOnlyGrantId },
  );
  assert.equal(viewSession.allowDownload, false);

  // 2. Reader auto-resolved grant without grantId (VIEW-only in DB) -> allowDownload MUST be false
  const autoViewSession = await pepViewOnly.enforceAccess(
    docId,
    { userId: 77n, username: 'reader_view_only', mfa: true },
    { ip: '127.0.0.1', userAgent: 'TestAgent' },
    { action: 'VIEW' },
  );
  assert.equal(autoViewSession.allowDownload, false);

  // 3. Reader with VIEW + DOWNLOAD grant and no FORBID_DOWNLOAD obligation -> allowDownload === true
  const pepWithDownload = new DocumentPepService(
    { evaluate: async () => ({ decision: 'PERMIT', obligations: [] }) },
    {
      assertGrantValidForAccess: async () => ({
        grant: { id: downloadGrantId, document_id: docId, principal_type: 'USER' },
        permissions: ['VIEW', 'DOWNLOAD'],
        documentRank: 2,
      }),
    },
    { record: async () => {} },
    makeDb(),
  );
  const downloadCapableSession = await pepWithDownload.enforceAccess(
    docId,
    { userId: 77n, username: 'reader_with_dl', mfa: true },
    { ip: '127.0.0.1', userAgent: 'TestAgent' },
    { action: 'VIEW', grantId: downloadGrantId },
  );
  assert.equal(downloadCapableSession.allowDownload, true);

  // 4. Same DOWNLOAD grant when ABAC emits FORBID_DOWNLOAD obligation -> allowDownload === false & obligation exposed
  const pepForbidObligation = new DocumentPepService(
    {
      evaluate: async () => ({
        decision: 'PERMIT',
        obligations: [{ type: 'FORBID_DOWNLOAD' }],
      }),
    },
    {
      assertGrantValidForAccess: async () => ({
        grant: { id: downloadGrantId, document_id: docId, principal_type: 'USER' },
        permissions: ['VIEW', 'DOWNLOAD'],
        documentRank: 2,
      }),
    },
    { record: async () => {} },
    makeDb(),
  );
  const obligationBlockedSession = await pepForbidObligation.enforceAccess(
    docId,
    { userId: 77n, username: 'reader_with_dl', mfa: true },
    { ip: '127.0.0.1', userAgent: 'TestAgent' },
    { action: 'VIEW', grantId: downloadGrantId },
  );
  assert.equal(obligationBlockedSession.allowDownload, false);
  assert.ok(obligationBlockedSession.obligations.includes('FORBID_DOWNLOAD'));
});

test('[BUG-022 & BUG-026] mapAccessRequestDetail includes documentClassificationCode; DocumentSearchService projects currentVersionNo and versionCount via safe LEFT JOIN + scalar subquery', async () => {
  const mappedReq = mapAccessRequestDetail({
    id: randomUUID(),
    document_id: randomUUID(),
    requester_id: 12n,
    reason: 'Cần đối chiếu hồ sơ mật',
    status: 'PENDING',
    submitted_at: new Date('2026-11-26T01:00:00.000Z'),
    requested_from: new Date('2026-11-26T01:00:00.000Z'),
    requested_until: new Date('2026-11-28T01:00:00.000Z'),
    documents: {
      title: 'Biên bản họp chiến lược',
      document_code: 'DOC-SEC-09',
      retention_until: new Date('2026-12-10T00:00:00.000Z'),
      classification_history: [
        {
          classification_levels: {
            code: 'SECRET',
            default_view_days: 7,
            allow_download: false,
          },
        },
      ],
    },
    users: { full_name: 'Nguyễn Văn A', username: 'reader.a', departments: { name: 'Kế hoạch' } },
    access_request_permissions: [{ permission: 'VIEW' }],
  });
  assert.equal(mappedReq.documentClassificationCode, 'SECRET');
  assert.equal(mappedReq.documentAllowDownload, false);

  const { service, capturedQueries, mockDatabase } = await buildService({
    discoverableDeptIds: null,
  });
  const origQueryRaw = mockDatabase.$queryRaw;
  mockDatabase.$queryRaw = async (sqlObj) => {
    const baseRows = await origQueryRaw(sqlObj);
    return baseRows.map((row, index) => ({
      ...row,
      current_version_no: index + 2,
      version_count: index + 3,
    }));
  };

  const searchRes = await service.searchDocuments(
    { scope: 'owned', page: 1, pageSize: 20, sort: 'created_at', order: 'desc' },
    READER_PRINCIPAL,
    TEST_CONTEXT,
  );
  const executedSql = capturedQueries.at(-1) ?? '';
  assert.match(executedSql, /LEFT JOIN document_versions cv\s+ON cv\.id = d\.current_version_id/);
  assert.match(
    executedSql,
    /\(SELECT COUNT\(\*\)::int FROM document_versions dv WHERE dv\.document_id = d\.id\) AS "version_count"/,
  );
  assert.doesNotMatch(executedSql, /LEFT JOIN document_versions dv\s+ON dv\.document_id = d\.id/);
  assert.equal(searchRes.data[0].currentVersionNo, 2);
  assert.equal(searchRes.data[0].versionCount, 3);
});

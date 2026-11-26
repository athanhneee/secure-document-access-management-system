/**
 * Module: Unit & Transaction TOCTOU Regression Tests for BUG-010
 * Verifies Bell-LaPadula clearance dominance (`actorClearanceRank >= level.rank`),
 * `classificationLevel.is_active`, and `businessCategory.is_active` are enforced in BOTH
 * `validateIngestionPreconditions` and `persistCleanIngestedVersion` when uploading to an
 * unclassified `DRAFT` document or creating a new document.
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { AppErrorCode } from '../../../packages/contracts/dist/error-codes.js';
import { validateIngestionPreconditions } from '../dist/modules/documents/ingestion-validation.helper.js';
import { persistCleanIngestedVersion } from '../dist/modules/documents/ingestion-version.helper.js';

function createDraftIngestionMockDb({
  draftId,
  ownerId,
  ownerClearanceRank,
  levels,
  categories,
  activeClassification = null,
}) {
  const createdVersions = [];
  const createdClassifications = [];

  const txClient = {
    document: {
      findUnique: async ({ where }) =>
        where.id === draftId
          ? {
              id: draftId,
              owner_id: ownerId,
              department_id: 10n,
              status: 'DRAFT',
              current_version_id: null,
              versions: [],
              classification_history: activeClassification ? [{ id: 1n }] : [],
            }
          : null,
      create: async ({ data }) => data,
      update: async ({ where, data }) => ({ id: where.id, ...data }),
    },
    department: {
      findUnique: async ({ where }) => (where.id === 10n ? { id: 10n, is_active: true } : null),
    },
    user: {
      findUnique: async () => ({ id: ownerId, department_id: 10n, status: 'ACTIVE' }),
    },
    userAttributeAssignment: {
      findFirst: async () => ({
        attribute_definitions: { is_active: true },
        attribute_options: { numeric_rank: ownerClearanceRank, is_active: true },
      }),
    },
    classificationLevel: {
      findUnique: async ({ where }) => levels.get(where.id) ?? null,
    },
    businessCategory: {
      findUnique: async ({ where }) => categories.get(where.id) ?? null,
    },
    documentClassificationHistory: {
      findFirst: async () => activeClassification,
      create: async ({ data }) => {
        createdClassifications.push(data);
        return { id: 99n, ...data };
      },
    },
    documentVersion: {
      create: async ({ data }) => {
        createdVersions.push(data);
        return { id: 500n, ...data };
      },
    },
  };

  return {
    db: {
      ...txClient,
      $transaction: async (fn) => fn(txClient),
    },
    createdVersions,
    createdClassifications,
  };
}

const VALIDATED_PDF_INFO = {
  sanitizedFilename: 'draft.pdf',
  extension: 'pdf',
  mimeType: 'application/pdf',
  isOfficeFormat: false,
};

test('BUG-010 — blocks Bell-LaPadula escalation, inactive level & inactive category on unclassified DRAFT in both pre-validation and transaction', async () => {
  const draftId = crypto.randomUUID();
  const ownerId = 42n;
  const principal = {
    userId: ownerId,
    sessionId: crypto.randomUUID(),
    username: 'rank1.owner',
    departmentId: 10n,
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const context = { ip: '127.0.0.1', correlationId: crypto.randomUUID() };

  const levels = new Map([
    [1n, { id: 1n, code: 'INTERNAL', rank: 1, is_active: true }],
    [4n, { id: 4n, code: 'TOP_SECRET', rank: 4, is_active: true }],
    [5n, { id: 5n, code: 'LEGACY_OFF', rank: 1, is_active: false }],
  ]);
  const categories = new Map([
    [1n, { id: 1n, code: 'GENERAL', is_active: true }],
    [2n, { id: 2n, code: 'RETIRED_CAT', is_active: false }],
  ]);

  const { db, createdVersions, createdClassifications } = createDraftIngestionMockDb({
    draftId,
    ownerId,
    ownerClearanceRank: 1,
    levels,
    categories,
  });

  // 1. Rank-1 owner tries to attach TOP_SECRET (rank 4) to unclassified DRAFT -> 403 in pre-validation
  const streamTopSecret = Readable.from([Buffer.from('%PDF-1.4')]);
  await assert.rejects(
    () =>
      validateIngestionPreconditions(
        {
          fileStream: streamTopSecret,
          rawFilename: 'draft.pdf',
          declaredMime: 'application/pdf',
          documentId: draftId,
          classificationLevelId: 4n,
          businessCategoryId: 1n,
          principal,
          context,
        },
        db,
      ),
    (err) => err.response?.errorCode === AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
  );
  assert.equal(streamTopSecret.destroyed, true);

  // 2. Inactive classification level -> 400 in pre-validation
  const streamInactiveLevel = Readable.from([Buffer.from('%PDF-1.4')]);
  await assert.rejects(
    () =>
      validateIngestionPreconditions(
        {
          fileStream: streamInactiveLevel,
          rawFilename: 'draft.pdf',
          declaredMime: 'application/pdf',
          documentId: draftId,
          classificationLevelId: 5n,
          businessCategoryId: 1n,
          principal,
          context,
        },
        db,
      ),
    (err) => err.response?.errorCode === AppErrorCode.VALIDATION_FAILED,
  );
  assert.equal(streamInactiveLevel.destroyed, true);

  // 3. Inactive business category -> 400 in pre-validation (for both DRAFT and brand-new doc)
  for (const targetDocumentId of [draftId, undefined]) {
    const streamInactiveCat = Readable.from([Buffer.from('%PDF-1.4')]);
    await assert.rejects(
      () =>
        validateIngestionPreconditions(
          {
            fileStream: streamInactiveCat,
            rawFilename: 'draft.pdf',
            declaredMime: 'application/pdf',
            documentId: targetDocumentId,
            classificationLevelId: 1n,
            businessCategoryId: 2n,
            principal,
            context,
          },
          db,
        ),
      (err) => err.response?.errorCode === AppErrorCode.VALIDATION_FAILED,
    );
    assert.equal(streamInactiveCat.destroyed, true);
  }

  // 4. TOCTOU transaction defense-in-depth: direct persistCleanIngestedVersion also blocks all 3 cases
  await assert.rejects(
    () =>
      persistCleanIngestedVersion({
        database: db,
        input: {
          fileStream: Readable.from([]),
          rawFilename: 'draft.pdf',
          declaredMime: 'application/pdf',
          documentId: draftId,
          classificationLevelId: 4n,
          businessCategoryId: 1n,
          principal,
          context,
        },
        targetDocId: draftId,
        validatedInfo: VALIDATED_PDF_INFO,
        documentStorageKey: 'documents/test.enc',
        totalBytes: 128,
        sha256Hash: 'a'.repeat(64),
        dekReference: 'kms:dek:1',
      }),
    (err) => err.response?.errorCode === AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
  );

  await assert.rejects(
    () =>
      persistCleanIngestedVersion({
        database: db,
        input: {
          fileStream: Readable.from([]),
          rawFilename: 'draft.pdf',
          declaredMime: 'application/pdf',
          documentId: draftId,
          classificationLevelId: 5n,
          businessCategoryId: 1n,
          principal,
          context,
        },
        targetDocId: draftId,
        validatedInfo: VALIDATED_PDF_INFO,
        documentStorageKey: 'documents/test.enc',
        totalBytes: 128,
        sha256Hash: 'a'.repeat(64),
        dekReference: 'kms:dek:1',
      }),
    (err) => err.response?.errorCode === AppErrorCode.VALIDATION_FAILED,
  );

  await assert.rejects(
    () =>
      persistCleanIngestedVersion({
        database: db,
        input: {
          fileStream: Readable.from([]),
          rawFilename: 'draft.pdf',
          declaredMime: 'application/pdf',
          documentId: draftId,
          classificationLevelId: 1n,
          businessCategoryId: 2n,
          principal,
          context,
        },
        targetDocId: draftId,
        validatedInfo: VALIDATED_PDF_INFO,
        documentStorageKey: 'documents/test.enc',
        totalBytes: 128,
        sha256Hash: 'a'.repeat(64),
        dekReference: 'kms:dek:1',
      }),
    (err) => err.response?.errorCode === AppErrorCode.VALIDATION_FAILED,
  );

  assert.equal(createdVersions.length, 0);
  assert.equal(createdClassifications.length, 0);

  // 5. Positive control: rank-1 owner attaching active rank-1 level + active category succeeds cleanly
  const validStream = Readable.from([Buffer.from('%PDF-1.4')]);
  await validateIngestionPreconditions(
    {
      fileStream: validStream,
      rawFilename: 'draft.pdf',
      declaredMime: 'application/pdf',
      documentId: draftId,
      classificationLevelId: 1n,
      businessCategoryId: 1n,
      principal,
      context,
    },
    db,
  );
  assert.equal(validStream.destroyed, false);

  const versionNo = await persistCleanIngestedVersion({
    database: db,
    input: {
      fileStream: validStream,
      rawFilename: 'draft.pdf',
      declaredMime: 'application/pdf',
      documentId: draftId,
      classificationLevelId: 1n,
      businessCategoryId: 1n,
      principal,
      context,
    },
    targetDocId: draftId,
    validatedInfo: VALIDATED_PDF_INFO,
    documentStorageKey: 'documents/valid.enc',
    totalBytes: 128,
    sha256Hash: 'b'.repeat(64),
    dekReference: 'kms:dek:2',
  });
  assert.equal(versionNo, 1);
  assert.equal(createdVersions.length, 1);
  assert.equal(createdClassifications.length, 1);
  assert.equal(createdClassifications[0].classification_level_id, 1n);
  assert.equal(createdClassifications[0].business_category_id, 1n);
});

test('BUG-010 — rejects missing/inactive fallback default businessCategoryId (1n) when classificationLevelId is provided without businessCategoryId', async () => {
  const draftId = crypto.randomUUID();
  const ownerId = 42n;
  const principal = {
    userId: ownerId,
    sessionId: crypto.randomUUID(),
    username: 'rank1.owner',
    departmentId: 10n,
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const context = { ip: '127.0.0.1', correlationId: crypto.randomUUID() };

  const { db } = createDraftIngestionMockDb({
    draftId,
    ownerId,
    ownerClearanceRank: 2,
    levels: new Map([[1n, { id: 1n, code: 'INTERNAL', rank: 1, is_active: true }]]),
    categories: new Map([[1n, { id: 1n, code: 'DISABLED_DEFAULT', is_active: false }]]),
  });

  const stream = Readable.from([Buffer.from('%PDF-1.4')]);
  await assert.rejects(
    () =>
      validateIngestionPreconditions(
        {
          fileStream: stream,
          rawFilename: 'draft.pdf',
          declaredMime: 'application/pdf',
          documentId: draftId,
          classificationLevelId: 1n,
          principal,
          context,
        },
        db,
      ),
    (err) => err.response?.errorCode === AppErrorCode.VALIDATION_FAILED,
  );
  assert.equal(stream.destroyed, true);
});

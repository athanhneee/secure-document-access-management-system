/**
 * Module: PostgreSQL Integration Regression Test for BUG-010
 * Verifies Bell-LaPadula clearance dominance and active classification/category guards
 * against real PostgreSQL when uploading a file with `classificationLevelId` into an
 * unclassified `DRAFT` document created via `DocumentsService.createDocumentDraft`.
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { after, before, test } from 'node:test';
import { AppErrorCode } from '@sda/contracts';
import { createEphemeralDatabaseHarness } from '../helpers/postgres-integration-harness.mjs';

const dbHarness = createEphemeralDatabaseHarness('sda_bug010_draft', { coerceBigIntId: true });

let DocumentsService;
let validateIngestionPreconditions;
let persistCleanIngestedVersion;
let documentsService;
let dept;
let rank1Owner;
let levelInternal;
let levelTopSecret;
let levelInactive;
let categoryActive;
let categoryInactive;

before(async () => {
  const ready = await dbHarness.setup();
  if (!ready) return;

  ({ DocumentsService } = await import('../../dist/modules/documents/documents.service.js'));
  ({ validateIngestionPreconditions } =
    await import('../../dist/modules/documents/ingestion-validation.helper.js'));
  ({ persistCleanIngestedVersion } =
    await import('../../dist/modules/documents/ingestion-version.helper.js'));

  const { sql, insertOne, prisma } = dbHarness;

  dept = await insertOne(
    "INSERT INTO departments(code,name,is_active) VALUES ('ING_OPS','Khối Tiếp nhận',true) RETURNING id",
  );
  rank1Owner = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('owner.rank1','owner.rank1@corp.local','hash','Chủ sở hữu Bậc 1',$1,'ACTIVE') RETURNING id`,
    [dept.id],
  );

  levelInternal = await insertOne(
    `INSERT INTO classification_levels(code,name,rank,default_view_days,allow_download,require_watermark,is_active)
     VALUES ('INTERNAL','Nội bộ',2,7,true,true,true) RETURNING id`,
  );
  levelTopSecret = await insertOne(
    `INSERT INTO classification_levels(code,name,rank,default_view_days,allow_download,require_watermark,is_active)
     VALUES ('TOP_SECRET','Tuyệt mật',4,1,false,true,true) RETURNING id`,
  );
  levelInactive = await insertOne(
    `INSERT INTO classification_levels(code,name,rank,default_view_days,allow_download,require_watermark,is_active)
     VALUES ('LEGACY_DISABLED','Cấp đã tắt',1,7,true,true,false) RETURNING id`,
  );

  categoryActive = await insertOne(
    "INSERT INTO business_categories(code,name,department_id,is_active) VALUES ('CAT_ACTIVE','Nghiệp vụ chuẩn',$1,true) RETURNING id",
    [dept.id],
  );
  categoryInactive = await insertOne(
    "INSERT INTO business_categories(code,name,department_id,is_active) VALUES ('CAT_OFF','Danh mục đã tắt',$1,false) RETURNING id",
    [dept.id],
  );

  const clearanceDef = await insertOne(
    "INSERT INTO attribute_definitions(code,name,scope,value_type,is_required,is_active,created_by) VALUES ('CLEARANCE_LEVEL','Clearance','USER','ENUM',true,true,$1) RETURNING id",
    [rank1Owner.id],
  );
  const rank2Opt = await insertOne(
    "INSERT INTO attribute_options(attribute_definition_id,value_code,display_name,numeric_rank,is_active) VALUES ($1,'INTERNAL','Rank 2',2,true) RETURNING id",
    [clearanceDef.id],
  );
  await sql.query(
    `INSERT INTO user_attribute_assignments(user_id,attribute_definition_id,option_id,valid_from,assigned_by)
     VALUES ($1,$2,$3,now() - interval '1 hour',$1)`,
    [rank1Owner.id, clearanceDef.id, rank2Opt.id],
  );

  documentsService = new DocumentsService(
    { record: async () => {} },
    { hasPermission: async () => true, visibleDepartmentIds: async () => null },
    { invalidateUser: () => {} },
    prisma,
  );
});

after(async () => {
  await dbHarness.teardown();
});

test('BUG-010 PostgreSQL integration — unclassified DRAFT upload rejects TOP_SECRET escalation, inactive level, and inactive category, while permitting rank-1 classification', async () => {
  const principal = {
    userId: rank1Owner.id,
    sessionId: randomUUID(),
    username: 'owner.rank1',
    departmentId: dept.id,
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const ctx = { ip: '10.0.0.15', userAgent: 'integration-bug010', correlationId: randomUUID() };

  // Create unclassified DRAFT via DocumentsService.createDocumentDraft (no classificationLevelId / businessCategoryId)
  const draft = await documentsService.createDocumentDraft(
    {
      title: 'Bản nháp chưa phân loại',
      documentCode: 'DOC-UNCLASS-010',
      departmentId: dept.id,
    },
    principal,
    ctx,
  );
  assert.equal(draft.status, 'DRAFT');

  const baseInput = {
    rawFilename: 'draft.pdf',
    declaredMime: 'application/pdf',
    documentId: draft.id,
    principal,
    context: ctx,
  };
  const validatedInfo = {
    sanitizedFilename: 'draft.pdf',
    extension: 'pdf',
    mimeType: 'application/pdf',
    isOfficeFormat: false,
  };

  // 1. Escalation to TOP_SECRET (rank 4 > rank 1) rejected in BOTH pre-validation and SQL transaction
  await assert.rejects(
    () =>
      validateIngestionPreconditions(
        {
          ...baseInput,
          fileStream: Readable.from([Buffer.from('%PDF-1.4')]),
          classificationLevelId: levelTopSecret.id,
          businessCategoryId: categoryActive.id,
        },
        dbHarness.prisma,
      ),
    (err) => err.response?.errorCode === AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
  );
  await assert.rejects(
    () =>
      persistCleanIngestedVersion({
        database: dbHarness.prisma,
        input: {
          ...baseInput,
          fileStream: Readable.from([]),
          classificationLevelId: levelTopSecret.id,
          businessCategoryId: categoryActive.id,
        },
        targetDocId: draft.id,
        validatedInfo,
        documentStorageKey: 'vault/top-secret-attempt.enc',
        totalBytes: 512,
        sha256Hash: '1'.repeat(64),
        dekReference: 'kms:dek:ts',
      }),
    (err) => err.response?.errorCode === AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
  );

  // 2. Inactive classification level rejected in BOTH pre-validation and SQL transaction
  await assert.rejects(
    () =>
      validateIngestionPreconditions(
        {
          ...baseInput,
          fileStream: Readable.from([Buffer.from('%PDF-1.4')]),
          classificationLevelId: levelInactive.id,
          businessCategoryId: categoryActive.id,
        },
        dbHarness.prisma,
      ),
    (err) => err.response?.errorCode === AppErrorCode.VALIDATION_FAILED,
  );
  await assert.rejects(
    () =>
      persistCleanIngestedVersion({
        database: dbHarness.prisma,
        input: {
          ...baseInput,
          fileStream: Readable.from([]),
          classificationLevelId: levelInactive.id,
          businessCategoryId: categoryActive.id,
        },
        targetDocId: draft.id,
        validatedInfo,
        documentStorageKey: 'vault/inactive-level-attempt.enc',
        totalBytes: 512,
        sha256Hash: '2'.repeat(64),
        dekReference: 'kms:dek:il',
      }),
    (err) => err.response?.errorCode === AppErrorCode.VALIDATION_FAILED,
  );

  // 3. Inactive business category rejected in BOTH pre-validation and SQL transaction
  await assert.rejects(
    () =>
      validateIngestionPreconditions(
        {
          ...baseInput,
          fileStream: Readable.from([Buffer.from('%PDF-1.4')]),
          classificationLevelId: levelInternal.id,
          businessCategoryId: categoryInactive.id,
        },
        dbHarness.prisma,
      ),
    (err) => err.response?.errorCode === AppErrorCode.VALIDATION_FAILED,
  );
  await assert.rejects(
    () =>
      persistCleanIngestedVersion({
        database: dbHarness.prisma,
        input: {
          ...baseInput,
          fileStream: Readable.from([]),
          classificationLevelId: levelInternal.id,
          businessCategoryId: categoryInactive.id,
        },
        targetDocId: draft.id,
        validatedInfo,
        documentStorageKey: 'vault/inactive-cat-attempt.enc',
        totalBytes: 512,
        sha256Hash: '3'.repeat(64),
        dekReference: 'kms:dek:ic',
      }),
    (err) => err.response?.errorCode === AppErrorCode.VALIDATION_FAILED,
  );

  // Verify database remained completely untouched after all blocked attempts
  const beforeValid = await dbHarness.sql.query(
    `SELECT
       (SELECT count(*)::int FROM document_versions WHERE document_id = $1) AS ver_cnt,
       (SELECT count(*)::int FROM document_classification_history WHERE document_id = $1) AS class_cnt`,
    [draft.id],
  );
  assert.equal(beforeValid.rows[0].ver_cnt, 0);
  assert.equal(beforeValid.rows[0].class_cnt, 0);

  // 4. Valid rank-1 active classification + active category succeeds and persists cleanly
  await validateIngestionPreconditions(
    {
      ...baseInput,
      fileStream: Readable.from([Buffer.from('%PDF-1.4')]),
      classificationLevelId: levelInternal.id,
      businessCategoryId: categoryActive.id,
    },
    dbHarness.prisma,
  );
  const versionNo = await persistCleanIngestedVersion({
    database: dbHarness.prisma,
    input: {
      ...baseInput,
      fileStream: Readable.from([]),
      classificationLevelId: levelInternal.id,
      businessCategoryId: categoryActive.id,
    },
    targetDocId: draft.id,
    validatedInfo,
    documentStorageKey: 'vault/valid-rank1.enc',
    totalBytes: 512,
    sha256Hash: '4'.repeat(64),
    dekReference: 'kms:dek:ok',
  });
  assert.equal(versionNo, 1);

  const afterValid = await dbHarness.sql.query(
    `SELECT dch.classification_level_id, dch.business_category_id, d.current_version_id
     FROM documents d
     JOIN document_classification_history dch ON dch.document_id = d.id AND dch.effective_to IS NULL
     WHERE d.id = $1`,
    [draft.id],
  );
  assert.equal(afterValid.rows.length, 1);
  assert.equal(BigInt(afterValid.rows[0].classification_level_id), levelInternal.id);
  assert.equal(BigInt(afterValid.rows[0].business_category_id), categoryActive.id);
  assert.ok(afterValid.rows[0].current_version_id !== null);
});

import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { BadRequestException } from '@nestjs/common';
import { createEphemeralDatabaseHarness } from '../helpers/postgres-integration-harness.mjs';
import { setupDocumentsWatermarksIntegrationFixture } from '../helpers/documents-watermarks-integration-setup.mjs';

const dbHarness = createEphemeralDatabaseHarness('sda_docs_wm', { coerceBigIntId: true });
const ctx = { ip: '10.10.20.30', userAgent: 'integration-docs', correlationId: randomUUID() };

let classificationsService;
let documentsService;
let watermarksService;
let dept;
let ownerUser;
let lowClearedReader;
let secOfficer;
let levelInternal;
let levelTopSecret;
let categoryFinance;
let wmConfig;

before(async () => {
  const ready = await dbHarness.setup();
  if (!ready) return;

  ({
    classificationsService,
    documentsService,
    watermarksService,
    dept,
    ownerUser,
    lowClearedReader,
    secOfficer,
    levelInternal,
    levelTopSecret,
    categoryFinance,
    wmConfig,
  } = await setupDocumentsWatermarksIntegrationFixture(dbHarness));
});

after(async () => {
  await dbHarness.teardown();
});

test('ClassificationsService & DocumentsService SQL integration — lattice projection, DRAFT->ACTIVE->ARCHIVED & SCD2 cascading rank revocation', async () => {
  const levels = await classificationsService.listClassificationLevels();
  assert.deepEqual(
    levels.data.map((l) => l.code),
    ['INTERNAL', 'TOP_SECRET'],
  );
  const categories = await classificationsService.listBusinessCategories();
  assert.equal(categories.data[0].code, 'FIN_REPORT');
  assert.equal(categories.data[0].departmentName, 'Khối Tài chính Kế toán');

  const ownerPrincipal = {
    userId: ownerUser.id,
    sessionId: randomUUID(),
    username: 'owner.docs',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };

  const draft = await documentsService.createDocumentDraft(
    {
      title: 'Báo cáo Kiểm toán Nội bộ Quý 4',
      documentCode: 'DOC-FIN-Q4-2026',
      departmentId: dept.id,
      classificationLevelId: levelInternal.id,
      businessCategoryId: categoryFinance.id,
      description: 'Tài liệu kiểm thử tích hợp SQL',
    },
    ownerPrincipal,
    ctx,
  );
  assert.equal(draft.status, 'DRAFT');

  // Attach a CLEAN document_version in SQL, set current version, and activate
  const versionRow = await dbHarness.insertOne(
    `INSERT INTO document_versions(document_id,version_no,storage_key,original_filename,mime_type,file_size_bytes,sha256_hash,encryption_key_ref,scan_status,uploaded_by)
     VALUES ($1,1,'vault/doc-q4-v1.enc','q4-report.pdf','application/pdf',4096,$2,'kms:dek:v1','CLEAN',$3) RETURNING id`,
    [draft.id, 'a'.repeat(64), ownerUser.id],
  );
  await documentsService.setCurrentVersion(
    draft.id,
    { versionId: versionRow.id },
    ownerPrincipal,
    ctx,
  );
  const active = await documentsService.activateDocument(draft.id, ownerPrincipal, ctx);
  assert.equal(active.status, 'ACTIVE');

  // Grant VIEW + DOWNLOAD to lowClearedReader (rank 2) while document is INTERNAL (rank 2)
  const grantId = randomUUID();
  const sessId = randomUUID();
  await dbHarness.sql.query(
    `INSERT INTO access_grants(id,document_id,principal_type,principal_user_id,status,valid_from,valid_until,granted_by,source)
     VALUES ($1,$2,'USER',$3,'ACTIVE',now() - interval '5 minutes',now() + interval '2 days',$4,'DIRECT')`,
    [grantId, draft.id, lowClearedReader.id, ownerUser.id],
  );
  await dbHarness.sql.query(
    "INSERT INTO access_grant_permissions(access_grant_id,permission) VALUES ($1,'VIEW'),($1,'DOWNLOAD')",
    [grantId],
  );
  await dbHarness.sql.query(
    `INSERT INTO access_sessions(id,access_grant_id,document_version_id,user_id,ip_address,status)
     VALUES ($1,$2,$3,$4,'10.10.20.99','ACTIVE')`,
    [sessId, grantId, versionRow.id, lowClearedReader.id],
  );

  // Upgrade classification to TOP_SECRET (rank 4) -> SCD2 closes old history row and cascades revocation on rank-2 user!
  await documentsService.reclassifyDocument(
    draft.id,
    {
      classificationLevelId: levelTopSecret.id,
      businessCategoryId: categoryFinance.id,
      reason: 'Nâng mức độ mật lên Tuyệt mật theo quyết định Ban Tổng Giám đốc',
    },
    ownerPrincipal,
    ctx,
  );

  const history = await documentsService.getClassificationHistory(draft.id, ownerPrincipal);
  assert.equal(history.length, 2);
  const postReclassify = await dbHarness.sql.query(
    `SELECT
       (SELECT status::text FROM access_grants WHERE id=$1) AS grant_status,
       (SELECT status::text FROM access_sessions WHERE id=$2) AS session_status`,
    [grantId, sessId],
  );
  assert.equal(postReclassify.rows[0].grant_status, 'REVOKED');
  assert.equal(postReclassify.rows[0].session_status, 'TERMINATED');

  const archived = await documentsService.archiveDocument(
    draft.id,
    { reason: 'Lưu trữ cuối kỳ tài chính' },
    ownerPrincipal,
    ctx,
  );
  assert.equal(archived.status, 'ARCHIVED');
});

test('WatermarksService SQL integration — policy-constrained config mutation & UC28 forensic leak token attribution', async () => {
  const secPrincipal = {
    userId: secOfficer.id,
    sessionId: randomUUID(),
    username: 'sec.forensic',
    roles: ['SECURITY_OFFICER'],
    mfa: true,
  };

  const listed = await watermarksService.listConfigs();
  assert.equal(listed.data.length, 1);

  await assert.rejects(
    () => watermarksService.updateConfig(wmConfig.id, { isVisible: false }, secPrincipal),
    BadRequestException,
  );
  await assert.rejects(
    () => watermarksService.updateConfig(wmConfig.id, { opacityPercent: 5 }, secPrincipal),
    BadRequestException,
  );

  const updated = await watermarksService.updateConfig(
    wmConfig.id,
    { opacityPercent: 35, templateText: 'TOP SECRET - {username} - {shortToken}' },
    secPrincipal,
  );
  assert.equal(updated.opacityPercent, 35);
  assert.equal(updated.templateText, 'TOP SECRET - {username} - {shortToken}');

  // Seed a forensic watermark_instances record tied to an access session and trace it via UC28
  const docRow = await dbHarness.insertOne(
    `INSERT INTO documents(id,document_code,title,owner_id,department_id,status)
     VALUES ($1,'DOC-WM-TRACE','Hồ sơ Mật Truy vết',$2,$3,'ACTIVE') RETURNING id`,
    [randomUUID(), ownerUser.id, dept.id],
  );
  await dbHarness.sql.query(
    "INSERT INTO document_classification_history(document_id,classification_level_id,business_category_id,classified_by,effective_from) VALUES ($1,$2,$3,$4,now() - interval '1 hour')",
    [docRow.id, levelInternal.id, categoryFinance.id, ownerUser.id],
  );
  const verRow = await dbHarness.insertOne(
    `INSERT INTO document_versions(document_id,version_no,storage_key,original_filename,mime_type,file_size_bytes,sha256_hash,encryption_key_ref,scan_status,uploaded_by)
     VALUES ($1,1,'vault/wm.enc','wm.pdf','application/pdf',2048,$2,'kms:dek:wm','CLEAN',$3) RETURNING id`,
    [docRow.id, 'b'.repeat(64), ownerUser.id],
  );
  const grantId = randomUUID();
  const sessId = randomUUID();
  const leakToken = `WMK-${randomUUID().replaceAll('-', '').slice(0, 24).toUpperCase()}`;
  await dbHarness.sql.query(
    `INSERT INTO access_grants(id,document_id,principal_type,principal_user_id,status,valid_from,valid_until,granted_by,source)
     VALUES ($1,$2,'USER',$3,'ACTIVE',now() - interval '1 hour',now() + interval '1 hour',$4,'DIRECT')`,
    [grantId, docRow.id, lowClearedReader.id, ownerUser.id],
  );
  await dbHarness.sql.query(
    `INSERT INTO access_sessions(id,access_grant_id,document_version_id,user_id,ip_address,user_agent,status)
     VALUES ($1,$2,$3,$4,'198.51.100.88','Mozilla/5.0','ACTIVE')`,
    [sessId, grantId, verRow.id, lowClearedReader.id],
  );
  await dbHarness.sql.query(
    `INSERT INTO watermark_instances(id,access_session_id,watermark_config_id,user_id,document_version_id,watermark_token,rendered_text,output_sha256_hash)
     VALUES ($1,$2,$3,$4,$5,$6,'TOP SECRET - reader.rank2',$7)`,
    [randomUUID(), sessId, wmConfig.id, lowClearedReader.id, verRow.id, leakToken, 'c'.repeat(64)],
  );

  const traced = await watermarksService.verifyWatermarkToken(leakToken, secPrincipal);
  assert.equal(traced.verified, true);
  assert.equal(traced.user.username, 'reader.rank2');
  assert.equal(traced.session.ipAddress, '198.51.100.88');
  assert.equal(traced.document.documentCode, 'DOC-WM-TRACE');
});

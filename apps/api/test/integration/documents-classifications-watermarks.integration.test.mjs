import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { BadRequestException } from '@nestjs/common';
import { createEphemeralDatabaseHarness } from '../helpers/postgres-integration-harness.mjs';

const dbHarness = createEphemeralDatabaseHarness('sda_docs_wm', { coerceBigIntId: true });
const ctx = { ip: '10.10.20.30', userAgent: 'integration-docs', correlationId: randomUUID() };

let classificationsService;
let documentsService;
let watermarksService;
let auditWriter;
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

  const { sql, insertOne, prisma } = dbHarness;
  dept = await insertOne(
    "INSERT INTO departments(code,name) VALUES ('FIN_DOCS','Khối Tài chính Kế toán') RETURNING id",
  );
  ownerUser = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('owner.docs','owner.docs@corp.local','hash','Chủ sở hữu Tài liệu',$1,'ACTIVE') RETURNING id`,
    [dept.id],
  );
  lowClearedReader = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('reader.rank2','reader.rank2@corp.local','hash','Người đọc Mức 2',$1,'ACTIVE') RETURNING id`,
    [dept.id],
  );
  secOfficer = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('sec.forensic','sec.forensic@corp.local','hash','Cán bộ An ninh',$1,'ACTIVE') RETURNING id`,
    [dept.id],
  );

  // Grant DOCUMENT:MANAGE to ownerUser
  const ownerRole = await insertOne(
    "INSERT INTO roles(code,name,is_active,created_by) VALUES ('DOCUMENT_OWNER','Owner',true,$1) RETURNING id",
    [ownerUser.id],
  );
  const docManagePerm = await insertOne(
    "INSERT INTO permissions(code,name,resource_type,action) VALUES ('DOC_MANAGE_IT','Doc Manage','DOCUMENT','MANAGE') RETURNING id",
  );
  await sql.query(
    'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3)',
    [ownerRole.id, docManagePerm.id, ownerUser.id],
  );
  await sql.query(
    "INSERT INTO user_roles(user_id,role_id,valid_from,assigned_by) VALUES ($1,$2,now() - interval '1 hour',$1)",
    [ownerUser.id, ownerRole.id],
  );

  // Seed classification lattice & business category
  levelInternal = await insertOne(
    `INSERT INTO classification_levels(code,name,rank,default_view_days,allow_download,require_watermark,is_active)
     VALUES ('INTERNAL','Nội bộ',2,14,true,true,true) RETURNING id`,
  );
  levelTopSecret = await insertOne(
    `INSERT INTO classification_levels(code,name,rank,default_view_days,allow_download,require_watermark,is_active)
     VALUES ('TOP_SECRET','Tuyệt mật',4,1,false,true,true) RETURNING id`,
  );
  categoryFinance = await insertOne(
    `INSERT INTO business_categories(code,name,department_id,is_active)
     VALUES ('FIN_REPORT','Báo cáo Tài chính',$1,true) RETURNING id`,
    [dept.id],
  );

  // Seed ABAC CLEARANCE_LEVEL = 2 for lowClearedReader and 4 for ownerUser (required by SQL trigger validate_user_clearance_for_grant)
  const clearanceDef = await insertOne(
    "INSERT INTO attribute_definitions(code,name,scope,value_type,is_required,is_active,created_by) VALUES ('CLEARANCE_LEVEL','Clearance','USER','ENUM',true,true,$1) RETURNING id",
    [ownerUser.id],
  );
  const rank2Opt = await insertOne(
    "INSERT INTO attribute_options(attribute_definition_id,value_code,display_name,numeric_rank,is_active) VALUES ($1,'INTERNAL','Rank 2',2,true) RETURNING id",
    [clearanceDef.id],
  );
  const rank4Opt = await insertOne(
    "INSERT INTO attribute_options(attribute_definition_id,value_code,display_name,numeric_rank,is_active) VALUES ($1,'TOP_SECRET','Rank 4',4,true) RETURNING id",
    [clearanceDef.id],
  );
  await sql.query(
    "INSERT INTO user_attribute_assignments(user_id,attribute_definition_id,option_id,valid_from,assigned_by) VALUES ($1,$2,$3,now() - interval '1 hour',$4),($4,$2,$5,now() - interval '1 hour',$4)",
    [lowClearedReader.id, clearanceDef.id, rank2Opt.id, ownerUser.id, rank4Opt.id],
  );

  wmConfig = await insertOne(
    `INSERT INTO watermark_configs(name,classification_level_id,is_default,is_visible,template_text,opacity_percent,rotation_degrees,font_size,color_hex,include_qr_code,is_active,created_by)
     VALUES ('Mẫu Tuyệt Mật',$1,true,true,'CONFIDENTIAL - {username} - {timestamp}',25,-35,16,'#CC0000',true,true,$2) RETURNING id`,
    [levelTopSecret.id, secOfficer.id],
  );

  const { AppConfigService } = await import('../../dist/config/config.service.js');
  const { AuthorizationCache } = await import('../../dist/modules/rbac/authorization-cache.js');
  const { AuthorizationService } = await import('../../dist/modules/rbac/authorization.service.js');
  const { AuditRedactionService } =
    await import('../../dist/modules/audit/audit-redaction.service.js');
  const { AuditWriterService } = await import('../../dist/modules/audit/audit-writer.service.js');
  const { DocumentAuditService } =
    await import('../../dist/modules/documents/document-audit.service.js');
  const { DocumentsService } = await import('../../dist/modules/documents/documents.service.js');
  const { ClassificationsService } =
    await import('../../dist/modules/classifications/classifications.service.js');
  const { WatermarksService } = await import('../../dist/modules/watermarks/watermarks.service.js');

  const appConfig = new AppConfigService({
    AUTH_AUDIT_HMAC_KEY: 'integration-docs-hmac-key-0123456789abcdef0123456789',
  });
  const cache = new AuthorizationCache();
  const authz = new AuthorizationService(cache);
  auditWriter = new AuditWriterService(appConfig, new AuditRedactionService(), prisma);
  classificationsService = new ClassificationsService(prisma);
  documentsService = new DocumentsService(
    new DocumentAuditService(appConfig),
    authz,
    cache,
    prisma,
  );
  watermarksService = new WatermarksService(prisma, auditWriter);
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

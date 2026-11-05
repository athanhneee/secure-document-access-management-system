/**
 * Module: Documents, Classification Lattice & Forensic Watermarks SQL Integration Fixture Builder
 * Algorithm: Provisions security lattice levels, ABAC clearance ranks, watermark templates, and
 *   service instances over an isolated PostgreSQL schema.
 */

/**
 * Thuật toán: Khởi tạo dữ liệu hạt giống SQL (dàn độ mật, ABAC `CLEARANCE_LEVEL`, cấu hình thủy vân) và các dịch vụ tài liệu/thủy vân cho kiểm thử tích hợp.
 */
export async function setupDocumentsWatermarksIntegrationFixture(dbHarness) {
  const { sql, insertOne, prisma } = dbHarness;
  const dept = await insertOne(
    "INSERT INTO departments(code,name) VALUES ('FIN_DOCS','Khối Tài chính Kế toán') RETURNING id",
  );
  const ownerUser = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('owner.docs','owner.docs@corp.local','hash','Chủ sở hữu Tài liệu',$1,'ACTIVE') RETURNING id`,
    [dept.id],
  );
  const lowClearedReader = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('reader.rank2','reader.rank2@corp.local','hash','Người đọc Mức 2',$1,'ACTIVE') RETURNING id`,
    [dept.id],
  );
  const secOfficer = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('sec.forensic','sec.forensic@corp.local','hash','Cán bộ An ninh',$1,'ACTIVE') RETURNING id`,
    [dept.id],
  );

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

  const levelInternal = await insertOne(
    `INSERT INTO classification_levels(code,name,rank,default_view_days,allow_download,require_watermark,is_active)
     VALUES ('INTERNAL','Nội bộ',2,14,true,true,true) RETURNING id`,
  );
  const levelTopSecret = await insertOne(
    `INSERT INTO classification_levels(code,name,rank,default_view_days,allow_download,require_watermark,is_active)
     VALUES ('TOP_SECRET','Tuyệt mật',4,1,false,true,true) RETURNING id`,
  );
  const categoryFinance = await insertOne(
    `INSERT INTO business_categories(code,name,department_id,is_active)
     VALUES ('FIN_REPORT','Báo cáo Tài chính',$1,true) RETURNING id`,
    [dept.id],
  );

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

  const wmConfig = await insertOne(
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
  const auditWriter = new AuditWriterService(appConfig, new AuditRedactionService(), prisma);

  return {
    classificationsService: new ClassificationsService(prisma),
    documentsService: new DocumentsService(
      new DocumentAuditService(appConfig),
      authz,
      cache,
      prisma,
    ),
    watermarksService: new WatermarksService(prisma, auditWriter),
    auditWriter,
    dept,
    ownerUser,
    lowClearedReader,
    secOfficer,
    levelInternal,
    levelTopSecret,
    categoryFinance,
    wmConfig,
  };
}

/**
 * Module: Access Workflow & Redlock Concurrency SQL Integration Fixture Builder
 * Algorithm: Simulates quorum Redis nodes with atomic CAS (`SET NX PX` + Lua `del`/`pexpire`)
 *   and provisions RBAC/ABAC/document SQL fixtures for concurrent approval and grant coalescing tests.
 */
import { randomUUID } from 'node:crypto';

/**
 * Thuật toán: Mô phỏng nút Redis trong bộ nhớ hỗ trợ khóa phân tán Redlock (`SET NX PX` và kịch bản Lua `del`/`pexpire` kiểm tra token).
 */
export function createInMemoryRedisNode() {
  const store = new Map();
  return {
    async set(key, token, ...args) {
      const pxIndex = args.findIndex((a) => String(a).toUpperCase() === 'PX');
      const ttlMs = pxIndex >= 0 ? Number(args[pxIndex + 1]) : 5000;
      const existing = store.get(key);
      const now = Date.now();
      if (existing && existing.expiresAt > now) return null;
      store.set(key, { token, expiresAt: now + ttlMs });
      return 'OK';
    },
    async eval(script, _numKeys, key, token, ttlMs) {
      const existing = store.get(key);
      if (!existing || existing.token !== token) return 0;
      if (script.includes('del')) return Number(store.delete(key));
      if (script.includes('pexpire')) {
        existing.expiresAt = Date.now() + Number(ttlMs);
        return 1;
      }
      return 0;
    },
    async ping() {
      return 'PONG';
    },
    async quit() {
      store.clear();
      return 'OK';
    },
    disconnect() {
      store.clear();
    },
  };
}

/**
 * Thuật toán: Khởi tạo dữ liệu hạt giống SQL (người dùng, quyền chia sẻ, bậc độ mật ABAC, tài liệu `ACTIVE`) và các dịch vụ phê duyệt truy cập có khóa Redlock.
 */
export async function setupAccessWorkflowIntegrationFixture(dbHarness) {
  const { sql, insertOne, prisma } = dbHarness;
  const dept = await insertOne(
    "INSERT INTO departments(code,name) VALUES ('OPS_WF','Khối Vận hành') RETURNING id",
  );
  const ownerUser = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('owner.wf','owner.wf@corp.local','hash','Chủ sở hữu',$1,'ACTIVE') RETURNING id`,
    [dept.id],
  );
  const readerUser = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('reader.wf','reader.wf@corp.local','hash','Chuyên viên Đọc',$1,'ACTIVE') RETURNING id`,
    [dept.id],
  );

  const ownerRole = await insertOne(
    "INSERT INTO roles(code,name,is_active,created_by) VALUES ('DOCUMENT_OWNER','Owner',true,$1) RETURNING id",
    [ownerUser.id],
  );
  const sharePerm = await insertOne(
    "INSERT INTO permissions(code,name,resource_type,action) VALUES ('DOC_SHARE_WF','Share','DOCUMENT','SHARE') RETURNING id",
  );
  await sql.query(
    'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3)',
    [ownerRole.id, sharePerm.id, ownerUser.id],
  );
  await sql.query(
    "INSERT INTO user_roles(user_id,role_id,valid_from,assigned_by) VALUES ($1,$2,now() - interval '1 hour',$1)",
    [ownerUser.id, ownerRole.id],
  );

  const classLevel = await insertOne(
    `INSERT INTO classification_levels(code,name,rank,default_view_days,allow_download,require_watermark,is_active)
     VALUES ('CONFIDENTIAL','Mật',2,7,true,true,true) RETURNING id`,
  );
  const category = await insertOne(
    "INSERT INTO business_categories(code,name,department_id,is_active) VALUES ('OPS_CAT','Vận hành',$1,true) RETURNING id",
    [dept.id],
  );
  const clearanceDef = await insertOne(
    "INSERT INTO attribute_definitions(code,name,scope,value_type,is_required,is_active,created_by) VALUES ('CLEARANCE_LEVEL','Clearance','USER','ENUM',true,true,$1) RETURNING id",
    [ownerUser.id],
  );
  const clearanceOpt = await insertOne(
    "INSERT INTO attribute_options(attribute_definition_id,value_code,display_name,numeric_rank,is_active) VALUES ($1,'SECRET','Rank 3',3,true) RETURNING id",
    [clearanceDef.id],
  );
  await sql.query(
    "INSERT INTO user_attribute_assignments(user_id,attribute_definition_id,option_id,valid_from,assigned_by) VALUES ($1,$2,$3,now() - interval '1 hour',$4)",
    [readerUser.id, clearanceDef.id, clearanceOpt.id, ownerUser.id],
  );

  const docId = randomUUID();
  await sql.query(
    `INSERT INTO documents(id,document_code,title,owner_id,department_id,status,discoverable)
     VALUES ($1,'DOC-WF-001','Quy trình Vận hành An toàn',$2,$3,'ACTIVE',true)`,
    [docId, ownerUser.id, dept.id],
  );
  const verRow = await insertOne(
    `INSERT INTO document_versions(document_id,version_no,storage_key,original_filename,mime_type,file_size_bytes,sha256_hash,encryption_key_ref,scan_status,uploaded_by)
     VALUES ($1,1,'vault/wf.enc','wf.pdf','application/pdf',1024,$2,'kms:dek:wf','CLEAN',$3) RETURNING id`,
    [docId, 'd'.repeat(64), ownerUser.id],
  );
  const versionId = verRow.id;
  await sql.query('UPDATE documents SET current_version_id=$1 WHERE id=$2', [versionId, docId]);
  await sql.query(
    "INSERT INTO document_classification_history(document_id,classification_level_id,business_category_id,classified_by,effective_from) VALUES ($1,$2,$3,$4,now() - interval '1 hour')",
    [docId, classLevel.id, category.id, ownerUser.id],
  );

  const { AppConfigService } = await import('../../dist/config/config.service.js');
  const { AuthorizationCache } = await import('../../dist/modules/rbac/authorization-cache.js');
  const { AuthorizationService } = await import('../../dist/modules/rbac/authorization.service.js');
  const { AuditRedactionService } =
    await import('../../dist/modules/audit/audit-redaction.service.js');
  const { AuditWriterService } = await import('../../dist/modules/audit/audit-writer.service.js');
  const { AccessGrantAuditService } =
    await import('../../dist/modules/access-grants/access-grant-audit.service.js');
  const { AccessGrantsService } =
    await import('../../dist/modules/access-grants/access-grants.service.js');
  const { AccessRequestsService } =
    await import('../../dist/modules/access-requests/access-requests.service.js');
  const { AccessSessionsService } =
    await import('../../dist/modules/access-sessions/access-sessions.service.js');
  const { NotificationsService } =
    await import('../../dist/modules/notifications/notifications.service.js');
  const { RedlockService } = await import('../../dist/modules/concurrency/redlock.service.js');

  const config = new AppConfigService({
    NODE_ENV: 'test',
    AUTH_AUDIT_HMAC_KEY: 'integration-wf-hmac-key-0123456789abcdef0123456789',
    GRANT_MAX_DURATION_DAYS: 90,
    REDLOCK_RETRY_COUNT: 15,
    REDLOCK_RETRY_DELAY_MS: 10,
    REDLOCK_RETRY_JITTER_MS: 4,
  });

  const redlockService = new RedlockService(config, [
    createInMemoryRedisNode(),
    createInMemoryRedisNode(),
    createInMemoryRedisNode(),
  ]);
  const cache = new AuthorizationCache();
  const authz = new AuthorizationService(cache);
  const auditWriter = new AuditWriterService(config, new AuditRedactionService(), prisma);
  const grantAudit = new AccessGrantAuditService(config);
  const notificationsService = new NotificationsService(prisma);

  const grantsService = new AccessGrantsService(
    grantAudit,
    authz,
    cache,
    { evaluate: async () => ({ decision: 'PERMIT', obligations: [] }) },
    config,
    prisma,
    redlockService,
    notificationsService,
  );

  return {
    requestsService: new AccessRequestsService(grantAudit, grantsService, prisma, redlockService),
    grantsService,
    sessionsService: new AccessSessionsService(prisma, auditWriter),
    notificationsService,
    redlockService,
    dept,
    ownerUser,
    readerUser,
    docId,
    versionId,
  };
}

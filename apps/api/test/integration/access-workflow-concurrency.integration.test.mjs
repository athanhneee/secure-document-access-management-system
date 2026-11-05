import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { BadRequestException } from '@nestjs/common';
import { AppErrorCode } from '@sda/contracts';
import { createEphemeralDatabaseHarness } from '../helpers/postgres-integration-harness.mjs';

const dbHarness = createEphemeralDatabaseHarness('sda_access_wf', { coerceBigIntId: true });
const ctx = { ip: '10.0.10.25', userAgent: 'integration-access', correlationId: randomUUID() };

let requestsService;
let grantsService;
let sessionsService;
let notificationsService;
let redlockService;
let dept;
let ownerUser;
let readerUser;
let docId;
let versionId;

function createInMemoryRedisNode() {
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

before(async () => {
  const ready = await dbHarness.setup();
  if (!ready) return;

  const { sql, insertOne, prisma } = dbHarness;
  dept = await insertOne(
    "INSERT INTO departments(code,name) VALUES ('OPS_WF','Khối Vận hành') RETURNING id",
  );
  ownerUser = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('owner.wf','owner.wf@corp.local','hash','Chủ sở hữu',$1,'ACTIVE') RETURNING id`,
    [dept.id],
  );
  readerUser = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('reader.wf','reader.wf@corp.local','hash','Chuyên viên Đọc',$1,'ACTIVE') RETURNING id`,
    [dept.id],
  );

  // Seed RBAC permissions & roles
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

  // Seed classification rank 2 & clearance rank 3 for readerUser
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

  // Seed an ACTIVE discoverable document + CLEAN version + active classification history
  docId = randomUUID();
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
  versionId = verRow.id;
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

  redlockService = new RedlockService(config, [
    createInMemoryRedisNode(),
    createInMemoryRedisNode(),
    createInMemoryRedisNode(),
  ]);
  const cache = new AuthorizationCache();
  const authz = new AuthorizationService(cache);
  const auditWriter = new AuditWriterService(config, new AuditRedactionService(), prisma);
  const grantAudit = new AccessGrantAuditService(config);
  notificationsService = new NotificationsService(prisma);

  grantsService = new AccessGrantsService(
    grantAudit,
    authz,
    cache,
    { evaluate: async () => ({ decision: 'PERMIT', obligations: [] }) },
    config,
    prisma,
    redlockService,
    notificationsService,
  );
  requestsService = new AccessRequestsService(grantAudit, grantsService, prisma, redlockService);
  sessionsService = new AccessSessionsService(prisma, auditWriter);
});

after(async () => {
  await redlockService?.onModuleDestroy();
  await dbHarness.teardown();
});

test('Access workflow SQL integration — request submission, Redlock-serialized approval, interval coalescing, session termination & notification outbox', async () => {
  const readerPrincipal = {
    userId: readerUser.id,
    sessionId: randomUUID(),
    username: 'reader.wf',
    roles: ['DOCUMENT_READER'],
    mfa: true,
  };
  const ownerPrincipal = {
    userId: ownerUser.id,
    sessionId: randomUUID(),
    username: 'owner.wf',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };

  const createdReq = await requestsService.createRequest(
    {
      documentId: docId,
      requestedAction: 'VIEW',
      reason: 'Cần nghiên cứu quy trình vận hành phục vụ đợt diễn tập an toàn Quý 4.',
      requestedUntil: new Date(Date.now() + 3 * 86_400_000).toISOString(),
    },
    readerPrincipal,
    ctx,
  );
  assert.equal(createdReq.status, 'PENDING');

  // Concurrent owner approvals serialized via Redlock + SQL transaction -> exactly one winner
  const settled = await Promise.allSettled([
    requestsService.decideRequest(
      createdReq.id,
      { decision: 'APPROVED', validDays: 5, decisionNote: 'Đồng ý cấp quyền đọc' },
      ownerPrincipal,
      ctx,
    ),
    requestsService.decideRequest(
      createdReq.id,
      { decision: 'APPROVED', validDays: 5, decisionNote: 'Đồng ý song song' },
      ownerPrincipal,
      ctx,
    ),
  ]);
  const reasons = settled
    .filter((r) => r.status === 'rejected')
    .map((r) => r.reason?.stack || r.reason?.message || String(r.reason));
  assert.equal(
    settled.filter((r) => r.status === 'fulfilled').length,
    1,
    `Expected 1 fulfilled decision, got rejections: ${reasons.join(' | ')}`,
  );
  assert.equal(settled.filter((r) => r.status === 'rejected').length, 1);

  // Verify ACCESS_GRANT_ISSUED notification & outbox persisted in SQL
  const issuedNotif = await dbHarness.sql.query(
    "SELECT count(*)::int AS cnt FROM notifications WHERE recipient_id=$1 AND notification_type='ACCESS_GRANT_ISSUED'",
    [readerUser.id],
  );
  assert.equal(issuedNotif.rows[0].cnt, 1);

  // Direct overlapping grant with same permission set coalesces into the single ACTIVE grant instead of duplicating
  const coalesced = await grantsService.createGrant(
    {
      documentId: docId,
      principalType: 'USER',
      principalUserId: readerUser.id,
      permissions: ['VIEW'],
      validUntil: new Date(Date.now() + 10 * 86_400_000).toISOString(),
    },
    ownerPrincipal,
    ctx,
  );
  const activeGrantsInSql = await dbHarness.sql.query(
    "SELECT count(*)::int AS cnt FROM access_grants WHERE document_id=$1 AND principal_user_id=$2 AND status='ACTIVE'",
    [docId, readerUser.id],
  );
  assert.equal(activeGrantsInSql.rows[0].cnt, 1);

  // Create two active sessions: terminate one manually via AccessSessionsService, cascade-terminate the other via revokeGrant
  const manualSessId = randomUUID();
  const cascadeSessId = randomUUID();
  await dbHarness.sql.query(
    `INSERT INTO access_sessions(id,access_grant_id,document_version_id,user_id,ip_address,status)
     VALUES ($1,$3,$4,$5,'10.0.10.50','ACTIVE'),($2,$3,$4,$5,'10.0.10.51','ACTIVE')`,
    [manualSessId, cascadeSessId, coalesced.id, versionId, readerUser.id],
  );

  // MEDIUM-04: invalid UUID throws 400 BadRequestException; valid termination writes audit log
  await assert.rejects(
    () => sessionsService.terminateSession('not-a-uuid', 'Bad ID', ownerPrincipal, ctx),
    BadRequestException,
  );
  const manualTerminated = await sessionsService.terminateSession(
    manualSessId,
    'Chấm dứt kiểm tra định kỳ',
    ownerPrincipal,
    ctx,
  );
  assert.equal(manualTerminated.status, 'TERMINATED');
  const terminatedListing = await sessionsService.listSessions({ status: 'TERMINATED' });
  assert.equal(terminatedListing.data[0].documentVersionId, String(versionId));

  // Revoke grant -> cascades to remaining active session and emits ACCESS_GRANT_REVOKED notification
  const revoked = await grantsService.revokeGrant(
    coalesced.id,
    { reason: 'Thu hồi sau khi kết thúc diễn tập' },
    ownerPrincipal,
    ctx,
  );
  assert.equal(revoked.status, 'REVOKED');

  const cascadeCheck = await dbHarness.sql.query(
    `SELECT
       (SELECT status::text FROM access_sessions WHERE id=$1) AS sess_status,
       (SELECT count(*)::int FROM notifications WHERE recipient_id=$2 AND notification_type='ACCESS_GRANT_REVOKED') AS revoke_notifs`,
    [cascadeSessId, readerUser.id],
  );
  assert.equal(cascadeCheck.rows[0].sess_status, 'TERMINATED');
  assert.equal(cascadeCheck.rows[0].revoke_notifs, 1);

  await assert.rejects(
    () =>
      grantsService.assertGrantValidForAccess(
        coalesced.id,
        readerUser.id,
        'VIEW',
        new Date(),
        docId,
      ),
    (err) => err.response?.errorCode === AppErrorCode.GRANT_REVOKED,
  );
});

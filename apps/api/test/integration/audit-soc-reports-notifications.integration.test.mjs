import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import { after, before, test } from 'node:test';
import { ForbiddenException } from '@nestjs/common';
import { createEphemeralDatabaseHarness } from '../helpers/postgres-integration-harness.mjs';

const dbHarness = createEphemeralDatabaseHarness('sda_audit_soc', { coerceBigIntId: true });
const HMAC_KEY = 'integration-audit-soc-hmac-key-0123456789abcdef012345';

let auditWriter;
let auditVerifier;
let auditService;
let detectionService;
let alertsService;
let incidentsService;
let exportJobService;
let notificationsService;
let deptAlpha;
let deptBeta;
let secUser;
let deptManagerAlpha;
const createdExportFiles = [];

before(async () => {
  const ready = await dbHarness.setup();
  if (!ready) return;

  const { sql, insertOne, prisma } = dbHarness;
  deptAlpha = await insertOne(
    "INSERT INTO departments(code,name) VALUES ('DEPT_ALPHA','Phòng Alpha') RETURNING id",
  );
  deptBeta = await insertOne(
    "INSERT INTO departments(code,name) VALUES ('DEPT_BETA','Phòng Beta') RETURNING id",
  );
  secUser = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('sec.officer','sec.officer@corp.local','hash','Sĩ quan An ninh',$1,'ACTIVE') RETURNING id`,
    [deptAlpha.id],
  );
  deptManagerAlpha = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('mgr.alpha','mgr.alpha@corp.local','hash','Trưởng phòng Alpha',$1,'ACTIVE') RETURNING id`,
    [deptAlpha.id],
  );
  const userBeta = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('staff.beta','staff.beta@corp.local','hash','Nhân viên Beta',$1,'ACTIVE') RETURNING id`,
    [deptBeta.id],
  );
  void userBeta;

  // Give deptManagerAlpha ONLY department-scoped AUDIT_LOG:EXPORT & AUDIT_LOG:READ on deptAlpha
  const mgrRole = await insertOne(
    "INSERT INTO roles(code,name,is_active,created_by) VALUES ('DEPT_AUDIT_MGR','Dept Audit Mgr',true,$1) RETURNING id",
    [secUser.id],
  );
  for (const action of ['READ', 'EXPORT']) {
    const p = await insertOne(
      'INSERT INTO permissions(code,name,resource_type,action) VALUES ($1,$1,$2,$3) RETURNING id',
      [`AUDIT_LOG_${action}_IT`, 'AUDIT_LOG', action],
    );
    await sql.query(
      'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3)',
      [mgrRole.id, p.id, secUser.id],
    );
  }
  await sql.query(
    "INSERT INTO user_roles(user_id,role_id,scope_department_id,valid_from,assigned_by) VALUES ($1,$2,$3,now() - interval '1 hour',$4)",
    [deptManagerAlpha.id, mgrRole.id, deptAlpha.id, secUser.id],
  );

  const { AppConfigService } = await import('../../dist/config/config.service.js');
  const { AuthorizationCache } = await import('../../dist/modules/rbac/authorization-cache.js');
  const { AuthorizationService } = await import('../../dist/modules/rbac/authorization.service.js');
  const { AuditRedactionService } =
    await import('../../dist/modules/audit/audit-redaction.service.js');
  const { AuditWriterService } = await import('../../dist/modules/audit/audit-writer.service.js');
  const { AuditVerifierService } =
    await import('../../dist/modules/audit/audit-verifier.service.js');
  const { AuditService } = await import('../../dist/modules/audit/audit.service.js');
  const { SecurityDetectionService } =
    await import('../../dist/modules/security-operations/security-detection.service.js');
  const { SecurityAlertsService } =
    await import('../../dist/modules/security-operations/security-alerts.service.js');
  const { IncidentsService } =
    await import('../../dist/modules/security-operations/incidents.service.js');
  const { ExportJobService } = await import('../../dist/modules/reports/export-job.service.js');
  const { NotificationsService } =
    await import('../../dist/modules/notifications/notifications.service.js');

  const config = new AppConfigService({ AUTH_AUDIT_HMAC_KEY: HMAC_KEY });
  const authz = new AuthorizationService(new AuthorizationCache());
  auditWriter = new AuditWriterService(config, new AuditRedactionService(), prisma);
  auditVerifier = new AuditVerifierService(auditWriter, prisma);
  auditService = new AuditService(auditWriter, auditVerifier, prisma);
  detectionService = new SecurityDetectionService(prisma, auditWriter);
  alertsService = new SecurityAlertsService(prisma, auditWriter);
  incidentsService = new IncidentsService(prisma, auditWriter);
  exportJobService = new ExportJobService(prisma, auditWriter, authz);
  notificationsService = new NotificationsService(prisma);
});

after(async () => {
  for (const p of createdExportFiles) {
    try {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    } catch {
      // ignore cleanup error
    }
  }
  await dbHarness.teardown();
});

test('Audit SQL integration — HMAC chain append, checkpoint anchor verification & SQL triggers blocking UPDATE/DELETE/TRUNCATE [HIGH-06]', async () => {
  const first = await auditWriter.writeLog({
    action: 'TEST_CHAIN_1',
    outcome: 'SUCCESS',
    objectType: 'DOCUMENT',
    objectId: 'doc-alpha-1',
    actorUserId: deptManagerAlpha.id,
    actorUsername: 'mgr.alpha',
    chainPartition: 'INTEGRATION_TEST',
  });
  const second = await auditWriter.writeLog({
    action: 'TEST_CHAIN_2',
    outcome: 'DENIED',
    objectType: 'DOCUMENT',
    objectId: 'doc-beta-2',
    actorUsername: 'staff.beta',
    reasonCode: 'INSUFFICIENT_CLEARANCE',
    chainPartition: 'INTEGRATION_TEST',
  });

  const anchorSig = createHmac('sha256', auditWriter.getHmacKey(1))
    .update(`INTEGRATION_TEST:${second.chain_sequence}:${second.entry_hash}`)
    .digest('hex');
  await dbHarness.sql.query(
    `INSERT INTO audit_anchors(chain_partition,anchor_sequence,entry_hash,signature,signer_key_id)
     VALUES ('INTEGRATION_TEST',$1,$2,$3,'audit-hmac-v1')`,
    [second.chain_sequence, second.entry_hash, anchorSig],
  );

  const verified = await auditVerifier.verifyPartition('INTEGRATION_TEST');
  assert.deepEqual(verified.violations, []);
  assert.equal(verified.valid, true);
  assert.equal(verified.totalChecked, 2);
  assert.equal(verified.anchorsChecked, 1);

  const listed = await auditService.queryAuditLogs(
    {
      userId: secUser.id,
      sessionId: randomUUID(),
      username: 'sec.officer',
      roles: ['SECURITY_OFFICER'],
      mfa: true,
    },
    {
      page: 1,
      pageSize: 20,
      sort: 'occurred_at',
      order: 'desc',
      action: 'TEST_CHAIN_1',
    },
  );
  assert.equal(listed.data.length, 1);
  assert.equal(listed.data[0].id, String(first.id));

  // Verify database triggers forbid UPDATE, DELETE, and TRUNCATE on audit_logs & audit_anchors
  await assert.rejects(
    dbHarness.sql.query("UPDATE audit_logs SET action='TAMPERED' WHERE id=$1", [first.id]),
    /immutable|append-only|prohibited/iu,
  );
  await assert.rejects(
    dbHarness.sql.query('DELETE FROM audit_logs WHERE id=$1', [first.id]),
    /immutable|append-only|prohibited/iu,
  );
  await assert.rejects(
    dbHarness.sql.query('TRUNCATE TABLE audit_logs'),
    /truncate|immutable|append-only|prohibited/iu,
  );
  await assert.rejects(
    dbHarness.sql.query('TRUNCATE TABLE audit_anchors'),
    /truncate|immutable|append-only|prohibited/iu,
  );
});

test('SOC, Reports & Notifications SQL integration — detection rules, alert/incident lifecycle, scoped export [HIGH-05] & idempotent notifications', async () => {
  const secPrincipal = {
    userId: secUser.id,
    sessionId: randomUUID(),
    username: 'sec.officer',
    roles: ['SECURITY_OFFICER'],
    mfa: true,
  };
  const mgrPrincipal = {
    userId: deptManagerAlpha.id,
    sessionId: randomUUID(),
    username: 'mgr.alpha',
    roles: [],
    mfa: true,
  };

  // 1. SOC detection rules + alert + incident full workflow
  const rules = await detectionService.getRules();
  assert.equal(rules.length, 6);

  const alertId = randomUUID();
  await dbHarness.sql.query(
    `INSERT INTO security_alerts(id,alert_type,severity,status,title,description,detected_user_id)
     VALUES ($1,'REPEATED_LOGIN_FAILURES','HIGH','OPEN','Đăng nhập thất bại liên tiếp','Phát hiện 6 lần sai mật khẩu',$2)`,
    [alertId, deptManagerAlpha.id],
  );
  const investigating = await alertsService.updateAlertStatus(
    alertId,
    { status: 'INVESTIGATING' },
    secPrincipal,
  );
  assert.equal(investigating.status, 'INVESTIGATING');

  const incident = await incidentsService.createIncidentReport(
    {
      alertId,
      title: 'Sự cố dò mật khẩu từ IP ngoại biên',
      summary: 'Xác minh nguồn tấn công từ 203.0.113.55 và khóa tạm thời phiên nghi vấn.',
      findings: 'Phát hiện 6 lần thử mật khẩu sai liên tiếp.',
    },
    secPrincipal,
  );
  assert.equal(incident.status, 'DRAFT');

  const action = await incidentsService.addIncidentAction(
    incident.id,
    {
      actionType: 'FIREWALL_BLOCK',
      recommendation: 'Chặn dải IP trên tường lửa biên và đặt lại phiên xác thực.',
    },
    secPrincipal,
  );
  await incidentsService.completeIncidentAction(
    BigInt(action.id),
    { completionNote: 'Đã cập nhật ACL tường lửa thành công.' },
    secPrincipal,
    incident.id,
  );
  const submitted = await incidentsService.submitIncidentReport(
    incident.id,
    { submittedToAdmin: secUser.id },
    secPrincipal,
  );
  assert.equal(submitted.status, 'SUBMITTED');
  const closed = await incidentsService.closeIncidentReport(
    incident.id,
    { closingNote: 'Sự cố đã được khắc phục triệt để.' },
    secPrincipal,
  );
  assert.equal(closed.status, 'CLOSED');

  const resolvedAlert = await alertsService.updateAlertStatus(
    alertId,
    { status: 'RESOLVED', resolutionNote: 'Đã đóng theo hồ sơ sự cố.' },
    secPrincipal,
  );
  assert.equal(resolvedAlert.status, 'RESOLVED');

  // 2. Reports [HIGH-05]: Department manager blocked from SECURITY_ALERTS export, and AUDIT_LOGS export scoped strictly to deptAlpha
  await assert.rejects(
    () =>
      exportJobService.createExportJob(
        { exportType: 'SECURITY_ALERTS', format: 'CSV' },
        mgrPrincipal,
      ),
    ForbiddenException,
  );

  const exportJob = await exportJobService.createExportJob(
    { exportType: 'AUDIT_LOGS', format: 'CSV' },
    mgrPrincipal,
  );
  // Wait briefly for async background export job completion
  let jobDetail = exportJob;
  for (
    let i = 0;
    i < 30 && jobDetail.status !== 'COMPLETED' && jobDetail.status !== 'FAILED';
    i++
  ) {
    await new Promise((r) => setTimeout(r, 25));
    jobDetail = await exportJobService.getExportJob(exportJob.id, mgrPrincipal);
  }
  assert.equal(jobDetail.status, 'COMPLETED');
  const downloaded = await exportJobService.downloadExportJob(exportJob.id, mgrPrincipal);
  const csvText = downloaded.buffer.toString('utf8');
  assert.match(csvText, /TEST_CHAIN_1/u, 'Department Alpha event must be included');
  assert.doesNotMatch(csvText, /TEST_CHAIN_2/u, 'Department Beta event must be excluded');
  const rawJob = await dbHarness.sql.query('SELECT file_path FROM async_export_jobs WHERE id=$1', [
    exportJob.id,
  ]);
  if (rawJob.rows[0]?.file_path) createdExportFiles.push(rawJob.rows[0].file_path);

  // 3. Notifications deduplication, unread listing & owner-scoped markAsRead
  const firstNotif = await notificationsService.sendNotification({
    recipientId: deptManagerAlpha.id,
    notificationType: 'SECURITY_DIGEST',
    title: 'Bản tin An ninh',
    body: 'Hoàn tất trích xuất báo cáo kiểm toán phòng Alpha.',
    deduplicationKey: 'digest:alpha:2026-11-05',
  });
  assert.equal(firstNotif.isDuplicate, false);
  assert.ok(firstNotif.notificationId);

  const duplicateNotif = await notificationsService.sendNotification({
    recipientId: deptManagerAlpha.id,
    notificationType: 'SECURITY_DIGEST',
    title: 'Bản tin An ninh',
    body: 'Bản gửi trùng.',
    channel: 'EMAIL',
    deduplicationKey: 'digest:alpha:2026-11-05',
  });
  assert.equal(duplicateNotif.isDuplicate, true);

  const unreadBefore = await notificationsService.listUserNotifications(deptManagerAlpha.id, {
    page: 1,
    pageSize: 20,
    status: 'UNREAD',
  });
  assert.equal(unreadBefore.data.length, 1);
  await notificationsService.markAsRead(firstNotif.notificationId, deptManagerAlpha.id);
  const unreadAfter = await notificationsService.listUserNotifications(deptManagerAlpha.id, {
    page: 1,
    pageSize: 20,
    status: 'UNREAD',
  });
  assert.equal(unreadAfter.data.length, 0);
});

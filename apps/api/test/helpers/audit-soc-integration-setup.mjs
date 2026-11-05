/**
 * Module: Audit, SOC, Reports & Notifications SQL Integration Fixture Builder
 * Algorithm: Provisions ephemeral departments, scoped RBAC audit manager roles, and real NestJS
 *   service instances backed by isolated PostgreSQL schemas.
 */

import assert from 'node:assert/strict';

export const AUDIT_SOC_HMAC_KEY = 'integration-audit-soc-hmac-key-0123456789abcdef012345';

/**
 * Thuật toán: Khởi tạo dữ liệu hạt giống SQL và lắp ghép các dịch vụ kiểm toán, SOC, xuất báo cáo và thông báo cho kiểm thử tích hợp.
 */
export async function setupAuditSocIntegrationFixture(dbHarness) {
  const { sql, insertOne, prisma } = dbHarness;
  const deptAlpha = await insertOne(
    "INSERT INTO departments(code,name) VALUES ('DEPT_ALPHA','Phòng Alpha') RETURNING id",
  );
  const deptBeta = await insertOne(
    "INSERT INTO departments(code,name) VALUES ('DEPT_BETA','Phòng Beta') RETURNING id",
  );
  const secUser = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('sec.officer','sec.officer@corp.local','hash','Sĩ quan An ninh',$1,'ACTIVE') RETURNING id`,
    [deptAlpha.id],
  );
  const deptManagerAlpha = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('mgr.alpha','mgr.alpha@corp.local','hash','Trưởng phòng Alpha',$1,'ACTIVE') RETURNING id`,
    [deptAlpha.id],
  );
  await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('staff.beta','staff.beta@corp.local','hash','Nhân viên Beta',$1,'ACTIVE') RETURNING id`,
    [deptBeta.id],
  );

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

  const config = new AppConfigService({ AUTH_AUDIT_HMAC_KEY: AUDIT_SOC_HMAC_KEY });
  const authz = new AuthorizationService(new AuthorizationCache());
  const auditWriter = new AuditWriterService(config, new AuditRedactionService(), prisma);
  const auditVerifier = new AuditVerifierService(auditWriter, prisma);

  return {
    auditWriter,
    auditVerifier,
    auditService: new AuditService(auditWriter, auditVerifier, prisma),
    detectionService: new SecurityDetectionService(prisma, auditWriter),
    alertsService: new SecurityAlertsService(prisma, auditWriter),
    incidentsService: new IncidentsService(prisma, auditWriter),
    exportJobService: new ExportJobService(prisma, auditWriter, authz),
    notificationsService: new NotificationsService(prisma),
    deptAlpha,
    deptBeta,
    secUser,
    deptManagerAlpha,
  };
}

/**
 * Thuật toán: Chờ bất đồng bộ có giới hạn số vòng lặp cho đến khi tác vụ xuất báo cáo chuyển sang `COMPLETED`/`FAILED` và thu thập đường dẫn tệp tạm để dọn dẹp.
 */
export async function waitForExportJobCompletion(
  exportJobService,
  dbHarness,
  jobId,
  principal,
  createdExportFiles,
) {
  let jobDetail = await exportJobService.getExportJob(jobId, principal);
  for (
    let i = 0;
    i < 30 && jobDetail.status !== 'COMPLETED' && jobDetail.status !== 'FAILED';
    i++
  ) {
    await new Promise((r) => setTimeout(r, 25));
    jobDetail = await exportJobService.getExportJob(jobId, principal);
  }
  const rawJob = await dbHarness.sql.query('SELECT file_path FROM async_export_jobs WHERE id=$1', [
    jobId,
  ]);
  if (rawJob.rows[0]?.file_path) createdExportFiles.push(rawJob.rows[0].file_path);
  return jobDetail;
}

/**
 * Thuật toán: Xác minh các trigger bất biến SQL chặn mọi lệnh `UPDATE`, `DELETE` và `TRUNCATE` trên `audit_logs` và `audit_anchors`.
 */
export async function assertAuditImmutabilityTriggers(dbHarness, firstLogId) {
  await assert.rejects(
    dbHarness.sql.query("UPDATE audit_logs SET action='TAMPERED' WHERE id=$1", [firstLogId]),
    /immutable|append-only|prohibited/iu,
  );
  await assert.rejects(
    dbHarness.sql.query('DELETE FROM audit_logs WHERE id=$1', [firstLogId]),
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
}

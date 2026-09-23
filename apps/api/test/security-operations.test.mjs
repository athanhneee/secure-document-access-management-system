import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';

// ── Contract & DTO Tests ─────────────────────────────────────────────────────

import {
  UpdateAlertStatusSchema,
  CreateIncidentReportSchema,
  CompleteIncidentActionSchema,
  AppErrorCode,
} from '@sda/contracts';

// ── Service & Logic Imports ──────────────────────────────────────────────────

import { SecurityDetectionService } from '../dist/modules/security-operations/security-detection.service.js';
import { SecurityAlertsService } from '../dist/modules/security-operations/security-alerts.service.js';
import { IncidentsService } from '../dist/modules/security-operations/incidents.service.js';
import { sanitizeCsvCell, sanitizeCsvRow } from '../dist/modules/reports/csv-formula-sanitizer.js';
import { ExportJobService } from '../dist/modules/reports/export-job.service.js';
import { NotificationsService } from '../dist/modules/notifications/notifications.service.js';
import { HealthService } from '../dist/modules/system-health/health.service.js';

// ── 1. Schema Validation Tests ───────────────────────────────────────────────

test('UpdateAlertStatusSchema — requires resolutionNote when transitioning to RESOLVED or FALSE_POSITIVE', () => {
  const validResolved = UpdateAlertStatusSchema.safeParse({
    status: 'RESOLVED',
    resolutionNote: 'Investigated and verified legitimate batch job.',
  });
  assert.ok(validResolved.success);

  const validFalsePositive = UpdateAlertStatusSchema.safeParse({
    status: 'FALSE_POSITIVE',
    resolutionNote: 'Authorized pen-test drill activity.',
  });
  assert.ok(validFalsePositive.success);

  const missingNoteResolved = UpdateAlertStatusSchema.safeParse({
    status: 'RESOLVED',
    resolutionNote: '',
  });
  assert.ok(!missingNoteResolved.success, 'Should reject empty resolutionNote for RESOLVED');

  const missingNoteFp = UpdateAlertStatusSchema.safeParse({
    status: 'FALSE_POSITIVE',
  });
  assert.ok(!missingNoteFp.success, 'Should reject missing resolutionNote for FALSE_POSITIVE');

  const validInvestigating = UpdateAlertStatusSchema.safeParse({
    status: 'INVESTIGATING',
  });
  assert.ok(validInvestigating.success, 'INVESTIGATING does not require resolutionNote');
});

test('CreateIncidentReportSchema — validates required fields and title length', () => {
  const valid = CreateIncidentReportSchema.safeParse({
    alertId: randomUUID(),
    title: 'Suspicious mass download from department A',
    summary: 'Detected 20 downloads in 3 minutes.',
    findings: 'Credentials likely leaked through phishing.',
    impactAssessment: 'High confidentiality breach risk.',
  });
  assert.ok(valid.success);

  const shortTitle = CreateIncidentReportSchema.safeParse({
    title: 'Hi',
    summary: 'Summary text',
    findings: 'Findings text',
  });
  assert.ok(!shortTitle.success, 'Should reject title shorter than 5 chars');
});

test('CompleteIncidentActionSchema — requires non-empty completionNote', () => {
  const valid = CompleteIncidentActionSchema.safeParse({
    completionNote: 'User credentials revoked and session terminated.',
  });
  assert.ok(valid.success);

  const empty = CompleteIncidentActionSchema.safeParse({
    completionNote: '   ',
  });
  assert.ok(!empty.success, 'Should reject whitespace completionNote');
});

// ── 2. CSV Formula Injection Escaping ─────────────────────────────────────────

test('CSV Formula Sanitizer [SECURITY] — escapes dangerous formula prefixes (=, +, -, @, \\t, \\r)', () => {
  const dangerousCells = [
    '=CMD|"/C calc"!A0',
    '+123456',
    '-5+5',
    '@SUM(A1:A10)',
    '\t=1+1',
    '\r=HYPERLINK("http://attacker.com")',
  ];

  for (const cell of dangerousCells) {
    const sanitized = sanitizeCsvCell(cell);
    assert.ok(
      sanitized.startsWith("'"),
      `Cell "${cell}" must be prefixed with single quote, got "${sanitized}"`,
    );
  }

  // Safe strings should remain untouched
  const safeCells = ['Normal User Name', 'DOCUMENT_VIEWED', '12345', 'info@example.com'];
  for (const cell of safeCells) {
    assert.equal(sanitizeCsvCell(cell), cell);
  }

  // Test row sanitization
  const row = ['=2+2', 'normal', '@hack'];
  const sanitizedRow = sanitizeCsvRow(row);
  assert.equal(sanitizedRow[0], "'=2+2");
  assert.equal(sanitizedRow[1], 'normal');
  assert.equal(sanitizedRow[2], "'@hack");
});

// ── 3. Rule-based Detection & Alert-Storm Suppression (Cooldown) ─────────────

test('SecurityDetectionService — creates 1 alert and suppresses duplicates within cooldown', async () => {
  const alertsTable = [];
  const linksTable = [];
  const now = new Date('2026-09-23T10:00:00Z');
  const actorUserId = 100n;

  // Mock 6 download logs within 10-minute window (threshold is 5)
  const mockAuditLogs = Array.from({ length: 6 }, (_, i) => ({
    id: BigInt(i + 1),
    actor_user_id: actorUserId,
    document_id: randomUUID(),
    action: 'DOCUMENT_DOWNLOADED',
    outcome: 'SUCCESS',
    occurred_at: new Date(now.getTime() - (i + 1) * 60 * 1000),
  }));

  const mockDb = {
    detectionRuleConfig: {
      findMany: async () => [
        {
          rule_code: 'MASS_DOWNLOAD',
          name: 'Mass Download Rule',
          is_enabled: true,
          severity: 'HIGH',
          threshold: 5,
          window_minutes: 10,
          cooldown_minutes: 30,
          parameters: {},
        },
      ],
    },
    auditLog: {
      findMany: async () => mockAuditLogs,
    },
    securityAlert: {
      findFirst: async ({ where }) => {
        // Find existing alert within cooldown
        return alertsTable.find(
          (a) =>
            a.alert_type === where.alert_type &&
            a.detected_user_id === where.detected_user_id &&
            a.detected_at >= where.detected_at.gte,
        );
      },
      create: async ({ data }) => {
        alertsTable.push(data);
        return data;
      },
    },
    alertAuditLink: {
      createMany: async ({ data }) => {
        linksTable.push(...data);
        return { count: data.length };
      },
    },
    $transaction: async (fn) => fn(mockDb),
  };

  const detectionService = new SecurityDetectionService(mockDb);

  // First detection run: should trigger 1 alert
  const run1 = await detectionService.runAllDetections(10);
  const newAlerts1 = run1.filter((r) => r.isNewAlert);
  assert.equal(newAlerts1.length, 1);
  assert.equal(alertsTable.length, 1);
  assert.equal(alertsTable[0].alert_type, 'MASS_DOWNLOAD');
  assert.equal(alertsTable[0].detected_user_id, actorUserId);
  assert.equal(linksTable.length, 6, 'All 6 audit logs must be linked');

  // Second detection run immediately after (within 30m cooldown): should be SUPPRESSED
  const run2 = await detectionService.runAllDetections(10);
  const suppressed2 = run2.filter((r) => r.suppressedByCooldown);
  const newAlerts2 = run2.filter((r) => r.isNewAlert);
  assert.equal(suppressed2.length, 1, 'Must suppress duplicate alert within cooldown');
  assert.equal(newAlerts2.length, 0, 'No new alerts should be created');
  assert.equal(alertsTable.length, 1, 'Total alerts must remain 1');
});

// ── 4. Alert State Transitions & Resolution Note Enforcement ──────────────────

test('SecurityAlertsService — enforces valid transitions and requires resolution note', async () => {
  const alertId = randomUUID();
  let currentAlert = {
    id: alertId,
    alert_type: 'MASS_DOWNLOAD',
    severity: 'HIGH',
    status: 'OPEN',
    title: 'Mass download',
    description: 'Test',
    detected_user_id: 10n,
    document_id: null,
    detected_at: new Date(),
    assigned_to: null,
    resolved_at: null,
    resolution_note: null,
    users_security_alerts_detected_user_idTousers: null,
    users_security_alerts_assigned_toTousers: null,
    alert_audit_links: [],
    incident_reports: [],
  };

  const mockDb = {
    securityAlert: {
      findUnique: async () => currentAlert,
      update: async ({ data }) => {
        currentAlert = { ...currentAlert, ...data };
        return currentAlert;
      },
    },
  };

  const alertService = new SecurityAlertsService(mockDb);
  const secOfficer = { userId: 50n, username: 'sec_officer', roles: ['SECURITY_OFFICER'] };

  // 1. OPEN -> INVESTIGATING: valid
  const updated1 = await alertService.updateAlertStatus(
    alertId,
    { status: 'INVESTIGATING' },
    secOfficer,
  );
  assert.equal(updated1.status, 'INVESTIGATING');

  // 2. INVESTIGATING -> RESOLVED WITHOUT note: must throw RESOLUTION_NOTE_REQUIRED
  await assert.rejects(
    async () => {
      await alertService.updateAlertStatus(alertId, { status: 'RESOLVED' }, secOfficer);
    },
    (err) => {
      const resp = typeof err.getResponse === 'function' ? err.getResponse() : err.response;
      assert.equal(resp?.errorCode, AppErrorCode.RESOLUTION_NOTE_REQUIRED);
      return true;
    },
  );

  // 3. INVESTIGATING -> RESOLVED WITH note: valid
  const updated2 = await alertService.updateAlertStatus(
    alertId,
    { status: 'RESOLVED', resolutionNote: 'Root cause resolved. Account secured.' },
    secOfficer,
  );
  assert.equal(updated2.status, 'RESOLVED');
  assert.ok(updated2.resolvedAt !== null);
  assert.equal(updated2.resolutionNote, 'Root cause resolved. Account secured.');

  // 4. RESOLVED -> OPEN: invalid transition
  await assert.rejects(
    async () => {
      await alertService.updateAlertStatus(alertId, { status: 'OPEN' }, secOfficer);
    },
    (err) => {
      const resp = typeof err.getResponse === 'function' ? err.getResponse() : err.response;
      assert.equal(resp?.errorCode, AppErrorCode.ALERT_INVALID_TRANSITION);
      return true;
    },
  );
});

// ── 5. Auditor SoD Matrix (Mutation Forbidden) ───────────────────────────────

test('IncidentsService [SoD] — blocks AUDITOR role from creating or mutating incidents', async () => {
  const mockDb = {
    incidentReport: {
      create: async () => ({ id: randomUUID() }),
    },
  };

  const incidentsService = new IncidentsService(mockDb);
  const auditorUser = {
    userId: 99n,
    username: 'auditor_bob',
    roles: ['AUDITOR'], // Strictly read/audit only
  };

  // Auditor attempting to create incident report must be blocked
  await assert.rejects(
    async () => {
      await incidentsService.createIncidentReport(
        {
          title: 'Incident from auditor',
          summary: 'Auditor found suspicious activity',
          findings: 'Details',
        },
        auditorUser,
      );
    },
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.AUDITOR_CANNOT_MUTATE_INCIDENTS);
      return true;
    },
  );

  // Auditor attempting to update or submit incident must also be blocked
  await assert.rejects(
    async () => {
      await incidentsService.submitIncidentReport(randomUUID(), {}, auditorUser);
    },
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.AUDITOR_CANNOT_MUTATE_INCIDENTS);
      return true;
    },
  );
});

// ── 6. Async Report Export TTL & Authorization ───────────────────────────────

test('ExportJobService — validates TTL and restricts download to requester or authorized roles', async () => {
  const requesterId = 101n;
  const otherUserId = 202n;
  const expiredJobId = randomUUID();
  const validJobId = randomUUID();
  const now = new Date();

  const jobs = new Map([
    [
      expiredJobId,
      {
        id: expiredJobId,
        requester_user_id: requesterId,
        export_type: 'AUDIT_LOGS',
        format: 'CSV',
        status: 'COMPLETED',
        file_path: 'C:/temp/export.csv',
        file_size_bytes: 1024n,
        sha256_hash: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        mime_type: 'text/csv',
        row_count: 50,
        error_message: null,
        created_at: new Date(now.getTime() - 25 * 3600 * 1000),
        completed_at: new Date(now.getTime() - 24 * 3600 * 1000),
        expires_at: new Date(now.getTime() - 1 * 3600 * 1000), // Expired 1h ago
      },
    ],
    [
      validJobId,
      {
        id: validJobId,
        requester_user_id: requesterId,
        export_type: 'INCIDENT_SUMMARY',
        format: 'PDF',
        status: 'COMPLETED',
        file_path: 'C:/temp/incident.pdf',
        file_size_bytes: 2048n,
        sha256_hash: '123456abcdef123456abcdef123456abcdef123456abcdef123456abcdef123456',
        mime_type: 'application/pdf',
        row_count: 1,
        error_message: null,
        created_at: now,
        completed_at: now,
        expires_at: new Date(now.getTime() + 24 * 3600 * 1000), // Valid for 24h
      },
    ],
  ]);

  const mockDb = {
    asyncExportJob: {
      findUnique: async ({ where }) => jobs.get(where.id) ?? null,
    },
  };

  const exportService = new ExportJobService(mockDb);
  exportService['memoryStorage'].set(validJobId, Buffer.from('mock pdf content'));

  // 1. Downloading expired job throws EXPORT_JOB_EXPIRED
  await assert.rejects(
    async () => {
      await exportService.downloadExportJob(expiredJobId, {
        userId: requesterId,
        username: 'user1',
        roles: ['USER'],
      });
    },
    (err) => {
      const resp = typeof err.getResponse === 'function' ? err.getResponse() : err.response;
      assert.equal(resp?.errorCode, AppErrorCode.EXPORT_JOB_EXPIRED);
      return true;
    },
  );

  // 2. Unauthorized user downloading another user's export throws EXPORT_UNAUTHORIZED
  await assert.rejects(
    async () => {
      await exportService.downloadExportJob(validJobId, {
        userId: otherUserId,
        username: 'user2',
        roles: ['USER'],
      });
    },
    (err) => {
      const resp = typeof err.getResponse === 'function' ? err.getResponse() : err.response;
      assert.equal(resp?.errorCode, AppErrorCode.EXPORT_UNAUTHORIZED);
      return true;
    },
  );

  // 3. Authorized requester downloading valid export succeeds
  const downloadInfo = await exportService.downloadExportJob(validJobId, {
    userId: requesterId,
    username: 'user1',
    roles: ['USER'],
  });
  assert.equal(downloadInfo.mimeType, 'application/pdf');
  assert.ok(downloadInfo.buffer.length > 0);
});

// ── 7. Notification Outbox Deduplication & Retry Backoff ─────────────────────

test('NotificationsService — deduplicates outbox entries with identical deduplication key', async () => {
  const outboxMap = new Map();
  const notificationsList = [];

  const mockDb = {
    notification: {
      create: async ({ data }) => {
        notificationsList.push(data);
        return data;
      },
    },
    notificationOutbox: {
      findUnique: async ({ where }) => outboxMap.get(where.deduplication_key) ?? null,
      create: async ({ data }) => {
        outboxMap.set(data.deduplication_key, data);
        return data;
      },
    },
  };

  const service = new NotificationsService(mockDb);

  // First send: should queue outbox entry
  const res1 = await service.sendNotification({
    recipientId: 456n,
    notificationType: 'SECURITY_ALERT',
    title: 'Suspicious login',
    body: 'Detected unrecognized IP',
    deduplicationKey: 'ALERT:MASS_DOWNLOAD:USER_456',
  });
  assert.equal(res1.isDuplicate, false);
  assert.ok(res1.outboxId);

  // Second send with same dedup key: should be suppressed
  const res2 = await service.sendNotification({
    recipientId: 456n,
    notificationType: 'SECURITY_ALERT',
    title: 'Suspicious login',
    body: 'Detected unrecognized IP',
    deduplicationKey: 'ALERT:MASS_DOWNLOAD:USER_456',
  });
  assert.equal(
    res2.isDuplicate,
    true,
    'Second notification with identical key must be deduplicated',
  );
  assert.equal(outboxMap.size, 1, 'Only one outbox entry must be created');
});

// ── 8. System Health Metrics Separation ──────────────────────────────────────

test('HealthService — reads live operational metrics without replacing with business snapshots', async () => {
  const mockConfig = {
    get: (key) => {
      if (key === 'DATABASE_URL') return 'postgresql://localhost:5432/test?schema=public';
      if (key === 'REDIS_URL') return 'redis://127.0.0.1:6379';
      if (key === 'STORAGE_ENDPOINT') return '127.0.0.1';
      if (key === 'STORAGE_PORT') return '9000';
      return '';
    },
  };

  const healthService = new HealthService(mockConfig);

  // Live operational metrics read directly from runtime & counters
  const metrics = await healthService.getLiveMetrics();
  assert.ok(metrics.timestamp);
  assert.ok(metrics.process.uptimeSeconds >= 0);
  assert.ok(metrics.process.heapUsedMb > 0);
  assert.ok(metrics.operational.openAlertsCount >= 0);

  // Business snapshot is stored separately in historical table
  const snapshot = await healthService.captureBusinessSnapshot('SECURE_CORE', 'HEALTHY', {
    activeUsersCount: 150,
    openAlertsCount: 3,
  });
  assert.ok(snapshot === null || snapshot.id);
});

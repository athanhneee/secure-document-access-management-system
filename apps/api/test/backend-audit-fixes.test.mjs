import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { UnauthorizedException, NotFoundException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { PUBLIC_ENDPOINT_METADATA } from '../dist/public-endpoint.js';
import { ClassificationsService } from '../dist/modules/classifications/classifications.service.js';
import { AccessSessionsService } from '../dist/modules/access-sessions/access-sessions.service.js';
import { AccessSessionsController } from '../dist/modules/access-sessions/access-sessions.controller.js';
import { AuditService } from '../dist/modules/audit/audit.service.js';
import { DocumentsController } from '../dist/modules/documents/documents.controller.js';
import { SecurityOperationsController } from '../dist/modules/security-operations/security-operations.controller.js';
import { ReportsController } from '../dist/modules/reports/reports.controller.js';
import { NotificationsController } from '../dist/modules/notifications/notifications.controller.js';

// ── 1. ClassificationsService Tests ──────────────────────────────────────────

test('ClassificationsService — listClassificationLevels queries active levels and maps fields', async () => {
  const mockLevels = [
    {
      id: 1n,
      code: 'UNCLASSIFIED',
      name: 'Unclassified',
      rank: 1,
      description: 'Public domain',
      default_view_days: 30,
      allow_download: true,
      require_watermark: false,
      is_active: true,
    },
    {
      id: 2n,
      code: 'SECRET',
      name: 'Secret',
      rank: 4,
      description: 'Strict security',
      default_view_days: 7,
      allow_download: false,
      require_watermark: true,
      is_active: true,
    },
  ];

  const mockDb = {
    classificationLevel: {
      findMany: async ({ where, orderBy }) => {
        assert.equal(where.is_active, true);
        assert.equal(orderBy.rank, 'asc');
        return mockLevels;
      },
    },
  };

  const service = new ClassificationsService(mockDb);
  const result = await service.listClassificationLevels();

  assert.equal(result.data.length, 2);
  assert.deepEqual(result.data[0], {
    id: 1,
    code: 'UNCLASSIFIED',
    name: 'Unclassified',
    rank: 1,
    description: 'Public domain',
    defaultViewDays: 30,
    allowDownload: true,
    requireWatermark: false,
    isActive: true,
  });
  assert.equal(result.data[1].code, 'SECRET');
  assert.equal(result.data[1].allowDownload, false);
  assert.equal(result.data[1].requireWatermark, true);
});

test('ClassificationsService — listBusinessCategories queries active categories with department', async () => {
  const mockCategories = [
    {
      id: 10n,
      code: 'FINANCE',
      name: 'Financial Reports',
      department_id: 100n,
      description: 'Quarterly financial audits',
      is_active: true,
      departments: {
        id: 100n,
        code: 'FIN_DEPT',
        name: 'Finance Department',
      },
    },
  ];

  const mockDb = {
    businessCategory: {
      findMany: async ({ where, orderBy, include }) => {
        assert.equal(where.is_active, true);
        assert.equal(orderBy.code, 'asc');
        assert.ok(include.departments);
        return mockCategories;
      },
    },
  };

  const service = new ClassificationsService(mockDb);
  const result = await service.listBusinessCategories();

  assert.equal(result.data.length, 1);
  assert.deepEqual(result.data[0], {
    id: 10,
    code: 'FINANCE',
    name: 'Financial Reports',
    departmentId: 100,
    departmentName: 'Finance Department',
    description: 'Quarterly financial audits',
    isActive: true,
  });
});

// ── 2. AccessSessionsService & Controller Tests ───────────────────────────────

test('AccessSessionsService — listSessions retrieves active sessions with document and user relations', async () => {
  const sessionId = randomUUID();
  const grantId = randomUUID();
  const docId = randomUUID();
  const now = new Date();

  const mockSessions = [
    {
      id: sessionId,
      access_grant_id: grantId,
      document_version_id: 5n,
      user_id: 42n,
      ip_address: '192.168.1.100',
      user_agent: 'Mozilla/5.0 TestBrowser',
      device_fingerprint: 'fp-123',
      status: 'ACTIVE',
      started_at: now,
      last_activity_at: now,
      ended_at: null,
      terminated_reason: null,
      users: { id: 42n, username: 'alice', full_name: 'Alice Reader' },
      document_versions: {
        id: 5n,
        version_no: 2,
        document: { id: docId, document_code: 'DOC-001', title: 'Top Secret Plans' },
      },
    },
  ];

  const mockDb = {
    accessSession: {
      findMany: async ({ where, take, orderBy }) => {
        assert.equal(where.status, 'ACTIVE');
        assert.equal(take, 50);
        assert.equal(orderBy.started_at, 'desc');
        return mockSessions;
      },
    },
  };

  const service = new AccessSessionsService(mockDb);
  const result = await service.listSessions({ status: 'ACTIVE' });

  assert.equal(result.data.length, 1);
  assert.equal(result.data[0].id, sessionId);
  assert.equal(result.data[0].userId, 42);
  assert.equal(result.data[0].username, 'alice');
  assert.equal(result.data[0].documentCode, 'DOC-001');
  assert.equal(result.data[0].documentTitle, 'Top Secret Plans');
  assert.equal(result.data[0].status, 'ACTIVE');
});

test('AccessSessionsService — terminateSession terminates active session and updates record', async () => {
  const sessionId = randomUUID();
  let sessionRecord = {
    id: sessionId,
    status: 'ACTIVE',
    ended_at: null,
    terminated_reason: null,
  };

  const mockDb = {
    accessSession: {
      findUnique: async ({ where }) => {
        if (where.id === sessionId) return sessionRecord;
        return null;
      },
      update: async ({ data }) => {
        sessionRecord = { ...sessionRecord, ...data };
        return sessionRecord;
      },
    },
  };

  const service = new AccessSessionsService(mockDb);

  // Non-existent session throws NotFoundException
  await assert.rejects(
    () => service.terminateSession(randomUUID(), 'Test reason'),
    (err) => err instanceof NotFoundException,
  );

  // Active session terminates cleanly
  const result = await service.terminateSession(sessionId, 'Security concern');
  assert.equal(result.id, sessionId);
  assert.equal(result.status, 'TERMINATED');
  assert.equal(sessionRecord.status, 'TERMINATED');
  assert.equal(sessionRecord.terminated_reason, 'Security concern');
  assert.ok(sessionRecord.ended_at instanceof Date);

  // Calling terminate again on already terminated session is idempotent
  const idempotentResult = await service.terminateSession(sessionId, 'Repeat');
  assert.equal(idempotentResult.status, 'TERMINATED');
});

test('AccessSessionsController — requires CSRF on terminateSession and 401 when unauthenticated', async () => {
  let csrfChecked = false;
  const mockCsrf = {
    assertRequest: () => {
      csrfChecked = true;
    },
  };

  const mockService = {
    listSessions: async () => ({ data: [] }),
    terminateSession: async (id) => ({ id, status: 'TERMINATED' }),
  };

  const controller = new AccessSessionsController(mockService, mockCsrf);

  // Unauthenticated listSessions throws UnauthorizedException (401)
  await assert.rejects(
    () => controller.listSessions({ auth: null }),
    (err) => err instanceof UnauthorizedException,
  );

  // Unauthenticated terminateSession throws UnauthorizedException (401)
  await assert.rejects(
    () => controller.terminateSession('s-1', { auth: null }),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfChecked, true, 'CSRF assertion must be called before authentication check');
});

// ── 3. AuditService CSV Formula Injection Defense (CWE-1236) ──────────────────

test('AuditService — exportAuditLogs sanitizes CSV formula injection prefixes (=, +, -, @, \\t, \\r)', async () => {
  const dangerousLogs = [
    {
      id: 101n,
      occurred_at: new Date('2026-09-24T00:00:00Z'),
      actor_user_id: 1n,
      actor_username: "=cmd|' /C calc'!A0",
      action: '+ADMIN_ACTION',
      object_type: '-CRITICAL_OBJECT',
      object_id: '@EVIL_FORMULA',
      document_id: 'doc-uuid-1',
      access_session_id: 'session-uuid-1',
      outcome: 'DENY',
      reason_code: '\tTAB_PREFIX_INJECTION',
      ip_address: '10.0.0.1',
      correlation_id: 'corr-1',
      chain_partition: 'DOC:doc-uuid-1',
      chain_sequence: 1n,
      entry_hash: 'hash-abc',
    },
  ];

  const mockDb = {
    auditLog: {
      findMany: async () => dangerousLogs,
    },
  };

  const service = new AuditService(null, null, mockDb);
  const principal = { userId: 99n, username: 'audit_officer', roles: ['AUDITOR'] };

  const result = await service.exportAuditLogs(principal, {
    format: 'CSV',
    limit: 10,
  });

  assert.equal(result.format, 'CSV');
  const lines = result.data.split('\r\n');
  assert.equal(lines.length, 2, 'Header line + 1 data line');

  const dataLine = lines[1];
  // Verify every formula prefix is neutralized by a prepended single quote (')
  assert.ok(dataLine.includes("'=cmd|"), "Prefix '=' must be escaped with single quote");
  assert.ok(dataLine.includes("'+ADMIN_ACTION"), "Prefix '+' must be escaped with single quote");
  assert.ok(dataLine.includes("'-CRITICAL_OBJECT"), "Prefix '-' must be escaped with single quote");
  assert.ok(dataLine.includes("'@EVIL_FORMULA"), "Prefix '@' must be escaped with single quote");
  assert.ok(
    dataLine.includes("'\tTAB_PREFIX_INJECTION"),
    "Prefix '\\t' must be escaped with single quote",
  );
});

// ── 4. PublicEndpoint and CSRF Verification on Controllers ────────────────────

test('DocumentsController — downloadWithTicket is marked @PublicEndpoint() for one-time ticket redemption', () => {
  const reflector = new Reflector();
  const isPublic = reflector.get(
    PUBLIC_ENDPOINT_METADATA,
    DocumentsController.prototype.downloadWithTicket,
  );
  assert.equal(isPublic, true, 'downloadWithTicket must have @PublicEndpoint() metadata');
});

test('DocumentsController — checkRetention enforces CSRF protection', async () => {
  let csrfChecked = false;
  const mockCsrf = {
    assertRequest: () => {
      csrfChecked = true;
    },
  };
  const mockDocsService = {
    checkRetentionWarnings: async () => ({ checked: 10 }),
  };

  const controller = new DocumentsController(mockDocsService, null, null, mockCsrf);

  await controller.checkRetention({});
  assert.equal(csrfChecked, true, 'checkRetention must assert CSRF token');
});

test('SecurityOperationsController — mutation endpoints enforce CSRF and throw UnauthorizedException when unauthenticated', async () => {
  let csrfCheckCount = 0;
  const mockCsrf = {
    assertRequest: () => {
      csrfCheckCount++;
    },
  };

  const controller = new SecurityOperationsController(null, null, null, mockCsrf);

  const unauthReq = { auth: null };

  // 1. updateAlertStatus
  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.updateAlertStatus('alt-1', { status: 'INVESTIGATING' }, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  // 2. assignAlert
  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.assignAlert('alt-1', { assignedToUserId: '50' }, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  // 3. addAlertNote
  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.addAlertNote('alt-1', { note: 'test' }, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  // 4. createIncident
  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.createIncident({}, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  // 5. submitIncident
  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.submitIncident('inc-1', {}, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  // 6. closeIncident
  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.closeIncident('inc-1', {}, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  // 7. addIncidentAction
  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.addIncidentAction('inc-1', {}, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  // 8. completeIncidentAction
  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.completeIncidentAction('123', {}, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  // 9. updateDetectionRule
  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.updateDetectionRule('MASS_DOWNLOAD', {}, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  // 10. runDetection
  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.runDetection({}, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);
});

test('ReportsController & NotificationsController — mutation endpoints assert CSRF and throw UnauthorizedException', async () => {
  let reportsCsrf = false;
  const mockReportsCsrf = {
    assertRequest: () => {
      reportsCsrf = true;
    },
  };
  const reportsController = new ReportsController(null, mockReportsCsrf);

  await assert.rejects(
    () => reportsController.createExportJob({}, { auth: null }),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(reportsCsrf, true, 'createExportJob must assert CSRF');

  let notificationsCsrf = false;
  const mockNotificationsCsrf = {
    assertRequest: () => {
      notificationsCsrf = true;
    },
  };
  const notificationsController = new NotificationsController(null, mockNotificationsCsrf);

  await assert.rejects(
    () => notificationsController.markAsRead('notif-1', { auth: null }),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(notificationsCsrf, true, 'markAsRead must assert CSRF');
});

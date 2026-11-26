import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import {
  AppErrorCode,
  ListAccessSessionsSchema,
  UpdateAlertStatusSchema,
  isOffHoursTimestampUtc,
  resolveMinClassificationRank,
} from '@sda/contracts';
import { AccessSessionsService } from '../dist/modules/access-sessions/access-sessions.service.js';
import { listPartitionAnchors } from '../dist/modules/audit/audit-anchor.helper.js';
import { executeGetWebAuthnAuthOptions } from '../dist/modules/auth/auth-webauthn.helper.js';
import { executeCheckRetentionWarnings } from '../dist/modules/documents/document-retention.helper.js';
import { finalizePermittedAccessSession } from '../dist/modules/documents/pep-obligations.helper.js';
import {
  RealtimeEventsController,
  isAllowedSseOrigin,
} from '../dist/modules/realtime/realtime-events.controller.js';
import { RealtimeEventsService } from '../dist/modules/realtime/realtime-events.service.js';
import { DlpStatusService } from '../dist/modules/security-operations/dlp-status.service.js';
import { splitIncidentSummaryAndClosingNote } from '../dist/modules/security-operations/incident-mapper.js';
import {
  executeCloseIncidentReport,
  executeReviewIncidentReport,
  executeSubmitIncidentReport,
} from '../dist/modules/security-operations/incident-transitions.helper.js';
import {
  extractAlertSourceIp,
  parseAlertDescriptionAndNotes,
} from '../dist/modules/security-operations/security-alerts.helper.js';
import { SecurityAlertsService } from '../dist/modules/security-operations/security-alerts.service.js';
import { SecurityDetectionService } from '../dist/modules/security-operations/security-detection.service.js';
import { HealthController } from '../dist/modules/system-health/health.controller.js';

const SOC_ACTOR = {
  userId: 50n,
  username: 'qa.security',
  roles: ['SECURITY_OFFICER'],
};

const READER_ACTOR = {
  userId: 60n,
  username: 'qa.reader',
  roles: ['DOCUMENT_READER'],
};

test('N01 [SECURITY] — SSE stream enforces case-insensitive Origin allowlist, rejects evil Origin before hijack, and sends OWASP headers', async () => {
  assert.equal(isAllowedSseOrigin('http://localhost:3000', ['http://localhost:3000']), true);
  assert.equal(isAllowedSseOrigin('HTTP://LOCALHOST:3000', ['http://localhost:3000']), true);
  assert.equal(
    isAllowedSseOrigin('https://evil.attacker.example', ['http://localhost:3000']),
    false,
  );
  assert.equal(isAllowedSseOrigin('*', ['*']), false);

  const realtime = new RealtimeEventsService();
  const controller = new RealtimeEventsController(realtime, {
    corsOrigins: ['http://localhost:3000'],
    isProduction: true,
  });

  let hijacked = false;
  const evilReply = {
    hijack: () => {
      hijacked = true;
    },
    raw: {},
  };

  await assert.rejects(
    async () => {
      await controller.stream(
        {
          auth: SOC_ACTOR,
          headers: { origin: 'https://evil.attacker.example' },
          raw: {},
        },
        evilReply,
      );
    },
    (err) => err?.status === 403,
  );
  assert.equal(hijacked, false, 'Must reject disallowed Origin BEFORE calling reply.hijack()');

  let writtenHeaders = null;
  const closeHandlers = [];
  const goodReply = {
    hijack: () => {
      hijacked = true;
    },
    raw: {
      writeHead: (_status, headers) => {
        writtenHeaders = headers;
      },
      flushHeaders: () => {},
      write: () => true,
      end: () => {},
      once: () => {},
    },
  };
  await controller.stream(
    {
      auth: SOC_ACTOR,
      headers: { origin: 'http://localhost:3000' },
      correlationId: 'corr-sse-1',
      raw: {
        setTimeout: () => {},
        socket: { setTimeout: () => {}, setKeepAlive: () => {} },
        once: (ev, cb) => {
          if (ev === 'close') closeHandlers.push(cb);
        },
        on: (ev, cb) => {
          if (ev === 'close') closeHandlers.push(cb);
        },
      },
    },
    goodReply,
  );

  assert.equal(hijacked, true);
  assert.equal(writtenHeaders['Access-Control-Allow-Origin'], 'http://localhost:3000');
  assert.equal(writtenHeaders['Access-Control-Allow-Credentials'], 'true');
  assert.equal(writtenHeaders['Cross-Origin-Opener-Policy'], 'same-origin');
  assert.equal(writtenHeaders['Cross-Origin-Resource-Policy'], 'same-origin');
  assert.equal(writtenHeaders['Permissions-Policy'], 'camera=(), microphone=(), geolocation=()');
  assert.equal(writtenHeaders['Strict-Transport-Security'], 'max-age=31536000; includeSubDomains');
  for (const cb of closeHandlers) cb();
});

test('#01/#02/#03/#09 — parseAlertDescriptionAndNotes preserves [Network DLP]/[BLOCKED] tags while extracting ISO notes and atomic status+note update works', async () => {
  const rawDescription =
    '[Network DLP] [BLOCKED] Phát hiện rò rỉ dữ liệu nhạy cảm từ nguồn 10.20.30.40\n' +
    '[2026-11-14T15:32:07.619Z] qa.security: Đang điều tra máy trạm nguồn\n' +
    '[2026-11-14T16:00:00.000Z] qa.security: Đã cô lập phiên đọc';

  const parsed = parseAlertDescriptionAndNotes(rawDescription, 'alert-1');
  assert.equal(
    parsed.baseDescription,
    '[Network DLP] [BLOCKED] Phát hiện rò rỉ dữ liệu nhạy cảm từ nguồn 10.20.30.40',
  );
  assert.equal(parsed.notes.length, 2);
  assert.equal(parsed.notes[0].authorName, 'qa.security');
  assert.equal(parsed.notes[0].note, 'Đang điều tra máy trạm nguồn');
  assert.equal(parsed.notes[1].note, 'Đã cô lập phiên đọc');

  assert.equal(
    extractAlertSourceIp([{ audit_logs: { ip_address: '192.168.10.5' } }], parsed.baseDescription),
    '192.168.10.5',
  );
  assert.equal(extractAlertSourceIp([], parsed.baseDescription), '10.20.30.40');

  // Verify UpdateAlertStatusSchema supports atomic investigationNote
  const parsedDto = UpdateAlertStatusSchema.safeParse({
    status: 'INVESTIGATING',
    investigationNote: 'Tiếp nhận điều tra khẩn cấp',
  });
  assert.equal(parsedDto.success, true);

  const alertId = randomUUID();
  let alertRow = {
    id: alertId,
    alert_type: 'MASS_DOWNLOAD',
    severity: 'HIGH',
    status: 'OPEN',
    title: 'Mass download',
    description: 'User downloaded 12 files',
    detected_user_id: 10n,
    document_id: null,
    detected_at: new Date('2026-11-25T08:00:00Z'),
    assigned_to: null,
    resolved_at: null,
    resolution_note: null,
    users_security_alerts_detected_user_idTousers: null,
    users_security_alerts_assigned_toTousers: null,
    alert_audit_links: [{ audit_logs: { ip_address: '10.0.0.42' } }],
    _count: { alert_audit_links: 1 },
  };
  let updateCount = 0;
  const mockDb = {
    securityAlert: {
      findUnique: async () => alertRow,
      findMany: async () => [alertRow],
      count: async () => 1,
      update: async ({ data }) => {
        updateCount += 1;
        alertRow = { ...alertRow, ...data };
        return alertRow;
      },
    },
  };

  const alertsService = new SecurityAlertsService(mockDb);
  const updated = await alertsService.updateAlertStatus(
    alertId,
    { status: 'INVESTIGATING', investigationNote: 'Đã tiếp nhận và khóa tải xuống' },
    SOC_ACTOR,
  );
  assert.equal(updateCount, 1, 'Status + investigationNote must persist in a single atomic update');
  assert.equal(updated.status, 'INVESTIGATING');
  assert.equal(updated.notes.length, 1);
  assert.equal(updated.notes[0].note, 'Đã tiếp nhận và khóa tải xuống');
  assert.equal(updated.ipAddress, '10.0.0.42');

  const listed = await alertsService.listAlerts(
    { page: 1, pageSize: 20, search: 'Mass' },
    SOC_ACTOR,
  );
  assert.equal(listed.total, 1);
  assert.equal(listed.meta.total, 1);
  assert.equal(listed.data[0].ipAddress, '10.0.0.42');
  assert.equal(listed.data[0].notes.length, 1);
});

test('#06 — DlpStatusService probes real Worker ICAP status fail-closed across OFFLINE, DISABLED, AUDIT_ONLY, and BLOCK modes', async () => {
  const mockDb = {
    securityAlert: {
      count: async ({ where }) => (where?.status ? 2 : 5),
    },
  };
  const service = new DlpStatusService(mockDb);

  // 1. Worker unreachable -> OFFLINE fail-closed
  const offlineRes = await service.getNetworkDlpStatus(SOC_ACTOR, async () => {
    throw new Error('ECONNREFUSED');
  });
  assert.equal(offlineRes.gatewayHealth, 'OFFLINE');
  assert.equal(offlineRes.workerReachable, false);
  assert.equal(offlineRes.enforcementMode, 'OFFLINE');
  assert.equal(offlineRes.totalDlpAlerts, 5);
  assert.equal(offlineRes.openDlpAlerts, 2);

  // 2. ICAP disabled -> OFFLINE + DISABLED
  const disabledRes = await service.getNetworkDlpStatus(SOC_ACTOR, async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      status: 'ok',
      workerLoopAlive: true,
      icap: { enabled: false, listening: false, action: 'BLOCK' },
    }),
  }));
  assert.equal(disabledRes.gatewayHealth, 'OFFLINE');
  assert.equal(disabledRes.workerReachable, true);
  assert.equal(disabledRes.enforcementMode, 'DISABLED');

  // 3. ICAP listening in AUDIT_ONLY -> ONLINE + AUDIT_ONLY
  const auditOnlyRes = await service.getNetworkDlpStatus(SOC_ACTOR, async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      status: 'ok',
      workerLoopAlive: true,
      icap: { enabled: true, listening: true, action: 'AUDIT_ONLY' },
    }),
  }));
  assert.equal(auditOnlyRes.gatewayHealth, 'ONLINE');
  assert.equal(auditOnlyRes.icapListening, true);
  assert.equal(auditOnlyRes.enforcementMode, 'AUDIT_ONLY');

  // 4. ICAP listening in BLOCK -> ONLINE + BLOCK
  const blockRes = await service.getNetworkDlpStatus(SOC_ACTOR, async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      status: 'ok',
      workerLoopAlive: true,
      icap: { enabled: true, listening: true, action: 'BLOCK' },
    }),
  }));
  assert.equal(blockRes.gatewayHealth, 'ONLINE');
  assert.equal(blockRes.enforcementMode, 'BLOCK');
});

test('N04/N08/N10/N11 — Detection rules lock AUDIT_INTEGRITY_COMPROMISED, honor ruleCodes filter, use ICT UTC+7 off-hours, and emit PEP untrustedContext', async () => {
  // N10: ICT UTC+7 weekend & weekday check
  const ictParams = { workStartHour: 7, workEndHour: 19, timezoneOffsetMinutes: 420 };
  // Sunday 2026-11-29 19:00 UTC == Monday 2026-11-30 02:00 ICT (weekday off-hours)
  assert.equal(isOffHoursTimestampUtc(new Date('2026-11-29T19:00:00Z'), ictParams), true);
  // Sunday 2026-11-29 03:00 UTC == Sunday 2026-11-29 10:00 ICT (weekend -> off-hours!)
  assert.equal(isOffHoursTimestampUtc(new Date('2026-11-29T03:00:00Z'), ictParams), true);
  // Friday 2026-11-27 17:30 UTC == Saturday 2026-11-28 00:30 ICT (weekend -> off-hours!)
  assert.equal(isOffHoursTimestampUtc(new Date('2026-11-27T17:30:00Z'), ictParams), true);
  // Monday 2026-11-30 03:00 UTC == Monday 2026-11-30 10:00 ICT (business hours -> NOT off-hours)
  assert.equal(isOffHoursTimestampUtc(new Date('2026-11-30T03:00:00Z'), ictParams), false);
  assert.equal(resolveMinClassificationRank({ minClassificationRank: 3 }), 3);
  assert.equal(resolveMinClassificationRank({}), 2);

  // N04: Mandatory AUDIT_INTEGRITY_COMPROMISED cannot be disabled
  const mockRuleDb = {
    detectionRuleConfig: {
      findMany: async () => [],
      findUnique: async () => null,
      upsert: async ({ create }) => create,
    },
    auditLog: {
      findMany: async () => [],
    },
  };
  const detectionService = new SecurityDetectionService(mockRuleDb);
  await assert.rejects(
    async () => {
      await detectionService.updateRule(
        'AUDIT_INTEGRITY_COMPROMISED',
        { isEnabled: false },
        SOC_ACTOR,
      );
    },
    (err) => err?.status === 400,
  );

  // N08: runAllDetections honors ruleCodes filter (only queries requested rule)
  const queriedActions = [];
  const filterDb = {
    detectionRuleConfig: {
      findMany: async () => [],
    },
    auditLog: {
      findMany: async ({ where }) => {
        queriedActions.push(where.action);
        return [];
      },
    },
  };
  const filteredService = new SecurityDetectionService(filterDb);
  await filteredService.runAllDetections(undefined, ['MASS_DOWNLOAD']);
  assert.equal(queriedActions.length, 1, 'Should only run the single requested MASS_DOWNLOAD rule');

  // N11: PEP obligations emit untrustedIp / untrustedDevice / untrustedContext in ACCESS_PERMITTED audit log
  const recordedAudits = [];
  await finalizePermittedAccessSession({
    database: {
      accessSession: {
        create: async () => ({ id: 'sess-untrusted-1' }),
      },
    },
    audit: {
      record: async (entry) => {
        recordedAudits.push(entry);
      },
    },
    stateStore: {
      putEphemeral: async () => {},
    },
    documentId: 'doc-1',
    effectiveGrantId: 'grant-1',
    documentVersionId: 1n,
    versionNo: 1,
    action: 'VIEW',
    deviceFingerprint: undefined,
    now: new Date('2026-11-25T08:00:00Z'),
    principal: { ...READER_ACTOR, mfa: true },
    context: { ip: '203.0.113.99', userAgent: 'TestBrowser', correlationId: 'corr-1' },
    policyOutcome: {
      forbidDownloadObligation: false,
      watermarkRequired: true,
      maxSessionMinutes: 30,
      expiresAtMs: Date.now() + 1_800_000,
      obligationTypes: ['WATERMARK_REQUIRED'],
      riskScore: 75,
      riskFactors: ['UNTRUSTED_DEVICE'],
      trustedNetwork: false,
    },
  });
  assert.equal(recordedAudits.length, 1);
  assert.equal(recordedAudits[0].details.untrustedIp, true);
  assert.equal(recordedAudits[0].details.untrustedDevice, true);
  assert.equal(recordedAudits[0].details.untrustedContext, true);
});

test('N04 — executeCheckRetentionWarnings deduplicates existing OPEN RETENTION_OVERDUE alerts', async () => {
  const existingAlertDocIds = new Set();
  let createdAlerts = 0;
  const mockDb = {
    document: {
      findMany: async () => [
        {
          id: 'doc-overdue-1',
          document_code: 'DOC-900',
          title: 'Hồ sơ quá hạn',
          owner_id: 10n,
          department_id: 1n,
          retention_until: new Date('2025-01-01T00:00:00Z'),
          users: { id: 10n, username: 'owner1' },
        },
      ],
    },
    securityAlert: {
      findMany: async () =>
        existingAlertDocIds.size > 0
          ? [...existingAlertDocIds].map((docId) => ({ document_id: docId }))
          : [],
      createMany: async ({ data }) => {
        for (const row of data) {
          createdAlerts += 1;
          if (row.document_id) existingAlertDocIds.add(row.document_id);
        }
        return { count: data.length };
      },
      create: async ({ data }) => {
        createdAlerts += 1;
        if (data.document_id) existingAlertDocIds.add(data.document_id);
        return data;
      },
    },
    notification: {
      findMany: async () => [],
      createMany: async ({ data }) => ({ count: data.length }),
      create: async () => ({ id: 'notif-1' }),
    },
  };
  const mockAudit = { record: async () => {} };

  await executeCheckRetentionWarnings({
    database: mockDb,
    authorization: {},
    audit: mockAudit,
    daysThreshold: 30,
    systemScan: true,
  });
  await executeCheckRetentionWarnings({
    database: mockDb,
    authorization: {},
    audit: mockAudit,
    daysThreshold: 30,
    systemScan: true,
  });
  assert.equal(createdAlerts, 1, 'Second retention sweep must not create duplicate OPEN alert');
});

test('N13/#15/#18/#19 — Incident FSM supports SUBMITTED -> IN_REVIEW -> CLOSED, blocks uncompleted actions unless forceClose, splits closingNote cleanly, and verifies submit recipients', async () => {
  const incId = randomUUID();
  let row = {
    id: incId,
    incident_code: 'INC-2026-TEST01',
    status: 'DRAFT',
    summary: 'Tóm tắt sự cố gốc',
  };
  let incompleteActions = 1;

  const mockDb = {
    user: {
      findUnique: async ({ where }) => (where.id === 999n ? null : { id: where.id }),
    },
    incidentReport: {
      findUnique: async () => row,
      update: async ({ data }) => {
        row = { ...row, ...data };
        return row;
      },
    },
    incidentAction: {
      count: async () => incompleteActions,
    },
  };

  // Non-existent owner recipient rejected with 404
  await assert.rejects(
    async () => {
      await executeSubmitIncidentReport(
        mockDb,
        undefined,
        incId,
        { submittedToOwner: 999n },
        SOC_ACTOR,
      );
    },
    (err) => err?.status === 404,
  );

  // Submit valid -> SUBMITTED
  await executeSubmitIncidentReport(mockDb, undefined, incId, { submittedToOwner: 2n }, SOC_ACTOR);
  assert.equal(row.status, 'SUBMITTED');

  // Review -> IN_REVIEW (#18)
  await executeReviewIncidentReport(mockDb, undefined, incId, SOC_ACTOR);
  assert.equal(row.status, 'IN_REVIEW');

  // Close blocked while incompleteActions > 0 without forceClose (#15)
  await assert.rejects(
    async () => {
      await executeCloseIncidentReport(
        mockDb,
        undefined,
        incId,
        { closingNote: 'Đóng sớm' },
        SOC_ACTOR,
      );
    },
    (err) => {
      const resp = typeof err.getResponse === 'function' ? err.getResponse() : err.response;
      assert.equal(resp?.errorCode, AppErrorCode.INCIDENT_INVALID_TRANSITION);
      return err?.status === 400;
    },
  );

  // Force close with valid closingNote succeeds
  await executeCloseIncidentReport(
    mockDb,
    undefined,
    incId,
    { forceClose: true, closingNote: 'Đã thống nhất đóng ngoại lệ cùng Ban an ninh' },
    SOC_ACTOR,
  );
  assert.equal(row.status, 'CLOSED');

  // splitIncidentSummaryAndClosingNote keeps summary clean and exposes closingNote (#19)
  const split = splitIncidentSummaryAndClosingNote(row.summary);
  assert.equal(split.cleanSummary, 'Tóm tắt sự cố gốc');
  assert.equal(split.closingNote, 'Đã thống nhất đóng ngoại lệ cùng Ban an ninh');
});

test('#12/#20 — AccessSessionsService supports ALL/ACTIVE/ENDED/TERMINATED statuses, rejects legacy REVOKED, and returns activeCount + total', async () => {
  assert.equal(ListAccessSessionsSchema.safeParse({ status: 'ALL' }).success, true);
  assert.equal(ListAccessSessionsSchema.safeParse({ status: 'ENDED' }).success, true);
  assert.equal(ListAccessSessionsSchema.safeParse({ status: 'TERMINATED' }).success, true);
  assert.equal(ListAccessSessionsSchema.safeParse({ status: 'REVOKED' }).success, false);
  assert.equal(ListAccessSessionsSchema.safeParse({ status: 'COMPLETED' }).success, false);

  const mockDb = {
    accessSession: {
      findMany: async () => [
        {
          id: 'sess-1',
          access_grant_id: 'grant-1',
          document_version_id: 1n,
          user_id: 10n,
          status: 'ACTIVE',
          ip_address: '10.0.0.1',
          user_agent: 'Chrome',
          started_at: new Date('2026-11-25T08:00:00Z'),
          last_activity_at: new Date('2026-11-25T08:05:00Z'),
          ended_at: null,
          terminated_by: null,
          termination_reason: null,
          users: {
            id: 10n,
            username: 'athanhnee',
            full_name: 'Anh Thành',
          },
          document_versions: {
            id: 1n,
            version_no: 1,
            document: { id: 'doc-1', document_code: 'DOC-1', title: 'Tài liệu Mật' },
          },
        },
      ],
      count: async ({ where }) => (where?.status === 'ACTIVE' ? 1 : 17),
    },
  };
  const service = new AccessSessionsService(mockDb);
  const res = await service.listSessions(
    { status: 'ALL', page: 1, limit: 20, search: 'DOC-1' },
    SOC_ACTOR,
  );
  assert.equal(res.total, 17);
  assert.equal(res.activeCount, 1);
  assert.equal(res.meta.total, 17);
  assert.equal(res.data.length, 1);
});

test('#04/N05/N12 — listPartitionAnchors enforces role SoD, WebAuthn options blocks unauthenticated user enumeration, and /health/metrics rejects public IP', async () => {
  const anchorDb = {
    auditAnchor: {
      findMany: async () => [
        {
          id: 1n,
          chain_partition: 'SECURITY_OPERATIONS',
          anchor_sequence: 42n,
          entry_hash: 'a'.repeat(64),
          signature: 'b'.repeat(64),
          signer_key_id: 'hmac-key-v1',
          status: 'VALID',
          anchored_at: new Date('2026-11-25T08:00:00Z'),
        },
      ],
    },
  };
  const anchorsRes = await listPartitionAnchors(anchorDb, SOC_ACTOR);
  assert.equal(anchorsRes.data.length, 1);
  assert.equal(anchorsRes.data[0].chainPartition, 'SECURITY_OPERATIONS');

  await assert.rejects(
    async () => {
      await listPartitionAnchors(anchorDb, READER_ACTOR);
    },
    (err) => err?.status === 403,
  );

  // N05: Passkey Enumeration Oracle closed — unauthenticated principal rejected
  await assert.rejects(
    async () => {
      await executeGetWebAuthnAuthOptions({}, undefined, 'qa.security', {
        ip: '127.0.0.1',
        userAgent: 'Burp',
      });
    },
    (err) => err?.status === 401,
  );

  // N12: /health/metrics blocks non-private IP in non-test environments when METRICS_SCRAPE_TOKEN is unset
  const prevNodeEnv = process.env['NODE_ENV'];
  const prevScrape = process.env['METRICS_SCRAPE_TOKEN'];
  process.env['NODE_ENV'] = 'development';
  delete process.env['METRICS_SCRAPE_TOKEN'];
  try {
    const healthController = new HealthController(
      {
        getLiveMetrics: async () => ({
          operational: { activeSessionsCount: 0, pendingExportsCount: 0 },
        }),
      },
      {
        setActiveSessions: () => {},
        setQueueDepth: () => {},
        exportPrometheusText: () => '# metrics',
      },
      { assertRequest: () => {} },
      { get: () => undefined, isProduction: false },
    );
    await assert.rejects(
      async () => {
        await healthController.getMetrics({
          headers: {},
          ip: '203.0.113.55',
          socket: { remoteAddress: '203.0.113.55' },
        });
      },
      (err) => err?.status === 403,
    );
  } finally {
    if (prevNodeEnv === undefined) delete process.env['NODE_ENV'];
    else process.env['NODE_ENV'] = prevNodeEnv;
    if (prevScrape !== undefined) process.env['METRICS_SCRAPE_TOKEN'] = prevScrape;
  }
});

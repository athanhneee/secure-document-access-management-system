import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runAuditVerificationSweep } from '../dist/audit-verification-job.js';
import { emitPerUserThresholdAlerts } from '../dist/detection/alert-correlators.js';
import { evaluateDetectionRule } from '../dist/detection/rule-evaluators.js';
import { IcapServer } from '../dist/icap/icap-server.js';
import { startWorkerHealthServer } from '../dist/worker-health-server.js';

test('N09 — Worker emitPerUserThresholdAlerts suppresses cooldown ONLY on OPEN/INVESTIGATING, links new audit logs during cooldown, and persists document_id', async () => {
  const existingAlerts = [];
  const linkedPairs = [];

  const mockTx = {
    securityAlert: {
      create: async ({ data }) => {
        existingAlerts.push(data);
        return data;
      },
    },
    alertAuditLink: {
      createMany: async ({ data }) => {
        for (const item of data) linkedPairs.push(item);
        return { count: data.length };
      },
    },
  };

  const mockDb = {
    $transaction: async (fn) => fn(mockTx),
    securityAlert: {
      findFirst: async ({ where }) => {
        assert.deepEqual(
          where.status,
          { in: ['OPEN', 'INVESTIGATING'] },
          'Cooldown filter must match API (OPEN or INVESTIGATING only)',
        );
        return (
          existingAlerts.find(
            (a) =>
              a.alert_type === where.alert_type &&
              a.detected_user_id === where.detected_user_id &&
              where.status.in.includes(a.status),
          ) ?? null
        );
      },
    },
    alertAuditLink: mockTx.alertAuditLink,
  };

  const rule = {
    ruleCode: 'OFF_HOURS_ACCESS',
    threshold: 1,
    windowMinutes: 60,
    cooldownMinutes: 30,
    severity: 'MEDIUM',
    parameters: {},
  };
  const now = new Date('2026-11-29T03:10:00Z');
  const cooldownStart = new Date('2026-11-29T02:40:00Z');

  // First alert created with document_id
  const firstCount = await emitPerUserThresholdAlerts(
    mockDb,
    rule,
    [{ id: 101n, actor_user_id: 10n, document_id: 'doc-secret-1', occurred_at: now }],
    now,
    cooldownStart,
    () => ({ title: 'Truy cập ngoài giờ', description: 'Test off-hours' }),
  );
  assert.equal(firstCount, 1);
  assert.equal(existingAlerts.length, 1);
  assert.equal(existingAlerts[0].document_id, 'doc-secret-1');
  assert.equal(linkedPairs.length, 1);

  // Second occurrence within cooldown -> suppressed, BUT still links new audit log 102n
  const secondCount = await emitPerUserThresholdAlerts(
    mockDb,
    rule,
    [{ id: 102n, actor_user_id: 10n, document_id: 'doc-secret-1', occurred_at: now }],
    now,
    cooldownStart,
    () => ({ title: 'Truy cập ngoài giờ', description: 'Test off-hours 2' }),
  );
  assert.equal(secondCount, 0);
  assert.equal(existingAlerts.length, 1);
  assert.equal(
    linkedPairs.length,
    2,
    'New audit log must be attached to existing alert during cooldown',
  );

  // Once resolved, subsequent anomaly must create a NEW alert
  existingAlerts[0].status = 'RESOLVED';
  const thirdCount = await emitPerUserThresholdAlerts(
    mockDb,
    rule,
    [{ id: 103n, actor_user_id: 10n, document_id: 'doc-secret-1', occurred_at: now }],
    now,
    cooldownStart,
    () => ({ title: 'Truy cập ngoài giờ sau khi đóng', description: 'Test off-hours 3' }),
  );
  assert.equal(thirdCount, 1, 'Must NOT suppress new alert after prior alert was RESOLVED');
  assert.equal(existingAlerts.length, 2);
});

test('N10 — Worker evaluateDetectionRule (OFF_HOURS_ACCESS) respects minClassificationRank and propagates document_id', async () => {
  const createdAlerts = [];
  const offHoursSundayUtc = new Date('2026-11-29T03:00:00Z'); // Sunday 10:00 ICT -> weekend off-hours

  const mockTx = {
    securityAlert: {
      create: async ({ data }) => {
        createdAlerts.push(data);
        return data;
      },
    },
    alertAuditLink: {
      create: async () => ({}),
      createMany: async () => ({ count: 1 }),
    },
  };

  const mockDb = {
    $transaction: async (fn) => fn(mockTx),
    auditLog: {
      findMany: async () => [
        {
          id: 201n,
          actor_user_id: 11n,
          document_id: 'doc-internal',
          occurred_at: offHoursSundayUtc,
          documents: {
            classification_history: [{ classification_levels: { rank: 1 } }],
          },
        },
        {
          id: 202n,
          actor_user_id: 12n,
          document_id: 'doc-confidential',
          occurred_at: offHoursSundayUtc,
          documents: {
            classification_history: [{ classification_levels: { rank: 2 } }],
          },
        },
      ],
    },
    securityAlert: {
      findFirst: async () => null,
    },
    alertAuditLink: mockTx.alertAuditLink,
  };

  const alertsCreated = await evaluateDetectionRule(
    mockDb,
    {
      ruleCode: 'OFF_HOURS_ACCESS',
      threshold: 1,
      windowMinutes: 60,
      cooldownMinutes: 30,
      severity: 'MEDIUM',
      parameters: {
        workStartHour: 7,
        workEndHour: 19,
        timezoneOffsetMinutes: 420,
        minClassificationRank: 2,
      },
    },
    new Date('2026-11-29T03:05:00Z'),
    new Date('2026-11-29T02:05:00Z'),
    new Date('2026-11-29T02:35:00Z'),
  );

  assert.equal(
    alertsCreated,
    1,
    'INTERNAL doc (rank 1) must be skipped; CONFIDENTIAL (rank 2) triggers',
  );
  assert.equal(createdAlerts.length, 1);
  assert.equal(createdAlerts[0].detected_user_id, 12n);
  assert.equal(createdAlerts[0].document_id, 'doc-confidential');
});

test('N04 — Worker audit verification job reads severity and cooldown_minutes from detection_rule_configs', async () => {
  const createdAlerts = [];
  let batchServed = false;
  const txMock = {
    $executeRaw: async () => 1,
    detectionRuleConfig: {
      findUnique: async () => ({
        severity: 'HIGH',
        cooldown_minutes: 45,
      }),
    },
    securityAlert: {
      findFirst: async () => null,
      create: async ({ data }) => {
        createdAlerts.push(data);
        return data;
      },
    },
    alertAuditLink: {
      create: async () => ({}),
      createMany: async () => ({ count: 1 }),
    },
  };
  const mockDb = {
    $transaction: async (fn) => fn(txMock),
    auditLog: {
      findMany: async ({ select, where }) => {
        if (select?.chain_partition) {
          return [{ chain_partition: 'SECURITY_OPERATIONS' }];
        }
        if (where?.chain_partition === 'SECURITY_OPERATIONS' && !batchServed) {
          batchServed = true;
          return [
            {
              id: 1n,
              chain_sequence: 1n,
              chain_partition: 'SECURITY_OPERATIONS',
              occurred_at: new Date('2026-11-25T08:00:00Z'),
              actor_user_id: 50n,
              actor_username: 'qa.security',
              action: 'LOGIN_SUCCESS',
              object_type: 'SESSION',
              object_id: 's1',
              document_id: null,
              outcome: 'SUCCESS',
              reason_code: null,
              ip_address: '127.0.0.1',
              user_agent: 'QA',
              request_id: 'req-1',
              details: {},
              prev_hash: '0'.repeat(64),
              entry_hash: 'tampered_invalid_hash',
              chain_algorithm: 'HMAC-SHA256-V1',
              hmac_key_version: 1,
            },
          ];
        }
        return [];
      },
    },
    auditAnchor: {
      findMany: async () => [],
      findFirst: async () => null,
    },
  };

  const report = await runAuditVerificationSweep('test-hmac-secret-key-at-least-32-chars!!', {
    databaseClient: mockDb,
  });

  assert.equal(report.totalViolations >= 1, true);
  assert.equal(report.alertsCreated, 1);
  assert.equal(createdAlerts.length, 1);
  assert.equal(createdAlerts[0].alert_type, 'AUDIT_INTEGRITY_COMPROMISED');
  assert.equal(
    createdAlerts[0].severity,
    'HIGH',
    'Must apply configured severity from detection_rule_configs',
  );
});

test('#06 — IcapServer.getStatusSnapshot and Worker /health expose real enabled/listening/action state', async () => {
  const icapServer = new IcapServer({
    enabled: true,
    host: '127.0.0.1',
    port: 0,
    action: 'AUDIT_ONLY',
    customKeywords: ['TOP-SECRET-PROJECT'],
  });

  const beforeStart = icapServer.getStatusSnapshot();
  assert.equal(beforeStart.enabled, true);
  assert.equal(beforeStart.listening, false);
  assert.equal(beforeStart.action, 'AUDIT_ONLY');
  assert.equal(beforeStart.customKeywordsCount, 1);

  await icapServer.start();
  const abort = new AbortController();
  const healthHandle = startWorkerHealthServer(
    {
      host: '127.0.0.1',
      port: 0,
      dbHeartbeatTtlMs: 0,
      checkDatabase: async () => true,
      getIcapStatus: () => icapServer.getStatusSnapshot(),
    },
    abort.signal,
  );
  const { port } = await healthHandle.ready;

  try {
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.icap.enabled, true);
    assert.equal(body.icap.listening, true);
    assert.equal(body.icap.action, 'AUDIT_ONLY');
    assert.equal(body.icap.customKeywordsCount, 1);
  } finally {
    abort.abort();
    await healthHandle.stop();
    await icapServer.stop();
  }
});

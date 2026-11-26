import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import * as net from 'node:net';
import { test } from 'node:test';
import { canonicalizeJson } from '@sda/contracts';
import { runAuditVerificationSweep } from '../dist/audit-verification-job.js';
import { expireIdleAccessSessions } from '../dist/derivative-cleanup-job.js';
import { processOutboxBatch } from '../dist/notification-outbox-job.js';
import { startWorkerHealthServer } from '../dist/worker-health-server.js';
import {
  getWorkerMetricsSnapshot,
  incrementIcapBlocked,
  incrementOutboxDeadLetter,
  recordWorkerJobRun,
  resetWorkerMetricsForTesting,
} from '../dist/worker-metrics.js';

test('WorkerHealthServer — serves /health 200/503 and /metrics with Bearer token protection', async () => {
  resetWorkerMetricsForTesting();
  recordWorkerJobRun('export_processor', 'success');
  incrementOutboxDeadLetter(2);
  incrementIcapBlocked(3);

  let dbHealthy = true;
  const abort = new AbortController();
  const handle = startWorkerHealthServer(
    {
      host: '127.0.0.1',
      port: 0,
      metricsScrapeToken: 'secret-prom-scrape-token-123',
      dbHeartbeatTtlMs: 0,
      checkDatabase: async () => dbHealthy,
    },
    abort.signal,
  );
  const { port } = await handle.ready;

  try {
    const healthOk = await fetch(`http://127.0.0.1:${port}/health`);
    assert.equal(healthOk.status, 200);
    const bodyOk = await healthOk.json();
    assert.equal(bodyOk.status, 'ok');
    assert.equal(bodyOk.dbHealthy, true);

    dbHealthy = false;
    const healthDegraded = await fetch(`http://127.0.0.1:${port}/health`);
    assert.equal(healthDegraded.status, 503);

    const unauthMetrics = await fetch(`http://127.0.0.1:${port}/metrics`);
    assert.equal(unauthMetrics.status, 401);

    const authMetrics = await fetch(`http://127.0.0.1:${port}/metrics`, {
      headers: { authorization: 'Bearer secret-prom-scrape-token-123' },
    });
    assert.equal(authMetrics.status, 200);
    const metricsText = await authMetrics.text();
    assert.match(metricsText, /sda_worker_up 1/u);
    assert.match(
      metricsText,
      /sda_worker_job_runs_total\{job="export_processor",status="success"\} 1/u,
    );
    assert.match(metricsText, /sda_worker_outbox_dead_letter_total 2/u);
    assert.match(metricsText, /sda_worker_icap_blocked_total 3/u);
    assert.match(
      metricsText,
      /sda_audit_integrity_compromised_total\{partition="ALL",source="worker"\} 0/u,
    );
  } finally {
    abort.abort();
    await handle.stop();
  }
});

test('NotificationOutboxJob — BOTH channel is idempotent across SMTP retries (no duplicate IN_APP row)', async () => {
  const prevHost = process.env['SMTP_HOST'];
  const prevPort = process.env['SMTP_PORT'];
  delete process.env['SMTP_HOST'];

  const outboxItem = {
    id: randomUUID(),
    recipient_id: 77n,
    channel: 'BOTH',
    notification_type: 'ACCESS_APPROVED',
    title: 'Grant Approved',
    body: 'Your document access request is approved.',
    payload: { email: 'user77@sda.local', relatedObjectType: 'GRANT', relatedObjectId: 'g-77' },
    status: 'PENDING',
    attempt_count: 0,
    max_attempts: 3,
    last_error: null,
    created_at: new Date('2026-11-01T00:00:00Z'),
  };

  const createdNotifications = [];
  const mockDb = {
    $queryRawUnsafe: async () => [{ ...outboxItem }],
    notification: {
      findFirst: async ({ where }) =>
        createdNotifications.find(
          (n) =>
            n.id === where?.OR?.[0]?.id ||
            (n.recipient_id === outboxItem.recipient_id && n.related_object_id === 'g-77'),
        ) ?? null,
      create: async ({ data }) => {
        createdNotifications.push(data);
        return data;
      },
    },
    notificationOutbox: {
      update: async ({ data }) => Object.assign(outboxItem, data),
    },
  };

  const firstAttempt = await processOutboxBatch({ databaseClient: mockDb });
  assert.equal(firstAttempt.failed, 1);
  assert.equal(createdNotifications.length, 1);
  assert.equal(outboxItem.payload.__inAppDelivered, true);

  const smtpServer = net.createServer((socket) => {
    socket.write('220 localhost ESMTP\r\n');
    let inData = false;
    socket.on('data', (chunk) => {
      const str = chunk.toString('utf8');
      if (inData && str.includes('\r\n.\r\n')) {
        inData = false;
        socket.write('250 OK\r\n');
      } else if (str.toUpperCase().startsWith('EHLO') || str.toUpperCase().startsWith('HELO')) {
        socket.write('250 localhost\r\n');
      } else if (str.toUpperCase().startsWith('DATA')) {
        inData = true;
        socket.write('354 Go ahead\r\n');
      } else if (str.toUpperCase().startsWith('QUIT')) {
        socket.write('221 Bye\r\n');
        socket.end();
      } else {
        socket.write('250 OK\r\n');
      }
    });
  });
  await new Promise((r) => smtpServer.listen(0, '127.0.0.1', r));
  process.env['SMTP_HOST'] = '127.0.0.1';
  process.env['SMTP_PORT'] = String(smtpServer.address().port);

  try {
    const secondAttempt = await processOutboxBatch({ databaseClient: mockDb });
    assert.equal(secondAttempt.sent, 1);
    assert.equal(outboxItem.status, 'SENT');
    assert.equal(createdNotifications.length, 1, 'Must NEVER insert duplicate IN_APP notification');
  } finally {
    if (prevHost === undefined) delete process.env['SMTP_HOST'];
    else process.env['SMTP_HOST'] = prevHost;
    if (prevPort === undefined) delete process.env['SMTP_PORT'];
    else process.env['SMTP_PORT'] = prevPort;
    await new Promise((r) => smtpServer.close(r));
  }
});

test('DerivativeCleanupJob & AuditVerificationJob — expires idle sessions and resumes from VALID AuditAnchor', async () => {
  resetWorkerMetricsForTesting();
  let capturedWhere = null;
  let capturedStatus = null;
  const expiredCount = await expireIdleAccessSessions({
    maxIdleSessionMinutes: 45,
    databaseClient: {
      accessSession: {
        updateMany: async ({ where, data }) => {
          capturedWhere = where;
          capturedStatus = data.status;
          return { count: 4 };
        },
      },
    },
  });
  assert.equal(expiredCount, 4);
  assert.equal(capturedWhere.status, 'ACTIVE');
  assert.equal(capturedStatus, 'ENDED');

  const key = 'audit-anchor-resume-secret-key-at-least-32-chars!';
  const anchorHash = 'a'.repeat(64);
  const anchorSig = createHmac('sha256', key).update(`DOCUMENT:500:${anchorHash}`).digest('hex');
  const occurredAt = new Date('2026-11-10T10:00:00.000Z');
  const corrId = randomUUID();
  const row501Canonical = canonicalizeJson({
    action: 'DOCUMENT_VIEW',
    actorUserId: '1',
    actorUsername: 'reader',
    chainAlgorithm: 'HMAC-SHA-256',
    chainPartition: 'DOCUMENT',
    chainSequence: '501',
    correlationId: corrId,
    details: {},
    documentId: 'doc-1',
    accessSessionId: null,
    ipAddress: '127.0.0.1',
    objectType: 'DOCUMENT',
    objectId: 'doc-1',
    occurredAt: occurredAt.toISOString(),
    outcome: 'SUCCESS',
    previousHash: anchorHash,
    reasonCode: null,
    userAgent: null,
  });
  const row501Hash = createHmac('sha256', key).update(row501Canonical, 'utf8').digest('hex');

  let queriedAfterSequence = null;
  const summary = await runAuditVerificationSweep(key, {
    databaseClient: {
      auditLog: {
        findFirst: async () => ({ id: 500n, entry_hash: anchorHash }),
        findMany: async (args) => {
          if (args?.distinct) return [{ chain_partition: 'DOCUMENT' }];
          queriedAfterSequence = args?.where?.chain_sequence?.gt;
          return [
            {
              id: 501n,
              chain_partition: 'DOCUMENT',
              chain_sequence: 501n,
              chain_algorithm: 'HMAC-SHA-256',
              hmac_key_version: 1,
              action: 'DOCUMENT_VIEW',
              actor_user_id: 1n,
              actor_username: 'reader',
              correlation_id: corrId,
              details: {},
              document_id: 'doc-1',
              access_session_id: null,
              ip_address: '127.0.0.1',
              object_type: 'DOCUMENT',
              object_id: 'doc-1',
              occurred_at: occurredAt,
              outcome: 'SUCCESS',
              previous_hash: anchorHash,
              reason_code: null,
              user_agent: null,
              entry_hash: row501Hash,
            },
          ];
        },
      },
      auditAnchor: {
        findMany: async (args) =>
          args?.distinct
            ? [{ chain_partition: 'DOCUMENT' }]
            : [
                {
                  chain_partition: 'DOCUMENT',
                  anchor_sequence: 500n,
                  entry_hash: anchorHash,
                  signature: anchorSig,
                  signer_key_id: 'audit-hmac-v1',
                  status: 'VALID',
                },
              ],
      },
    },
  });
  assert.equal(queriedAfterSequence, 500n, 'Must resume from VALID AuditAnchor sequence 500');
  assert.equal(summary.totalLogsChecked, 1);
  assert.equal(summary.totalViolations, 0);
  assert.equal(getWorkerMetricsSnapshot().auditIntegrityCompromisedTotal, 0);
});

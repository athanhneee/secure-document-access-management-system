import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import {
  runAuditVerificationSweep,
  startAuditVerificationJob,
} from '../dist/audit-verification-job.js';

process.env.DATABASE_URL = 'postgresql://localhost:5432/secure_docs?schema=public';
process.env.NODE_ENV = 'test';

// ── startAuditVerificationJob Tests ──────────────────────────────────────────

test('startAuditVerificationJob — stops cleanly when abort signal fires', async () => {
  const shutdown = new AbortController();
  startAuditVerificationJob(600_000, 'test-hmac-key-not-for-production-000', shutdown.signal);

  shutdown.abort();
  await new Promise((resolve) => setTimeout(resolve, 50));
});

test('startAuditVerificationJob — accepts valid interval and integrity key', () => {
  const shutdown = new AbortController();

  assert.doesNotThrow(() => {
    startAuditVerificationJob(60_000, 'test-hmac-key-not-for-production-000', shutdown.signal);
  });

  shutdown.abort();
});

test('startAuditVerificationJob — can be started and stopped multiple times', async () => {
  for (let i = 0; i < 3; i++) {
    const shutdown = new AbortController();
    startAuditVerificationJob(600_000, 'test-hmac-key-not-for-production-000', shutdown.signal);
    shutdown.abort();
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
});

test('runAuditVerificationSweep — verifies multi-version rotated keys and v2 anchor signatures', async () => {
  const keyV1 = 'primary-hmac-key-version-1-at-least-32-chars!!';
  const keyV2 = 'rotated-hmac-key-version-2-at-least-32-chars!!';
  const rotationJson = JSON.stringify({ 2: keyV2 });
  const occurredAt1 = new Date('2026-09-23T10:00:00.000Z');
  const occurredAt2 = new Date('2026-09-23T10:05:00.000Z');
  const corr1 = randomUUID();
  const corr2 = randomUUID();

  function signCanonicalLog(key, row) {
    const payload = {
      accessSessionId: row.access_session_id,
      action: row.action,
      actorUserId: row.actor_user_id ? row.actor_user_id.toString() : null,
      actorUsername: row.actor_username,
      chainAlgorithm: row.chain_algorithm,
      chainPartition: row.chain_partition,
      chainSequence: row.chain_sequence.toString(),
      correlationId: row.correlation_id,
      details: row.details,
      documentId: row.document_id,
      ipAddress: row.ip_address,
      objectId: row.object_id,
      objectType: row.object_type,
      occurredAt: row.occurred_at.toISOString(),
      outcome: row.outcome,
      previousHash: row.previous_hash,
      reasonCode: row.reason_code,
      userAgent: row.user_agent,
    };
    const canonical = JSON.stringify(
      Object.fromEntries(Object.entries(payload).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))),
    );
    return createHmac('sha256', key).update(canonical, 'utf8').digest('hex');
  }

  const log1 = {
    id: 1n,
    chain_partition: 'AUTH',
    chain_sequence: 1n,
    hmac_key_version: 1,
    chain_algorithm: 'HMAC-SHA-256',
    action: 'USER_LOGIN',
    actor_user_id: 10n,
    actor_username: 'alice',
    correlation_id: corr1,
    details: {},
    document_id: null,
    access_session_id: null,
    ip_address: '127.0.0.1',
    object_type: 'AUTHENTICATION',
    object_id: '10',
    occurred_at: occurredAt1,
    outcome: 'SUCCESS',
    previous_hash: null,
    reason_code: null,
    user_agent: null,
    entry_hash: '',
  };
  log1.entry_hash = signCanonicalLog(keyV1, log1);

  const log2 = {
    ...log1,
    id: 2n,
    chain_sequence: 2n,
    hmac_key_version: 2,
    correlation_id: corr2,
    occurred_at: occurredAt2,
    previous_hash: log1.entry_hash,
    entry_hash: '',
  };
  log2.entry_hash = signCanonicalLog(keyV2, log2);

  const anchorSigV2 = createHmac('sha256', keyV2).update(`AUTH:2:${log2.entry_hash}`).digest('hex');

  const mockDb = {
    auditLog: {
      findMany: async (args) => {
        if (args?.distinct) return [{ chain_partition: 'AUTH' }];
        if (args?.where?.chain_sequence?.gt === 2n) return [];
        return [log1, log2];
      },
    },
    auditAnchor: {
      findMany: async () => [
        {
          id: 1n,
          chain_partition: 'AUTH',
          anchor_sequence: 2n,
          entry_hash: log2.entry_hash,
          signature: anchorSigV2,
          signer_key_id: 'integrity-key-v2',
        },
      ],
    },
    securityAlert: {
      findFirst: async () => null,
      create: async ({ data }) => data,
    },
    alertAuditLink: {
      create: async ({ data }) => data,
    },
    $transaction: async (fn) => fn(mockDb),
  };

  const summary = await runAuditVerificationSweep(keyV1, {
    keyRotationJson: rotationJson,
    databaseClient: mockDb,
  });
  assert.equal(summary.partitionsChecked, 1);
  assert.equal(summary.totalLogsChecked, 2);
  assert.equal(summary.totalViolations, 0);
  assert.equal(summary.alertsCreated, 0);
});

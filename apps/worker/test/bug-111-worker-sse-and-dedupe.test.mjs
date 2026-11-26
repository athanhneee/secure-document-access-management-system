import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHmac, randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { canonicalizeJson } from '@sda/contracts';

import {
  deduplicateAuditViolations,
  runAuditVerificationSweep,
} from '../dist/audit-verification-job.js';
import { runGrantExpiryBatch } from '../dist/grant-expiry-job.js';
import { setWorkerRealtimeTestObserver } from '../dist/realtime-redis-publisher.js';

const TEST_HMAC_KEY = 'worker-bug-111-hmac-secret-key-0123456789abcdef';

function buildValidLogRow(seq, prevHash, partition = 'SECURITY', overrides = {}) {
  const occurredAt = new Date('2026-06-01T10:00:00.000Z');
  const details = { step: Number(seq) };
  const correlationId = '00000000-0000-4000-8000-000000000001';
  const canonical = canonicalizeJson({
    action: 'SECURITY_CHECK',
    actorUserId: null,
    actorUsername: 'SYSTEM_WORKER',
    chainAlgorithm: 'HMAC-SHA-256',
    chainPartition: partition,
    chainSequence: seq.toString(),
    correlationId,
    details,
    documentId: null,
    accessSessionId: null,
    ipAddress: '127.0.0.1',
    objectType: 'SYSTEM',
    objectId: null,
    occurredAt: occurredAt.toISOString(),
    outcome: 'SUCCESS',
    previousHash: prevHash,
    reasonCode: null,
    userAgent: null,
  });
  const entryHash = createHmac('sha256', TEST_HMAC_KEY).update(canonical, 'utf8').digest('hex');
  return {
    id: seq,
    occurred_at: occurredAt,
    actor_user_id: null,
    actor_username: 'SYSTEM_WORKER',
    action: 'SECURITY_CHECK',
    object_type: 'SYSTEM',
    object_id: null,
    document_id: null,
    access_session_id: null,
    outcome: 'SUCCESS',
    reason_code: null,
    ip_address: '127.0.0.1',
    user_agent: null,
    correlation_id: correlationId,
    details,
    previous_hash: prevHash,
    entry_hash: entryHash,
    chain_partition: partition,
    chain_sequence: seq,
    hmac_key_version: 1,
    chain_algorithm: 'HMAC-SHA-256',
    ...overrides,
  };
}

test('BUG-111 (Worker): deduplicateAuditViolations collapses duplicate (code, sequence) and preserves logId', () => {
  const deduped = deduplicateAuditViolations([
    { code: 'AUDIT_ANCHOR_MISMATCH', sequence: 5n, message: 'probe mismatch' },
    { code: 'AUDIT_ANCHOR_MISMATCH', sequence: 5n, logId: 500n, message: 'full scan mismatch' },
    { code: 'AUDIT_LOG_TAMPERED', sequence: 5n, logId: 500n, message: 'probe tamper' },
    { code: 'AUDIT_LOG_TAMPERED', sequence: 5n, logId: 500n, message: 'full scan tamper' },
  ]);
  assert.equal(deduped.length, 2);
  assert.equal(deduped[0].logId, 500n);
  assert.equal(deduped[1].code, 'AUDIT_LOG_TAMPERED');
});

test('BUG-111 (Worker): runAuditVerificationSweep deduplicates fallback violations and publishes SECURITY_ALERT_UPDATED SSE', async () => {
  const events = [];
  setWorkerRealtimeTestObserver((ev) => events.push(ev));
  try {
    const log1 = buildValidLogRow(1n, null, 'SECURITY');
    const validLog2 = buildValidLogRow(2n, log1.entry_hash, 'SECURITY');
    // Tamper log2 payload while keeping valid anchor signature on validLog2.entry_hash so anchor fallback triggers!
    const tamperedLog2 = { ...validLog2, details: { step: 999 } };

    const anchorSig = createHmac('sha256', TEST_HMAC_KEY)
      .update(`SECURITY:2:${validLog2.entry_hash}`)
      .digest('hex');

    const anchors = [
      {
        id: 1n,
        chain_partition: 'SECURITY',
        anchor_sequence: 2n,
        entry_hash: validLog2.entry_hash,
        signature: anchorSig,
        signer_key_id: 'v1',
        status: 'VALID',
      },
    ];
    const logs = [log1, tamperedLog2];
    const createdAlerts = [];

    const mockDb = {
      auditLog: {
        findMany: async (args) => {
          if (args?.distinct) return [{ chain_partition: 'SECURITY' }];
          const gt = args?.where?.chain_sequence?.gt;
          return gt !== undefined ? logs.filter((l) => l.chain_sequence > gt) : logs;
        },
        count: async () => 2,
        findFirst: async ({ where }) =>
          logs.find((l) => l.chain_sequence === where.chain_sequence) ?? null,
      },
      auditAnchor: {
        findMany: async (args) => (args?.distinct ? [{ chain_partition: 'SECURITY' }] : anchors),
      },
      detectionRuleConfig: {
        findUnique: async () => null,
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
      },
      $transaction: async (fn) => fn(mockDb),
    };

    const summary = await runAuditVerificationSweep(TEST_HMAC_KEY, {
      databaseClient: mockDb,
      fullScan: false,
    });

    // Previously counted 2 for the exact same tampered log at sequence 2 (once during anchor probe + once in full scan)
    assert.equal(summary.totalViolations, 1);
    assert.equal(summary.alertsCreated, 1);
    assert.equal(createdAlerts.length, 1);

    const sseAlert = events.find((e) => e.type === 'SECURITY_ALERT_UPDATED');
    assert.ok(sseAlert, 'Must publish SECURITY_ALERT_UPDATED over Redis bridge');
    assert.equal(sseAlert.payload.alertType, 'AUDIT_INTEGRITY_COMPROMISED');
    assert.equal(sseAlert.payload.partition, 'SECURITY');
  } finally {
    setWorkerRealtimeTestObserver(null);
  }
});

test('BUG-111 (Worker): runGrantExpiryBatch emits ACCESS_GRANT_UPDATED and ACCESS_SESSION_UPDATED post-commit SSE events', async () => {
  const events = [];
  setWorkerRealtimeTestObserver((ev) => events.push(ev));
  try {
    const grantId = randomUUID();
    const docId = randomUUID();
    const sessionId = randomUUID();

    const txMock = {
      $queryRawUnsafe: async (sql) => {
        if (sql.includes('FROM access_grants')) {
          return [
            {
              id: grantId,
              document_id: docId,
              principal_user_id: 25n,
              principal_role_id: null,
              principal_type: 'USER',
            },
          ];
        }
        return [];
      },
      $executeRawUnsafe: async () => 1,
      accessGrant: { updateMany: async () => ({ count: 1 }) },
      document: {
        findMany: async () => [{ id: docId, owner_id: 10n }],
      },
      accessSession: {
        findMany: async () => [{ id: sessionId, user_id: 25n, access_grant_id: grantId }],
        updateMany: async () => ({ count: 1 }),
      },
      auditLog: { create: async () => ({}) },
    };
    const dbMock = {
      $transaction: async (fn) => fn(txMock),
    };

    const expiredCount = await runGrantExpiryBatch(TEST_HMAC_KEY, undefined, {
      databaseClient: dbMock,
    });
    assert.equal(expiredCount, 1);

    const grantEv = events.find((e) => e.type === 'ACCESS_GRANT_UPDATED');
    assert.ok(grantEv, 'Must emit ACCESS_GRANT_UPDATED');
    assert.equal(grantEv.payload.id, grantId);
    assert.equal(grantEv.payload.status, 'EXPIRED');
    assert.equal(grantEv.payload.action, 'REVOKED');
    assert.deepEqual(grantEv.targetUserIds, ['10', '25']);

    const sessEv = events.find((e) => e.type === 'ACCESS_SESSION_UPDATED');
    assert.ok(sessEv, 'Must emit ACCESS_SESSION_UPDATED');
    assert.equal(sessEv.payload.id, sessionId);
    assert.equal(sessEv.payload.status, 'TERMINATED');
  } finally {
    setWorkerRealtimeTestObserver(null);
  }
});

test('BUG-111 (Worker): icap-alert-sink wires publishWorkerRealtimeEvent for NETWORK_DLP_VIOLATION', () => {
  const sinkSrc = fs.readFileSync(
    path.resolve(import.meta.dirname, '../src/icap/icap-alert-sink.ts'),
    'utf8',
  );
  assert.match(sinkSrc, /publishWorkerRealtimeEvent/);
  assert.match(sinkSrc, /SECURITY_ALERT_UPDATED/);
  assert.match(sinkSrc, /NETWORK_DLP_VIOLATION/);
});

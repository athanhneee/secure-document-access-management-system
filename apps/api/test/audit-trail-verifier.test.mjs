import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHmac, randomUUID } from 'node:crypto';
import { AppErrorCode } from '../../../packages/contracts/dist/error-codes.js';
import { canonicalizeJson } from '../dist/modules/audit/audit-canonicalizer.js';
import { AuditVerifierService } from '../dist/modules/audit/audit-verifier.service.js';
import { createAuditWriterHarness } from './helpers/audit-trail-mocks.mjs';

test('AuditVerifierService: Validates pristine chain successfully', async () => {
  const { writer, logs, mockTx } = createAuditWriterHarness();
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  await writer.record(
    { action: 'EVENT_1', outcome: 'SUCCESS', objectType: 'DOC', chainPartition: 'P1' },
    context,
    mockTx,
  );
  await writer.record(
    { action: 'EVENT_2', outcome: 'DENIED', objectType: 'DOC', chainPartition: 'P1' },
    context,
    mockTx,
  );
  await writer.record(
    { action: 'EVENT_3', outcome: 'FAILED', objectType: 'DOC', chainPartition: 'P1' },
    context,
    mockTx,
  );

  const mockDatabase = {
    auditLog: { findMany: async () => logs },
    auditAnchor: { findMany: async () => [] },
  };

  const verifier = new AuditVerifierService(writer, mockDatabase);
  const result = await verifier.verifyPartition('P1');

  assert.equal(result.valid, true);
  assert.equal(result.totalChecked, 3);
  assert.equal(result.violations.length, 0);
});

test('AuditVerifierService: Detects AUDIT_LOG_TAMPERED on protected field modification', async () => {
  const { writer, logs, mockTx } = createAuditWriterHarness();
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };
  await writer.record(
    { action: 'ORIGINAL_ACTION', outcome: 'SUCCESS', objectType: 'DOC', chainPartition: 'P1' },
    context,
    mockTx,
  );

  const tamperedLogs = [{ ...logs[0], action: 'TAMPERED_ACTION' }];

  let alertCreated = false;
  const mockDatabase = {
    auditLog: { findMany: async () => tamperedLogs },
    auditAnchor: { findMany: async () => [] },
    $transaction: async (fn) =>
      fn({
        securityAlert: {
          create: async ({ data }) => {
            alertCreated = true;
            assert.equal(data.severity, 'CRITICAL');
            assert.equal(data.alert_type, 'AUDIT_INTEGRITY_COMPROMISED');
          },
        },
        alertAuditLink: { create: async () => {} },
      }),
  };

  const verifier = new AuditVerifierService(writer, mockDatabase);
  const result = await verifier.verifyPartition('P1');

  assert.equal(result.valid, false);
  assert.equal(result.violations.length, 1);
  assert.equal(result.violations[0].code, AppErrorCode.AUDIT_LOG_TAMPERED);
  assert.equal(alertCreated, true);
});

test('AuditVerifierService: Detects AUDIT_SEQUENCE_GAP when log is missing/deleted', async () => {
  const { config, writer } = createAuditWriterHarness();

  const logs = [
    {
      id: 1n,
      action: 'OP1',
      actor_user_id: null,
      actor_username: null,
      chain_algorithm: 'HMAC-SHA-256',
      chain_partition: 'P1',
      chain_sequence: 1n,
      correlation_id: randomUUID(),
      details: {},
      document_id: null,
      access_session_id: null,
      ip_address: null,
      object_type: 'DOC',
      object_id: null,
      occurred_at: new Date(),
      outcome: 'SUCCESS',
      previous_hash: null,
      reason_code: null,
      user_agent: null,
      hmac_key_version: 1,
      entry_hash: '',
    },
    {
      id: 3n,
      action: 'OP3',
      actor_user_id: null,
      actor_username: null,
      chain_algorithm: 'HMAC-SHA-256',
      chain_partition: 'P1',
      chain_sequence: 3n,
      correlation_id: randomUUID(),
      details: {},
      document_id: null,
      access_session_id: null,
      ip_address: null,
      object_type: 'DOC',
      object_id: null,
      occurred_at: new Date(),
      outcome: 'SUCCESS',
      previous_hash: 'some-hash',
      reason_code: null,
      user_agent: null,
      hmac_key_version: 1,
      entry_hash: 'entry3',
    },
  ];

  const canon1 = canonicalizeJson({
    action: logs[0].action,
    actorUserId: null,
    actorUsername: null,
    chainAlgorithm: logs[0].chain_algorithm,
    chainPartition: logs[0].chain_partition,
    chainSequence: '1',
    correlationId: logs[0].correlation_id,
    details: logs[0].details,
    documentId: null,
    accessSessionId: null,
    ipAddress: null,
    objectType: logs[0].object_type,
    objectId: null,
    occurredAt: logs[0].occurred_at.toISOString(),
    outcome: logs[0].outcome,
    previousHash: null,
    reasonCode: null,
    userAgent: null,
  });
  logs[0].entry_hash = createHmac('sha256', config.get('AUDIT_INTEGRITY_KEY'))
    .update(canon1)
    .digest('hex');

  const mockDatabase = {
    auditLog: { findMany: async () => logs },
    auditAnchor: { findMany: async () => [] },
    $transaction: async (fn) =>
      fn({
        securityAlert: { create: async () => {} },
        alertAuditLink: { create: async () => {} },
      }),
  };

  const verifier = new AuditVerifierService(writer, mockDatabase);
  const result = await verifier.verifyPartition('P1');

  assert.equal(result.valid, false);
  const gapViolation = result.violations.find((v) => v.code === AppErrorCode.AUDIT_SEQUENCE_GAP);
  assert.ok(gapViolation);
  assert.equal(gapViolation.sequence, 3n);
});

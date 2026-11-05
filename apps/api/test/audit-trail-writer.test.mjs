import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { AppErrorCode } from '../../../packages/contracts/dist/error-codes.js';
import { AuditRedactionService } from '../dist/modules/audit/audit-redaction.service.js';
import {
  AuditWriterService,
  AuditWriteException,
} from '../dist/modules/audit/audit-writer.service.js';
import { createMockConfig, createAuditWriterHarness } from './helpers/audit-trail-mocks.mjs';

test('AuditWriterService: Sequential recording with previous_hash and HMAC chaining', async () => {
  const { writer, logs: inMemoryLogs, mockTx } = createAuditWriterHarness();
  const context = {
    ip: '192.168.1.100',
    userAgent: 'AuditClient/1.0',
    correlationId: randomUUID(),
  };

  const entry1 = await writer.record(
    {
      action: 'DOCUMENT_CREATED',
      outcome: 'SUCCESS',
      objectType: 'DOCUMENT',
      objectId: 'doc-uuid-1',
      documentId: 'doc-uuid-1',
      actorUserId: 101n,
      actorUsername: 'alice',
      chainPartition: 'DOCUMENT',
    },
    context,
    mockTx,
  );

  assert.equal(entry1.chain_sequence, 1n);
  assert.equal(inMemoryLogs[0].previous_hash, null);
  assert.equal(inMemoryLogs[0].chain_partition, 'DOCUMENT');

  const entry2 = await writer.record(
    {
      action: 'DOCUMENT_CLASSIFIED',
      outcome: 'SUCCESS',
      objectType: 'DOCUMENT',
      objectId: 'doc-uuid-1',
      documentId: 'doc-uuid-1',
      actorUserId: 101n,
      actorUsername: 'alice',
      chainPartition: 'DOCUMENT',
    },
    context,
    mockTx,
  );

  assert.equal(entry2.chain_sequence, 2n);
  assert.equal(inMemoryLogs[1].previous_hash, inMemoryLogs[0].entry_hash);
  assert.notEqual(inMemoryLogs[1].entry_hash, inMemoryLogs[0].entry_hash);
});

test('AuditWriterService: Partition isolation allows independent sequences', async () => {
  const redaction = new AuditRedactionService();
  const config = createMockConfig();
  const partitionMap = new Map();

  const mockTx = {
    $executeRawUnsafe: async () => {},
    $queryRawUnsafe: async (_sql, partition) => {
      const logs = partitionMap.get(partition) ?? [];
      if (logs.length === 0) return [];
      const last = logs[logs.length - 1];
      return [{ entry_hash: last.entry_hash, chain_sequence: last.chain_sequence }];
    },
    auditLog: {
      create: async ({ data }) => {
        if (!partitionMap.has(data.chain_partition)) {
          partitionMap.set(data.chain_partition, []);
        }
        partitionMap.get(data.chain_partition).push(data);
        return {
          id: BigInt(Date.now()),
          entry_hash: data.entry_hash,
          chain_partition: data.chain_partition,
          chain_sequence: data.chain_sequence,
        };
      },
    },
  };

  const writer = new AuditWriterService(config, redaction);
  const context = { ip: '10.0.0.1', correlationId: randomUUID() };

  const authEntry1 = await writer.record(
    {
      action: 'USER_LOGIN',
      outcome: 'SUCCESS',
      objectType: 'USER',
      chainPartition: 'AUTH',
    },
    context,
    mockTx,
  );

  const grantEntry1 = await writer.record(
    {
      action: 'GRANT_CREATED',
      outcome: 'SUCCESS',
      objectType: 'ACCESS_GRANT',
      chainPartition: 'ACCESS_GRANT',
    },
    context,
    mockTx,
  );

  assert.equal(authEntry1.chain_sequence, 1n);
  assert.equal(grantEntry1.chain_sequence, 1n);
  assert.equal(partitionMap.get('AUTH').length, 1);
  assert.equal(partitionMap.get('ACCESS_GRANT').length, 1);
});

test('AuditWriterService: Does not swallow errors and throws AuditWriteException', async () => {
  const redaction = new AuditRedactionService();
  const config = createMockConfig();

  const failingTx = {
    $executeRawUnsafe: async () => {
      throw new Error('Database connection failed');
    },
  };

  const writer = new AuditWriterService(config, redaction);
  const context = { ip: '10.0.0.1', correlationId: randomUUID() };

  await assert.rejects(
    async () => {
      await writer.record(
        {
          action: 'CRITICAL_OP',
          outcome: 'SUCCESS',
          objectType: 'SYSTEM',
        },
        context,
        failingTx,
      );
    },
    (err) => {
      assert.ok(err instanceof AuditWriteException);
      assert.equal(err.code, AppErrorCode.AUDIT_WRITE_FAILED);
      return true;
    },
  );
});

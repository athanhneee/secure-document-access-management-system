import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { startGrantExpiryJob, runGrantExpiryBatch } from '../dist/grant-expiry-job.js';

// ── startGrantExpiryJob Tests ────────────────────────────────────────────────

test('startGrantExpiryJob — stops cleanly when abort signal fires', async () => {
  const shutdown = new AbortController();
  // Start with a very long interval so it won't actually tick
  startGrantExpiryJob(600_000, 'test-hmac-key-not-for-production-000', shutdown.signal);

  // Immediately abort
  shutdown.abort();

  // Should not throw — verify by waiting a tick
  await new Promise((resolve) => setTimeout(resolve, 50));
});

test('startGrantExpiryJob — accepts valid interval and hmac key', () => {
  const shutdown = new AbortController();

  // Should not throw
  assert.doesNotThrow(() => {
    startGrantExpiryJob(60_000, 'test-hmac-key-not-for-production-000', shutdown.signal);
  });

  shutdown.abort();
});

test('startGrantExpiryJob — can be started and stopped multiple times', async () => {
  for (let i = 0; i < 3; i++) {
    const shutdown = new AbortController();
    startGrantExpiryJob(600_000, 'test-hmac-key-not-for-production-000', shutdown.signal);
    shutdown.abort();
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
});

test('runGrantExpiryBatch — uses 64-bit hashtextextended lock once per partition and retries 40001 without double-counting', async () => {
  let txAttempts = 0;
  const advisoryLockQueries = [];
  const createdAuditLogs = [];
  const g1 = randomUUID();
  const g2 = randomUUID();
  const docId = randomUUID();

  const mockClient = {
    async $transaction(operation) {
      txAttempts++;
      if (txAttempts === 1) {
        throw { code: '40001', message: 'could not serialize access due to concurrent update' };
      }
      const tx = {
        $queryRawUnsafe: async (sql) => {
          if (sql.includes('FROM access_grants')) {
            return [
              {
                id: g1,
                document_id: docId,
                principal_user_id: 10n,
                principal_role_id: null,
                principal_type: 'USER',
              },
              {
                id: g2,
                document_id: docId,
                principal_user_id: 11n,
                principal_role_id: null,
                principal_type: 'USER',
              },
            ];
          }
          return [{ entry_hash: 'a'.repeat(64), chain_sequence: 5n }];
        },
        $executeRawUnsafe: async (sql, partition) => {
          advisoryLockQueries.push({ sql, partition });
          return 1;
        },
        accessGrant: { updateMany: async ({ where }) => ({ count: where.id.in.length }) },
        accessSession: {
          findMany: async () => [],
          updateMany: async () => ({ count: 0 }),
        },
        auditLog: {
          create: async ({ data }) => {
            createdAuditLogs.push(data);
            return data;
          },
        },
      };
      return operation(tx);
    },
  };

  const count = await runGrantExpiryBatch('test-hmac-key-not-for-production-000000', undefined, {
    databaseClient: mockClient,
    maxRetries: 2,
  });

  assert.equal(txAttempts, 2);
  assert.equal(count, 2);
  assert.equal(advisoryLockQueries.length, 1);
  assert.match(advisoryLockQueries[0].sql, /hashtextextended\(\$1,\s*0\)/u);
  assert.equal(advisoryLockQueries[0].partition, 'ACCESS_GRANT');
  assert.equal(createdAuditLogs.length, 2);
  assert.equal(createdAuditLogs[0].chain_sequence, 6n);
  assert.equal(createdAuditLogs[1].chain_sequence, 7n);
  assert.equal(createdAuditLogs[1].previous_hash, createdAuditLogs[0].entry_hash);
});

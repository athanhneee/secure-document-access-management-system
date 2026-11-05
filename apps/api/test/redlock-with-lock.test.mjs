import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RedlockService } from '../dist/modules/concurrency/redlock.service.js';
import { MockRedisNode, createMockConfig } from './helpers/redlock-mocks.mjs';

test('Redlock — withLock executes callback and automatically cleans up lock', async () => {
  const node = new MockRedisNode('node-1');
  const redlock = new RedlockService(createMockConfig(), [node]);
  const lockKey = redlock.getLockKey('work-item-1');

  let executed = false;
  const result = await redlock.withLock('work-item-1', 1000, async (handle) => {
    assert.ok(handle);
    assert.ok(node.store.has(lockKey));
    executed = true;
    return 'computation-result';
  });

  assert.equal(executed, true);
  assert.equal(result, 'computation-result');
  assert.equal(
    node.store.has(lockKey),
    false,
    'Lock must be released automatically after withLock',
  );
});

test('Redlock — withLock releases lock even if callback throws an exception', async () => {
  const node = new MockRedisNode('node-1');
  const redlock = new RedlockService(createMockConfig(), [node]);
  const lockKey = redlock.getLockKey('work-item-error');

  await assert.rejects(
    async () =>
      redlock.withLock('work-item-error', 1000, async () => {
        throw new Error('Business error inside transaction');
      }),
    /Business error inside transaction/,
  );

  assert.equal(
    node.store.has(lockKey),
    false,
    'Lock must be cleaned up even on unhandled exception',
  );
});

test('Redlock — withLock throws ConflictException when lock cannot be acquired', async () => {
  const node = new MockRedisNode('node-1');
  const redlock = new RedlockService(createMockConfig({ REDLOCK_FAIL_CLOSED: true }), [node]);

  const lockKey = redlock.getLockKey('contended-res');
  node.store.set(lockKey, { value: 'other-token', expiresAt: Date.now() + 5000 });

  await assert.rejects(
    async () =>
      redlock.withLock('contended-res', 1000, async () => 'never-runs', {
        retryCount: 0,
        failClosed: true,
      }),
    /Failed to acquire distributed lock for resource "contended-res"/,
  );
});

test('Redlock — hybrid concurrency control serializes concurrent operations without race condition', async () => {
  const node = new MockRedisNode('node-1');
  const redlock = new RedlockService(createMockConfig(), [node]);

  let counter = 0;
  const executionOrder = [];

  async function performCriticalSection(callerId, durationMs) {
    return redlock.withLock(
      'shared-counter',
      2000,
      async () => {
        executionOrder.push(`${callerId}-start`);
        const readVal = counter;
        await new Promise((r) => setTimeout(r, durationMs));
        counter = readVal + 1;
        executionOrder.push(`${callerId}-end`);
        return counter;
      },
      { retryCount: 40, retryDelayMs: 15, retryJitterMs: 5 },
    );
  }

  const [res1, res2] = await Promise.all([
    performCriticalSection('caller-A', 25),
    performCriticalSection('caller-B', 25),
  ]);

  assert.equal(counter, 2, 'Counter must be incremented exactly twice without race condition');
  assert.ok(res1 === 1 || res1 === 2);
  assert.ok(res2 === 1 || res2 === 2);
  assert.notEqual(res1, res2);

  const firstCaller = executionOrder[0].startsWith('caller-A') ? 'caller-A' : 'caller-B';
  const secondCaller = firstCaller === 'caller-A' ? 'caller-B' : 'caller-A';
  assert.deepEqual(executionOrder, [
    `${firstCaller}-start`,
    `${firstCaller}-end`,
    `${secondCaller}-start`,
    `${secondCaller}-end`,
  ]);
});

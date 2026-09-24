import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RedlockService } from '../dist/modules/concurrency/redlock.service.js';

class MockRedisNode {
  constructor(name = 'node-1') {
    this.name = name;
    this.store = new Map();
    this.failNext = false;
  }

  async set(key, value, px, ttl, nx) {
    if (this.failNext) {
      throw new Error(`Node ${this.name} connection error`);
    }
    const existing = this.store.get(key);
    const now = Date.now();
    if (existing && existing.expiresAt > now) {
      if (nx === 'NX') return null;
    }
    this.store.set(key, { value, expiresAt: now + ttl });
    return 'OK';
  }

  async eval(script, numKeys, key, ...args) {
    if (this.failNext) {
      throw new Error(`Node ${this.name} connection error`);
    }
    const entry = this.store.get(key);
    const now = Date.now();
    const token = args[0];

    // UNLOCK_LUA_SCRIPT
    if (script.includes('del')) {
      if (entry && entry.expiresAt > now && entry.value === token) {
        this.store.delete(key);
        return 1;
      }
      return 0;
    }

    // EXTEND_LUA_SCRIPT
    if (script.includes('pexpire')) {
      const additionalTtl = Number(args[1]);
      if (entry && entry.expiresAt > now && entry.value === token) {
        entry.expiresAt = now + additionalTtl;
        return 1;
      }
      return 0;
    }

    return 0;
  }

  async ping() {
    if (this.failNext) throw new Error('Unreachable');
    return 'PONG';
  }

  disconnect() {}
  on() {}
}

function createMockConfig(overrides = {}) {
  const values = {
    REDIS_URL: 'redis://127.0.0.1:6379/0',
    REDLOCK_RETRY_COUNT: 2,
    REDLOCK_RETRY_DELAY_MS: 10,
    REDLOCK_RETRY_JITTER_MS: 5,
    REDLOCK_DEFAULT_TTL_MS: 2000,
    REDLOCK_FAIL_CLOSED: false,
    ...overrides,
  };
  return {
    get: (key) => values[key],
  };
}

test('Redlock — acquires and releases lock on single resource successfully', async () => {
  const node = new MockRedisNode('node-1');
  const redlock = new RedlockService(createMockConfig(), [node]);

  const handle = await redlock.acquire('doc-100', 1000);
  assert.ok(handle, 'Lock must be successfully acquired');
  assert.equal(handle.resource, 'doc-100');
  assert.equal(typeof handle.token, 'string');
  assert.ok(handle.validityTimeMs > 0);

  // Key is set in Redis with prefix
  const lockKey = redlock.getLockKey('doc-100');
  assert.ok(node.store.has(lockKey));
  assert.equal(node.store.get(lockKey).value, handle.token);

  // Release lock
  const released = await handle.release();
  assert.equal(released, true);
  assert.equal(node.store.has(lockKey), false);
});

test('Redlock — rejects concurrent acquisition on identical resource while locked', async () => {
  const node = new MockRedisNode('node-1');
  const redlock = new RedlockService(createMockConfig(), [node]);

  // Client A acquires lock
  const handleA = await redlock.acquire('request-789', 2000);
  assert.ok(handleA);

  // Client B attempts to acquire same resource
  const handleB = await redlock.acquire('request-789', 2000, { retryCount: 1, retryDelayMs: 5 });
  assert.equal(handleB, null, 'Client B must fail to acquire locked resource');

  // Client A releases lock
  await handleA.release();

  // Client B can now acquire it
  const handleBRetry = await redlock.acquire('request-789', 2000);
  assert.ok(handleBRetry, 'Client B should succeed after Client A releases');
  await handleBRetry.release();
});

test('Redlock — safe release prevents unlocking another client lock if expired', async () => {
  const node = new MockRedisNode('node-1');
  const redlock = new RedlockService(createMockConfig(), [node]);

  const handleA = await redlock.acquire('resource-x', 50);
  assert.ok(handleA);

  // Simulate expiry by overwriting lock with Client B's token
  const lockKey = redlock.getLockKey('resource-x');
  node.store.set(lockKey, { value: 'client-b-token', expiresAt: Date.now() + 5000 });

  // Client A tries to release its old expired lock
  const released = await handleA.release();
  assert.equal(released, false, 'Client A must not be able to release Client B lock');

  // Verify Client B's lock remains intact
  assert.equal(node.store.get(lockKey).value, 'client-b-token');
});

test('Redlock — extends lock TTL via atomic extend script', async () => {
  const node = new MockRedisNode('node-1');
  const redlock = new RedlockService(createMockConfig(), [node]);

  const handle = await redlock.acquire('batch-job', 1000);
  assert.ok(handle);

  const lockKey = redlock.getLockKey('batch-job');
  const initialExpiry = node.store.get(lockKey).expiresAt;

  // Extend lock by 3000ms
  const extended = await handle.extend(3000);
  assert.equal(extended, true);

  const newExpiry = node.store.get(lockKey).expiresAt;
  assert.ok(newExpiry > initialExpiry, 'Expiry time must be pushed forward');

  await handle.release();
});

test('Redlock — multi-node quorum consensus (3 nodes: quorum 2/3)', async () => {
  const node1 = new MockRedisNode('node-1');
  const node2 = new MockRedisNode('node-2');
  const node3 = new MockRedisNode('node-3');

  const redlock = new RedlockService(createMockConfig(), [node1, node2, node3]);
  assert.equal(redlock.nodeCount, 3);
  assert.equal(redlock.quorumCount, 2);

  // Node 3 fails, but Node 1 and Node 2 succeed -> 2/3 reached!
  node3.failNext = true;

  const handle = await redlock.acquire('multi-node-res', 2000);
  assert.ok(handle, 'Quorum of 2/3 must allow lock acquisition even with 1 dead node');

  // Verify lock exists on node1 and node2
  const lockKey = redlock.getLockKey('multi-node-res');
  assert.ok(node1.store.has(lockKey));
  assert.ok(node2.store.has(lockKey));

  // Release
  const released = await handle.release();
  assert.equal(released, true);
  assert.equal(node1.store.has(lockKey), false);
  assert.equal(node2.store.has(lockKey), false);
});

test('Redlock — multi-node quorum failure (2 nodes fail out of 3 -> lock rejected)', async () => {
  const node1 = new MockRedisNode('node-1');
  const node2 = new MockRedisNode('node-2');
  const node3 = new MockRedisNode('node-3');

  const redlock = new RedlockService(createMockConfig(), [node1, node2, node3]);

  // Nodes 2 and 3 fail -> only 1 vote, quorum requires 2
  node2.failNext = true;
  node3.failNext = true;

  const handle = await redlock.acquire('split-brain-res', 1000, { retryCount: 0 });
  assert.equal(handle, null, 'Must fail when quorum cannot be achieved');

  // Node 1 was rolled back and unlocked
  const lockKey = redlock.getLockKey('split-brain-res');
  assert.equal(
    node1.store.has(lockKey),
    false,
    'Acquired node must be cleaned up on quorum failure',
  );
});

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

  // Pre-lock resource
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
      { retryCount: 15, retryDelayMs: 10, retryJitterMs: 5 },
    );
  }

  // Two parallel callers accessing shared resource
  const [res1, res2] = await Promise.all([
    performCriticalSection('caller-A', 25),
    performCriticalSection('caller-B', 25),
  ]);

  assert.equal(counter, 2, 'Counter must be incremented exactly twice without race condition');
  assert.ok(res1 === 1 || res1 === 2);
  assert.ok(res2 === 1 || res2 === 2);
  assert.notEqual(res1, res2);

  // Verify non-overlapping sequential execution
  // First caller must finish before second caller starts
  const firstCaller = executionOrder[0].startsWith('caller-A') ? 'caller-A' : 'caller-B';
  const secondCaller = firstCaller === 'caller-A' ? 'caller-B' : 'caller-A';
  assert.deepEqual(executionOrder, [
    `${firstCaller}-start`,
    `${firstCaller}-end`,
    `${secondCaller}-start`,
    `${secondCaller}-end`,
  ]);
});

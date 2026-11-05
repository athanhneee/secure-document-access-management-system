import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RedlockService } from '../dist/modules/concurrency/redlock.service.js';
import { MockRedisNode, createMockConfig } from './helpers/redlock-mocks.mjs';

test('Redlock — acquires and releases lock on single resource successfully', async () => {
  const node = new MockRedisNode('node-1');
  const redlock = new RedlockService(createMockConfig(), [node]);

  const handle = await redlock.acquire('doc-100', 1000);
  assert.ok(handle, 'Lock must be successfully acquired');
  assert.equal(handle.resource, 'doc-100');
  assert.equal(typeof handle.token, 'string');
  assert.ok(handle.validityTimeMs > 0);

  const lockKey = redlock.getLockKey('doc-100');
  assert.ok(node.store.has(lockKey));
  assert.equal(node.store.get(lockKey).value, handle.token);

  const released = await handle.release();
  assert.equal(released, true);
  assert.equal(node.store.has(lockKey), false);
});

test('Redlock — rejects concurrent acquisition on identical resource while locked', async () => {
  const node = new MockRedisNode('node-1');
  const redlock = new RedlockService(createMockConfig(), [node]);

  const handleA = await redlock.acquire('request-789', 2000);
  assert.ok(handleA);

  const handleB = await redlock.acquire('request-789', 2000, { retryCount: 1, retryDelayMs: 5 });
  assert.equal(handleB, null, 'Client B must fail to acquire locked resource');

  await handleA.release();

  const handleBRetry = await redlock.acquire('request-789', 2000);
  assert.ok(handleBRetry, 'Client B should succeed after Client A releases');
  await handleBRetry.release();
});

test('Redlock — safe release prevents unlocking another client lock if expired', async () => {
  const node = new MockRedisNode('node-1');
  const redlock = new RedlockService(createMockConfig(), [node]);

  const handleA = await redlock.acquire('resource-x', 500);
  assert.ok(handleA);

  const lockKey = redlock.getLockKey('resource-x');
  node.store.set(lockKey, { value: 'client-b-token', expiresAt: Date.now() + 5000 });

  const released = await handleA.release();
  assert.equal(released, false, 'Client A must not be able to release Client B lock');
  assert.equal(node.store.get(lockKey).value, 'client-b-token');
});

test('Redlock — extends lock TTL via atomic extend script', async () => {
  const node = new MockRedisNode('node-1');
  const redlock = new RedlockService(createMockConfig(), [node]);

  const handle = await redlock.acquire('batch-job', 1000);
  assert.ok(handle);

  const lockKey = redlock.getLockKey('batch-job');
  const initialExpiry = node.store.get(lockKey).expiresAt;

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

  node3.failNext = true;

  const handle = await redlock.acquire('multi-node-res', 2000);
  assert.ok(handle, 'Quorum of 2/3 must allow lock acquisition even with 1 dead node');

  const lockKey = redlock.getLockKey('multi-node-res');
  assert.ok(node1.store.has(lockKey));
  assert.ok(node2.store.has(lockKey));

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

  node2.failNext = true;
  node3.failNext = true;

  const handle = await redlock.acquire('split-brain-res', 1000, { retryCount: 0 });
  assert.equal(handle, null, 'Must fail when quorum cannot be achieved');

  const lockKey = redlock.getLockKey('split-brain-res');
  assert.equal(
    node1.store.has(lockKey),
    false,
    'Acquired node must be cleaned up on quorum failure',
  );
});

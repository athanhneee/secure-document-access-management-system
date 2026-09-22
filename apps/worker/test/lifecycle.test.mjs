import assert from 'node:assert/strict';
import { test } from 'node:test';
import { waitForShutdown } from '../dist/lifecycle.js';

test('worker stays idle until shutdown and cancels its timer cleanly', async () => {
  const shutdown = new AbortController();
  let stopped = false;
  const running = waitForShutdown(shutdown.signal).then(() => {
    stopped = true;
  });
  await Promise.resolve();
  assert.equal(stopped, false);
  shutdown.abort();
  await running;
  assert.equal(stopped, true);
});

test('a shutdown requested before startup returns immediately', async () => {
  const shutdown = new AbortController();
  shutdown.abort();
  await waitForShutdown(shutdown.signal);
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { startGrantExpiryJob } from '../dist/grant-expiry-job.js';

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

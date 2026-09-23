import assert from 'node:assert/strict';
import { test } from 'node:test';
import { startAuditVerificationJob } from '../dist/audit-verification-job.js';

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

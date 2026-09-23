import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { startSecurityDetectionJob, runDetectionCycle } from '../dist/security-detection-job.js';
import { startNotificationOutboxJob, processOutboxBatch } from '../dist/notification-outbox-job.js';
import { startExportCleanupJob, cleanExpiredExportJobs } from '../dist/export-cleanup-job.js';

// ── 1. Security Detection Worker Job ─────────────────────────────────────────

test('startSecurityDetectionJob — starts and stops cleanly via AbortSignal', async () => {
  const shutdown = new AbortController();
  startSecurityDetectionJob(600_000, shutdown.signal);
  shutdown.abort();
  await new Promise((resolve) => setTimeout(resolve, 20));
});

test('runDetectionCycle — evaluates rules and creates alerts with links', async () => {
  const createdAlerts = [];
  const createdLinks = [];
  const now = new Date('2026-09-23T12:00:00Z');
  const userId = 777n;

  const mockDb = {
    detectionRuleConfig: {
      findMany: async () => [
        {
          rule_code: 'MASS_DOWNLOAD',
          name: 'Mass Download Rule',
          is_enabled: true,
          severity: 'HIGH',
          threshold: 3,
          window_minutes: 10,
          cooldown_minutes: 30,
          parameters: {},
        },
      ],
    },
    auditLog: {
      findMany: async () => [
        { id: 1n, actor_user_id: userId, document_id: randomUUID(), occurred_at: now },
        { id: 2n, actor_user_id: userId, document_id: randomUUID(), occurred_at: now },
        { id: 3n, actor_user_id: userId, document_id: randomUUID(), occurred_at: now },
      ],
    },
    securityAlert: {
      findFirst: async () => null, // No existing alert
      create: async ({ data }) => {
        createdAlerts.push(data);
        return data;
      },
    },
    alertAuditLink: {
      createMany: async ({ data }) => {
        createdLinks.push(...data);
        return { count: data.length };
      },
    },
    $transaction: async (fn) => fn(mockDb),
  };

  const result = await runDetectionCycle({ databaseClient: mockDb, now });
  assert.equal(result.alertsCreated, 1);
  assert.equal(createdAlerts.length, 1);
  assert.equal(createdAlerts[0].alert_type, 'MASS_DOWNLOAD');
  assert.equal(createdAlerts[0].detected_user_id, userId);
  assert.equal(createdLinks.length, 3);
});

// ── 2. Notification Outbox Worker Job ────────────────────────────────────────

test('startNotificationOutboxJob — starts and stops cleanly via AbortSignal', async () => {
  const shutdown = new AbortController();
  startNotificationOutboxJob(600_000, shutdown.signal);
  shutdown.abort();
  await new Promise((resolve) => setTimeout(resolve, 20));
});

test('processOutboxBatch — processes in-app notifications and moves to SENT', async () => {
  const notifications = [];
  const outbox = [
    {
      id: randomUUID(),
      recipient_id: 123n,
      channel: 'IN_APP',
      notification_type: 'SECURITY_ALERT',
      title: 'Alert detected',
      body: 'Multiple denied access attempts detected',
      payload: { relatedObjectType: 'SECURITY_ALERT', relatedObjectId: 'alert-1' },
      deduplication_key: 'ALERT:1:123',
      status: 'PENDING',
      attempt_count: 0,
      max_attempts: 3,
      next_retry_at: new Date(),
      last_error: null,
      created_at: new Date(),
      processed_at: null,
    },
  ];

  const mockDb = {
    notificationOutbox: {
      findMany: async () => outbox,
      update: async ({ where, data }) => {
        const item = outbox.find((o) => o.id === where.id);
        Object.assign(item, data);
        return item;
      },
    },
    notification: {
      findFirst: async () => null,
      create: async ({ data }) => {
        notifications.push(data);
        return data;
      },
    },
  };

  const result = await processOutboxBatch({ databaseClient: mockDb });
  assert.equal(result.processed, 1);
  assert.equal(result.sent, 1);
  assert.equal(notifications.length, 1);
  assert.equal(notifications[0].title, 'Alert detected');
  assert.equal(outbox[0].status, 'SENT');
});

test('processOutboxBatch — transitions to DEAD_LETTER when attempt exceeds max_attempts', async () => {
  const outbox = [
    {
      id: randomUUID(),
      recipient_id: 999n,
      channel: 'EMAIL',
      notification_type: 'SECURITY_ALERT',
      title: 'Failed alert',
      body: 'Will fail',
      payload: {},
      deduplication_key: 'FAILED:KEY:1',
      status: 'FAILED',
      attempt_count: 3,
      max_attempts: 3,
      next_retry_at: new Date(Date.now() - 1000),
      last_error: 'Previous SMTP error',
      created_at: new Date(),
      processed_at: null,
    },
  ];

  const mockDb = {
    notificationOutbox: {
      findMany: async () => outbox,
      update: async ({ where, data }) => {
        const item = outbox.find((o) => o.id === where.id);
        Object.assign(item, data);
        return item;
      },
    },
  };

  const result = await processOutboxBatch({ databaseClient: mockDb });
  assert.equal(result.deadLettered, 1);
  assert.equal(outbox[0].status, 'DEAD_LETTER');
});

// ── 3. Export Cleanup Worker Job ─────────────────────────────────────────────

test('startExportCleanupJob — starts and stops cleanly via AbortSignal', async () => {
  const shutdown = new AbortController();
  startExportCleanupJob(600_000, shutdown.signal);
  shutdown.abort();
  await new Promise((resolve) => setTimeout(resolve, 20));
});

test('cleanExpiredExportJobs — deletes expired export records from database', async () => {
  const expiredId = randomUUID();
  const jobs = [
    {
      id: expiredId,
      file_path: null,
      expires_at: new Date(Date.now() - 3600 * 1000),
    },
  ];

  const mockDb = {
    asyncExportJob: {
      findMany: async () => jobs,
      delete: async ({ where }) => {
        const idx = jobs.findIndex((j) => j.id === where.id);
        if (idx !== -1) jobs.splice(idx, 1);
        return { id: where.id };
      },
    },
  };

  const result = await cleanExpiredExportJobs({ databaseClient: mockDb });
  assert.equal(result.expiredJobsCleaned, 1);
  assert.equal(jobs.length, 0);
});

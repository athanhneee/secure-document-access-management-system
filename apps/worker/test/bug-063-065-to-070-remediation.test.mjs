/**
 * Module: Bộ Kiểm Thử Hồi Quy Worker `BUG-063`, `BUG-065` .. `BUG-070` (`@sda/worker`)
 * Thuật toán: Kiểm chứng phát SSE `USER_SESSION_REVOKED` khi phiên hết hạn, đồng bộ khóa HMAC/Export đa tiến trình,
 *   thu hồi đối tượng S3/job kẹt `PROCESSING`, hợp nhất quy tắc SOC nền tảng, giới hạn `take: 5000` + khóa tư vấn Cooldown
 *   và khử trùng SSE `NOTIFICATION_CREATED` đủ 9 trường theo khóa tất định trên Outbox.
 */
import assert from 'node:assert/strict';
import { createDecipheriv, hkdfSync, randomUUID } from 'node:crypto';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
  EXPORT_AT_REST_HKDF_INFO,
  EXPORT_AT_REST_HKDF_SALT,
  resolveExportEncryptionIkm,
  resolvePrimaryAuditHmacKeyFromEnv,
} from '@sda/contracts';
import { expireIdleAndElapsedAuthSessions } from '../dist/auth-session-cleanup-job.js';
import { loadDetectionRules } from '../dist/detection/rule-defaults.js';
import { evaluateDetectionRule } from '../dist/detection/rule-evaluators.js';
import { cleanExpiredExportJobs } from '../dist/export-cleanup-job.js';
import {
  encryptExportArtifactBuffer,
  processPendingExportJobs,
} from '../dist/export-processor-job.js';
import { processOutboxBatch } from '../dist/notification-outbox-job.js';
import {
  deliverIdempotentInAppNotification,
  deliverIdempotentInAppNotificationDetailed,
  deriveDeterministicNotificationId,
} from '../dist/outbox-claim-and-inapp.helper.js';
import { setWorkerRealtimeTestObserver } from '../dist/realtime-redis-publisher.js';

test('BUG-063 (Worker) — expireIdleAndElapsedAuthSessions publishes USER_SESSION_REVOKED scoped to targetSessionIds', async () => {
  const observed = [];
  setWorkerRealtimeTestObserver((ev) => observed.push(ev));
  try {
    const res = await expireIdleAndElapsedAuthSessions({
      now: new Date('2026-11-26T10:00:00Z'),
      databaseClient: {
        authSession: {
          findMany: async () => [
            { id: 'sess-a', user_id: 10n },
            { id: 'sess-b', user_id: 10n },
          ],
          updateMany: async ({ where }) => (where.expires_at?.lte ? { count: 1 } : { count: 1 }),
        },
        refreshToken: { updateMany: async () => ({ count: 2 }) },
      },
    });
    assert.equal(res.expiredAbsoluteCount + res.expiredIdleCount, 2);
    assert.equal(observed.length, 1);
    assert.equal(observed[0].type, 'USER_SESSION_REVOKED');
    assert.deepEqual(observed[0].targetUserIds, ['10']);
    assert.deepEqual(observed[0].targetSessionIds, ['sess-a', 'sess-b']);
  } finally {
    setWorkerRealtimeTestObserver(null);
  }
});

test('BUG-065 & BUG-066 (Worker) — Shared audit HMAC priority skips empty strings and Worker AES-256-GCM export artifact decrypts cleanly with API HKDF key', () => {
  const resolvedKey = resolvePrimaryAuditHmacKeyFromEnv({
    NODE_ENV: 'production',
    AUDIT_INTEGRITY_KEY: '',
    DOCUMENT_AUDIT_HMAC_KEY: '   ',
    AUTH_AUDIT_HMAC_KEY: 'shared-auth-hmac-key-at-least-32-chars-00001',
  });
  assert.equal(resolvedKey, 'shared-auth-hmac-key-at-least-32-chars-00001');

  const prevNodeEnv = process.env['NODE_ENV'];
  const prevExportKey = process.env['EXPORT_ENCRYPTION_KEY'];
  const prevAuditKey = process.env['AUDIT_INTEGRITY_KEY'];
  try {
    process.env['NODE_ENV'] = 'development';
    delete process.env['EXPORT_ENCRYPTION_KEY'];
    delete process.env['AUDIT_INTEGRITY_KEY'];

    const jobId = randomUUID();
    const plaintext = Buffer.from('col1,col2\n1,2\n', 'utf8');
    const ciphertext = encryptExportArtifactBuffer(jobId, plaintext);

    // Decrypt independently using shared @sda/contracts HKDF derivation (identical to @sda/api)
    const apiKey = Buffer.from(
      hkdfSync(
        'sha256',
        Buffer.from(resolveExportEncryptionIkm(process.env), 'utf8'),
        Buffer.from(EXPORT_AT_REST_HKDF_SALT, 'utf8'),
        Buffer.from(EXPORT_AT_REST_HKDF_INFO, 'utf8'),
        32,
      ),
    );
    const iv = ciphertext.subarray(5, 17);
    const tag = ciphertext.subarray(17, 33);
    const body = ciphertext.subarray(33);
    const decipher = createDecipheriv('aes-256-gcm', apiKey, iv, { authTagLength: 16 });
    decipher.setAAD(Buffer.from(jobId, 'utf8'));
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(body), decipher.final()]);
    assert.deepEqual(decrypted, plaintext);
  } finally {
    if (prevNodeEnv === undefined) delete process.env['NODE_ENV'];
    else process.env['NODE_ENV'] = prevNodeEnv;
    if (prevExportKey === undefined) delete process.env['EXPORT_ENCRYPTION_KEY'];
    else process.env['EXPORT_ENCRYPTION_KEY'] = prevExportKey;
    if (prevAuditKey === undefined) delete process.env['AUDIT_INTEGRITY_KEY'];
    else process.env['AUDIT_INTEGRITY_KEY'] = prevAuditKey;
  }
});

test('BUG-067 (Worker) — Export cleanup deletes orphaned artifacts even when file_path is null, and claimPendingExportJobs filters expires_at > now and reclaims stale PROCESSING leases', async () => {
  const tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-bug067-'));
  try {
    const nullPathJobId = randomUUID();
    const orphanFile = path.join(tmpDir, `${nullPathJobId}.dat`);
    await fsp.writeFile(orphanFile, 'orphan-ciphertext');

    const deletedDbIds = [];
    const cleanupRes = await cleanExpiredExportJobs({
      exportBaseDir: tmpDir,
      now: new Date('2026-11-26T10:00:00Z'),
      databaseClient: {
        asyncExportJob: {
          findMany: async () => [{ id: nullPathJobId, file_path: null }],
          delete: async ({ where }) => {
            deletedDbIds.push(where.id);
          },
        },
      },
    });
    assert.equal(cleanupRes.expiredJobsCleaned, 1);
    assert.equal(cleanupRes.filesDeleted, 1);
    assert.deepEqual(deletedDbIds, [nullPathJobId]);
    await assert.rejects(() => fsp.stat(orphanFile));

    // Verify stuck PROCESSING job past lease is reclaimed while fresh PROCESSING & expired jobs are skipped
    const now = new Date('2026-11-26T12:00:00Z');
    const stuckJobId = randomUUID();
    const activeJobId = randomUUID();
    const expiredJobId = randomUUID();
    const updatedCompleted = [];

    const summary = await processPendingExportJobs({
      exportBaseDir: tmpDir,
      now,
      leaseMs: 15 * 60_000,
      databaseClient: {
        asyncExportJob: {
          findMany: async () => [
            {
              id: stuckJobId,
              requester_user_id: 1n,
              export_type: 'AUDIT_LOGS',
              format: 'CSV',
              status: 'PROCESSING',
              filter_params: { __leaseExpiresAt: new Date(now.getTime() - 60_000).toISOString() },
              created_at: new Date(now.getTime() - 30 * 60_000),
              expires_at: new Date(now.getTime() + 3_600_000),
            },
            {
              id: activeJobId,
              requester_user_id: 1n,
              export_type: 'AUDIT_LOGS',
              format: 'CSV',
              status: 'PROCESSING',
              filter_params: {
                __leaseExpiresAt: new Date(now.getTime() + 10 * 60_000).toISOString(),
              },
              created_at: new Date(now.getTime() - 60_000),
              expires_at: new Date(now.getTime() + 3_600_000),
            },
            {
              id: expiredJobId,
              requester_user_id: 1n,
              export_type: 'AUDIT_LOGS',
              format: 'CSV',
              status: 'PENDING',
              filter_params: {},
              created_at: new Date(now.getTime() - 3_600_000),
              expires_at: new Date(now.getTime() - 1_000),
            },
          ],
          updateMany: async () => ({ count: 1 }),
          update: async ({ where, data }) => {
            updatedCompleted.push({ id: where.id, status: data.status });
            return data;
          },
          count: async () => 0,
        },
        auditLog: { findMany: async () => [] },
      },
    });
    assert.equal(summary.claimed, 1);
    assert.equal(summary.completed, 1);
    assert.equal(updatedCompleted[0].id, stuckJobId);
    assert.equal(updatedCompleted[0].status, 'COMPLETED');
  } finally {
    await fsp.rm(tmpDir, { recursive: true, force: true });
  }
});

test('BUG-068 (Worker) — loadDetectionRules merges DB overrides onto all 6 baseline rules and forces AUDIT_INTEGRITY_COMPROMISED enabled', async () => {
  const rules = await loadDetectionRules({
    detectionRuleConfig: {
      findMany: async () => [
        {
          rule_code: 'MASS_DOWNLOAD',
          name: 'Custom Mass DL',
          is_enabled: true,
          severity: 'CRITICAL',
          threshold: 3,
          window_minutes: 5,
          cooldown_minutes: 15,
          parameters: {},
        },
        {
          rule_code: 'AUDIT_INTEGRITY_COMPROMISED',
          name: 'Audit Tamper',
          is_enabled: false,
          severity: 'CRITICAL',
          threshold: 1,
          window_minutes: 5,
          cooldown_minutes: 5,
          parameters: {},
        },
      ],
    },
  });

  assert.equal(
    rules.length,
    6,
    'Must retain all 6 baseline SOC rules when DB has partial overrides',
  );
  const massDl = rules.find((r) => r.ruleCode === 'MASS_DOWNLOAD');
  assert.equal(massDl?.threshold, 3);
  assert.equal(massDl?.severity, 'CRITICAL');
  const auditRule = rules.find((r) => r.ruleCode === 'AUDIT_INTEGRITY_COMPROMISED');
  assert.equal(auditRule?.isEnabled, true, 'AUDIT_INTEGRITY_COMPROMISED must remain force-enabled');
});

test('BUG-069 (Worker) — Evaluators bound queries with take: 5000, use advisory lock in $transaction, set detected_user_id: null on AUDIT_INTEGRITY_COMPROMISED, and block false-positive OFF_HOURS_ACCESS', async () => {
  const queryArgs = [];
  const advisoryLocks = [];
  const createdAlerts = [];

  const mockDb = {
    auditLog: {
      findMany: async (args) => {
        queryArgs.push(args);
        if (args.where?.action?.in?.includes('AUDIT_LOG_TAMPERED')) {
          return [
            { id: 1n, actor_user_id: 7n, action: 'AUDIT_LOG_TAMPERED', occurred_at: new Date() },
          ];
        }
        if (args.where?.action?.in?.includes('DOCUMENT_VIEWED')) {
          return [
            {
              id: 2n,
              actor_user_id: 8n,
              action: 'DOCUMENT_VIEWED',
              outcome: 'SUCCESS',
              document_id: 'doc-1',
              occurred_at: new Date('2026-11-26T18:00:00Z'),
              documents: null, // undefined rank must NOT trigger alert
            },
            {
              id: 3n,
              actor_user_id: 8n,
              action: 'DOCUMENT_VIEWED',
              outcome: 'DENIED',
              document_id: 'doc-2',
              occurred_at: new Date('2026-11-26T18:00:00Z'),
              documents: { classification_history: [{ classification_levels: { rank: 4 } }] },
            },
          ];
        }
        return [];
      },
    },
    securityAlert: {
      findFirst: async () => null,
      create: async ({ data }) => {
        createdAlerts.push(data);
        return data;
      },
    },
    alertAuditLink: { createMany: async () => ({ count: 1 }) },
    $executeRawUnsafe: async (sql, ...args) => {
      advisoryLocks.push({ sql, args });
    },
    $transaction: async (fn) => fn(mockDb),
  };

  const now = new Date('2026-11-26T19:00:00Z');
  const windowStart = new Date(now.getTime() - 3_600_000);
  const cooldownStart = new Date(now.getTime() - 1_800_000);

  const countAudit = await evaluateDetectionRule(
    mockDb,
    {
      ruleCode: 'AUDIT_INTEGRITY_COMPROMISED',
      name: 'Audit Tamper',
      isEnabled: true,
      severity: 'CRITICAL',
      threshold: 1,
      windowMinutes: 60,
      cooldownMinutes: 30,
      parameters: {},
    },
    now,
    windowStart,
    cooldownStart,
  );
  const countOffHours = await evaluateDetectionRule(
    mockDb,
    {
      ruleCode: 'OFF_HOURS_ACCESS',
      name: 'Off Hours',
      isEnabled: true,
      severity: 'HIGH',
      threshold: 1,
      windowMinutes: 60,
      cooldownMinutes: 30,
      parameters: { minClassificationRank: 3 },
    },
    now,
    windowStart,
    cooldownStart,
  );

  assert.equal(countAudit, 1);
  assert.equal(countOffHours, 0);
  assert.equal(createdAlerts[0].detected_user_id, null);
  assert.ok(queryArgs.every((q) => q.take === 5000 && q.orderBy?.occurred_at === 'desc'));
  assert.ok(advisoryLocks.some((c) => c.sql.includes('pg_advisory_xact_lock')));
});

test('BUG-070 (Worker) — Outbox emits SSE NOTIFICATION_CREATED once with deterministic DB id and all 9 fields, never duplicates SSE on SMTP retry, and preserves boolean wrapper', async () => {
  const outboxId = randomUUID();
  const expectedNotifId = deriveDeterministicNotificationId(outboxId);
  const storedNotifs = new Map();
  let outboxRow = {
    id: outboxId,
    recipient_id: 42n,
    channel: 'BOTH',
    notification_type: 'ACCESS_GRANT_CREATED',
    title: 'Bạn được cấp quyền mới',
    body: 'Tài liệu A đã được cấp quyền.',
    payload: { relatedObjectType: 'DOCUMENT', relatedObjectId: 'doc-70' },
    status: 'PENDING',
    attempt_count: 0,
    max_attempts: 5,
    last_error: null,
    created_at: new Date('2026-11-26T09:00:00Z'),
  };

  const mockDb = {
    notificationOutbox: {
      findMany: async () => [outboxRow],
      update: async ({ data }) => {
        outboxRow = { ...outboxRow, ...data };
        return outboxRow;
      },
    },
    notification: {
      findFirst: async ({ where }) => {
        if (where.id) return storedNotifs.get(where.id) ?? null;
        return null;
      },
      create: async ({ data }) => {
        storedNotifs.set(data.id, data);
        return data;
      },
    },
  };

  const sseEvents = [];
  setWorkerRealtimeTestObserver((ev) => sseEvents.push(ev));
  try {
    // Attempt 1: IN_APP succeeds + emits 1 complete SSE event; SMTP fails -> retry scheduled with __inAppDelivered: true
    const run1 = await processOutboxBatch({
      databaseClient: mockDb,
      now: new Date('2026-11-26T09:01:00Z'),
      emailSender: async () => false,
    });
    assert.equal(run1.failed, 1);
    assert.equal(sseEvents.length, 1);
    assert.equal(sseEvents[0].type, 'NOTIFICATION_CREATED');
    assert.deepEqual(Object.keys(sseEvents[0].payload).sort(), [
      'body',
      'createdAt',
      'id',
      'notificationType',
      'readAt',
      'relatedObjectId',
      'relatedObjectType',
      'status',
      'title',
    ]);
    assert.equal(sseEvents[0].payload.id, expectedNotifId);
    assert.equal(sseEvents[0].payload.readAt, null);
    assert.equal(outboxRow.payload.__inAppDelivered, true);

    // Attempt 2: SMTP succeeds -> MUST NOT emit duplicate SSE NOTIFICATION_CREATED
    const run2 = await processOutboxBatch({
      databaseClient: mockDb,
      now: new Date('2026-11-26T09:05:00Z'),
      emailSender: async () => true,
    });
    assert.equal(run2.sent, 1);
    assert.equal(sseEvents.length, 1, 'SMTP retry must not duplicate SSE NOTIFICATION_CREATED');

    // Backward-compatible boolean helper + detailed helper contracts
    const detailedAgain = await deliverIdempotentInAppNotificationDetailed(
      mockDb,
      outboxRow,
      new Date('2026-11-26T09:06:00Z'),
    );
    assert.equal(detailedAgain.inAppEnsured, true);
    assert.equal(detailedAgain.newlyCreated, false);
    const boolRes = await deliverIdempotentInAppNotification(
      mockDb,
      outboxRow,
      new Date('2026-11-26T09:06:00Z'),
    );
    assert.equal(boolRes, true);
  } finally {
    setWorkerRealtimeTestObserver(null);
  }
});

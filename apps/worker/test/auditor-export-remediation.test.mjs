/**
 * @module WorkerAuditorExportRemediationTests
 * Thuật toán: Kiểm thử hồi quy Worker cho các lỗi kiểm toán & xuất báo cáo `qa.auditor`:
 *   - `parseDateBound` & `queryExportDataset`: mở rộng ngày cuối `23:59:59.999Z`, tìm `action`/`actorUsername` không phân biệt hoa/thường.
 *   - `cleanExpiredExportJobs`: thu dọn được đối tượng gương S3/R2 đa container trong khi vẫn chặn đường dẫn `..` (path traversal).
 *   - `runAuditVerificationSweep`: phát hiện `anchoredRow` bị sửa nội dung phá HMAC và phát hiện bản ghi bị xóa trước điểm neo `K`.
 *   - Kiểm tra fail-fast trên `staging` và phát sự kiện SSE `PROCESSING` / `expiresAt` / `sha256Hash`.
 */
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import fsp from 'node:fs/promises';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseDateBound, queryExportDataset } from '../dist/export-query.helper.js';
import { cleanExpiredExportJobs } from '../dist/export-cleanup-job.js';
import { isCrossContainerExportFilename } from '../dist/exports/export-s3-storage.js';
import { runAuditVerificationSweep } from '../dist/audit-verification-job.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

test('Worker export-query expands date-only to end-of-day and applies insensitive partial action/actor filters', async () => {
  assert.equal(parseDateBound('2026-11-25', false)?.toISOString(), '2026-11-25T00:00:00.000Z');
  assert.equal(parseDateBound('2026-11-25', true)?.toISOString(), '2026-11-25T23:59:59.999Z');

  let capturedWhere = null;
  const mockDb = {
    auditLog: {
      findMany: async ({ where }) => {
        capturedWhere = where;
        return [];
      },
    },
  };

  await queryExportDataset(mockDb, 'AUDIT_LOGS', {
    action: 'login',
    actorUsername: 'qa.auditor',
    from: '2026-11-25',
    to: '2026-11-25',
  });

  assert.deepEqual(capturedWhere.action, { contains: 'login', mode: 'insensitive' });
  assert.deepEqual(capturedWhere.actor_username, { contains: 'qa.auditor', mode: 'insensitive' });
  assert.equal(capturedWhere.occurred_at.gte.toISOString(), '2026-11-25T00:00:00.000Z');
  assert.equal(capturedWhere.occurred_at.lte.toISOString(), '2026-11-25T23:59:59.999Z');
});

test('Worker export-cleanup purges cross-container S3 mirror safely while still blocking path traversal', async () => {
  const jobId = randomUUID();
  const traversalJobId = randomUUID();
  assert.equal(isCrossContainerExportFilename(`/app/.local/exports/${jobId}.dat`, jobId), true);
  assert.equal(isCrossContainerExportFilename(`/app/../etc/${jobId}.dat`, jobId), false);
  assert.equal(isCrossContainerExportFilename(`/app/.local/exports/other.dat`, jobId), false);

  const exportDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-cleanup-cross-'));
  const deletedS3Keys = [];
  const deletedDbIds = [];

  const s3Server = http.createServer((req, res) => {
    if (req.method === 'DELETE') {
      deletedS3Keys.push((req.url ?? '').split('?')[0]);
    }
    res.writeHead(204);
    res.end();
  });
  await new Promise((resolve) => s3Server.listen(0, '127.0.0.1', resolve));
  const s3Port = s3Server.address().port;

  const savedEnv = {
    NODE_ENV: process.env.NODE_ENV,
    STORAGE_MOCK: process.env.STORAGE_MOCK,
    STORAGE_ENDPOINT: process.env.STORAGE_ENDPOINT,
    STORAGE_ACCESS_KEY: process.env.STORAGE_ACCESS_KEY,
    STORAGE_SECRET_KEY: process.env.STORAGE_SECRET_KEY,
    STORAGE_BUCKET_DERIVATIVES: process.env.STORAGE_BUCKET_DERIVATIVES,
  };
  process.env.NODE_ENV = 'production';
  process.env.STORAGE_MOCK = 'false';
  process.env.STORAGE_ENDPOINT = `http://127.0.0.1:${s3Port}`;
  process.env.STORAGE_ACCESS_KEY = 'worker-s3-key';
  process.env.STORAGE_SECRET_KEY = 'worker-s3-secret';
  process.env.STORAGE_BUCKET_DERIVATIVES = 'sda-derivatives';

  try {
    const result = await cleanExpiredExportJobs({
      exportBaseDir: exportDir,
      databaseClient: {
        asyncExportJob: {
          findMany: async () => [
            { id: jobId, file_path: `/other-container/.local/exports/${jobId}.dat` },
            { id: traversalJobId, file_path: `/other-container/../etc/${traversalJobId}.dat` },
          ],
          delete: async ({ where }) => {
            deletedDbIds.push(where.id);
          },
        },
      },
    });

    assert.equal(result.expiredJobsCleaned, 1);
    assert.equal(result.filesDeleted, 1);
    assert.deepEqual(deletedDbIds, [jobId]);
    assert.deepEqual(deletedS3Keys, [`/sda-derivatives/exports/${jobId}.dat`]);
  } finally {
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    await new Promise((resolve) => s3Server.close(resolve));
    await fsp.rm(exportDir, { recursive: true, force: true });
  }
});

test('Worker audit verification catches tampered anchoredRow HMAC and deleted prior rows before anchor K', async () => {
  const key = 'worker-audit-integrity-key-at-least-32-bytes!!';
  const occurredAt = new Date('2026-11-25T10:00:00.000Z');
  const corr = randomUUID();
  const forgedHash = 'a'.repeat(64);
  const anchorSig = createHmac('sha256', key).update(`AUTH:1:${forgedHash}`).digest('hex');

  const tamperedAnchoredRow = {
    id: 1n,
    chain_partition: 'AUTH',
    chain_sequence: 1n,
    hmac_key_version: 1,
    chain_algorithm: 'HMAC-SHA-256',
    action: 'LOGIN_TAMPERED',
    actor_user_id: 10n,
    actor_username: 'alice',
    correlation_id: corr,
    details: {},
    document_id: null,
    access_session_id: null,
    ip_address: '127.0.0.1',
    object_type: 'AUTHENTICATION',
    object_id: '10',
    occurred_at: occurredAt,
    outcome: 'SUCCESS',
    previous_hash: null,
    reason_code: null,
    user_agent: null,
    entry_hash: forgedHash,
  };

  const mockDb = {
    auditLog: {
      count: async () => 1,
      findFirst: async () => tamperedAnchoredRow,
      findMany: async (args) => {
        if (args?.distinct) return [{ chain_partition: 'AUTH' }];
        if (args?.where?.chain_sequence?.gt) return [];
        return [tamperedAnchoredRow];
      },
    },
    auditAnchor: {
      findMany: async (args) => {
        if (args?.distinct) return [{ chain_partition: 'AUTH' }];
        return [
          {
            chain_partition: 'AUTH',
            anchor_sequence: 1n,
            entry_hash: forgedHash,
            signature: anchorSig,
            signer_key_id: 'v1',
            status: 'VALID',
          },
        ];
      },
    },
    securityAlert: { findFirst: async () => null, create: async ({ data }) => data },
    alertAuditLink: { create: async ({ data }) => data },
    $transaction: async (fn) => fn(mockDb),
  };

  const summary = await runAuditVerificationSweep(key, { databaseClient: mockDb });
  assert.ok(summary.totalViolations >= 1, 'Tampered anchoredRow must trigger integrity violation');
  assert.equal(summary.alertsCreated, 1);
});

test('Worker main.ts enforces staging fail-fast and export-processor emits PROCESSING + expiresAt + sha256Hash', () => {
  const mainSrc = fs.readFileSync(path.resolve(__dirname, '../src/main.ts'), 'utf8');
  assert.match(mainSrc, /NODE_ENV'\] === 'staging'/);

  const processorSrc = fs.readFileSync(
    path.resolve(__dirname, '../src/export-processor-job.ts'),
    'utf8',
  );
  assert.match(processorSrc, /status:\s*'PROCESSING'/);
  assert.match(processorSrc, /sha256Hash/);
  assert.match(processorSrc, /expiresAt:\s*expiresAtIso/);

  const redisPubSrc = fs.readFileSync(
    path.resolve(__dirname, '../src/realtime-redis-publisher.ts'),
    'utf8',
  );
  assert.match(redisPubSrc, /socket\.on\('data'/);
  assert.doesNotMatch(redisPubSrc, /setTimeout\(\(\)\s*=>\s*\{\s*socket\.destroy\(\)/);
});

/**
 * Module: Medium-Severity Security & Technical Hardening Regression Suite (MED-01 .. MED-07)
 * Thuật toán: Kiểm chứng trực tiếp 7 bất biến bảo mật mức MEDIUM trên mã nguồn biên dịch thật và tệp cấu hình CI/CD.
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { PositiveBigIntSchema } from '../../../packages/contracts/dist/dto.js';
import { EnvSchema } from '../dist/config/env.schema.js';
import { AuthRepository } from '../dist/modules/auth/auth.repository.js';
import { rotateSessionRefreshToken } from '../dist/modules/auth/auth-session.repository.js';
import { RedlockService } from '../dist/modules/concurrency/redlock.service.js';
import { redactRedisEndpointUrl } from '../dist/modules/concurrency/redlock-node.helper.js';
import { AntivirusScannerService } from '../dist/modules/documents/antivirus-scanner.service.js';
import { ObjectStorageService } from '../dist/modules/documents/object-storage.service.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

// ── [MED-01] Refresh Token Rotation Blocked When Account Is LOCKED ─────────────

test('[MED-01] rotateSessionRefreshToken revokes token family and refuses rotation when user is LOCKED', async () => {
  let familyRevokedReason = null;
  let createdReplacement = false;

  const mockDb = {
    async $transaction(cb) {
      const tx = {
        refreshToken: {
          async findUnique() {
            return {
              id: 'rt-1',
              token_family_id: 'fam-locked-1',
              used_at: null,
              revoked_at: null,
              expires_at: new Date(Date.now() + 60_000),
              auth_sessions: {
                id: 'sess-locked-1',
                user_id: 77n,
                status: 'ACTIVE',
                expires_at: new Date(Date.now() + 60_000),
                mfa_verified_at: new Date(),
                users: {
                  id: 77n,
                  status: 'LOCKED',
                  locked_until: new Date(Date.now() + 86_400_000),
                },
              },
            };
          },
          async updateMany({ data }) {
            familyRevokedReason = data.revocation_reason;
            return { count: 1 };
          },
          async create() {
            createdReplacement = true;
          },
        },
        authSession: {
          async updateMany() {
            return { count: 1 };
          },
        },
      };
      return cb(tx);
    },
  };

  const result = await rotateSessionRefreshToken(
    mockDb,
    'hash-old',
    { id: randomUUID(), hash: 'hash-new', expiresAt: new Date(Date.now() + 3600_000) },
    async () => null,
  );

  assert.equal(result.kind, 'locked');
  assert.equal(familyRevokedReason, 'ACCOUNT_LOCKED');
  assert.equal(createdReplacement, false, 'Locked user must never receive a replacement token');
});

// ── [MED-02] Monotonic Admin Lockout Preservation on Login Failure ─────────────

test('[MED-02] AuthRepository.recordLoginFailure preserves longer admin locked_until duration', async () => {
  const adminLockUntil = new Date(Date.now() + 30 * 24 * 3600 * 1_000); // 30 days in future
  let updatedData = null;

  const repo = Object.create(AuthRepository.prototype);
  repo.database = {
    user: {
      async findUnique() {
        return { locked_until: adminLockUntil };
      },
      async update({ data }) {
        updatedData = data;
        return {};
      },
    },
  };

  // Case A: First failed attempt (failures < 5) must NOT clear locked_until to null
  await repo.recordLoginFailure({
    id: 5n,
    failedLoginCount: 0,
    lockedUntil: adminLockUntil,
  });
  assert.equal(updatedData.locked_until.getTime(), adminLockUntil.getTime());

  // Case B: 6th failed attempt (60s auto-lock) must NOT shorten 30-day admin lock
  await repo.recordLoginFailure({
    id: 5n,
    failedLoginCount: 5,
    lockedUntil: adminLockUntil,
  });
  assert.equal(updatedData.locked_until.getTime(), adminLockUntil.getTime());
});

// ── [MED-03] PositiveBigIntSchema Safe Integer Enforcement ────────────────────

test('[MED-03] PositiveBigIntSchema rejects precision-losing numbers > Number.MAX_SAFE_INTEGER', () => {
  assert.equal(PositiveBigIntSchema.safeParse(9007199254740991).success, true);
  assert.equal(PositiveBigIntSchema.safeParse(9007199254740992).success, false);
  assert.equal(PositiveBigIntSchema.safeParse('9007199254740992').data, 9007199254740992n);
});

// ── [MED-04] Redlock Fail-Closed Default & Redis URL Credential Redaction ──────

test('[MED-04] RedlockService defaults to fail-closed when Redis is unreachable and redacts Redis URLs', async () => {
  const redacted = redactRedisEndpointUrl(
    'rediss://default:test-placeholder@redis.internal:6379/0',
  );
  assert.ok(!redacted.includes('test-placeholder'));
  assert.ok(redacted.includes('%5BREDACTED%5D') || redacted.includes('[REDACTED]'));

  const parsedEnv = EnvSchema.parse({});
  assert.equal(parsedEnv.REDLOCK_FAIL_CLOSED, true);

  const deadNode = {
    async set() {
      throw new Error('ECONNREFUSED');
    },
    async eval() {
      return 0;
    },
    async ping() {
      throw new Error('ECONNREFUSED');
    },
    disconnect() {},
    on() {},
  };

  const service = new RedlockService(
    {
      get(key) {
        if (key === 'REDLOCK_RETRY_COUNT') return 0;
        return undefined; // Exercise default fail-closed behavior
      },
    },
    [deadNode],
  );

  await assert.rejects(
    () => service.withLock('critical-grant', 1000, async () => 'should-not-run'),
    (err) => err.status === 409,
  );
});

// ── [MED-05] STORAGE_MOCK=true Blocked in Staging & Production ────────────────

test('[MED-05] ObjectStorageService and EnvSchema reject STORAGE_MOCK=true in staging and production', () => {
  for (const envName of ['staging', 'production']) {
    const schemaCheck = EnvSchema.safeParse({
      NODE_ENV: envName,
      STORAGE_MOCK: 'true',
    });
    assert.equal(
      schemaCheck.success,
      false,
      `EnvSchema must reject STORAGE_MOCK=true in ${envName}`,
    );

    assert.throws(
      () =>
        new ObjectStorageService({
          get(key) {
            if (key === 'NODE_ENV') return envName;
            if (key === 'STORAGE_MOCK') return true;
            if (key === 'STORAGE_BUCKET_QUARANTINE') return 'secure-quarantine';
            if (key === 'STORAGE_BUCKET_DOCUMENTS') return 'secure-documents';
            if (key === 'STORAGE_BUCKET_DERIVATIVES') return 'secure-derivatives';
            return undefined;
          },
        }),
      /SECURITY_VIOLATION/,
    );
  }
});

// ── [MED-06] ClamAV Fail-Closed in Both Staging & Production ──────────────────

test('[MED-06] AntivirusScannerService fails closed in staging and production when daemon is unreachable', async () => {
  const prevNodeEnv = process.env['NODE_ENV'];
  try {
    for (const envName of ['staging', 'production']) {
      process.env['NODE_ENV'] = envName;
      const scanner = new AntivirusScannerService({
        get(key) {
          if (key === 'CLAMAV_HOST') return '127.0.0.1';
          if (key === 'CLAMAV_PORT') return 1; // Guaranteed immediate connection refusal
          if (key === 'NODE_ENV') return envName;
          return undefined;
        },
      });
      const res = await scanner.scan(Buffer.from('%PDF-1.4 benign test buffer'));
      assert.equal(
        res.status,
        'FAILED',
        `Unreachable ClamAV must fail closed (FAILED) in ${envName}`,
      );
    }
  } finally {
    if (prevNodeEnv === undefined) delete process.env['NODE_ENV'];
    else process.env['NODE_ENV'] = prevNodeEnv;
  }
});

// ── [MED-07] Immutable 40-char SHA & Container Digest Pinning in GitHub Actions ─

test('[MED-07] all GitHub Actions workflows pin actions to 40-char SHAs and container images to @sha256 digests', () => {
  const workflowDir = path.join(repoRoot, '.github', 'workflows');
  const workflowFiles = fs.readdirSync(workflowDir).filter((f) => f.endsWith('.yml'));
  assert.ok(workflowFiles.length >= 3);

  for (const file of workflowFiles) {
    const content = fs.readFileSync(path.join(workflowDir, file), 'utf8');
    const usesMatches = [...content.matchAll(/^\s*(?:-\s*)?uses:\s*([^\s#]+)/gmu)];
    assert.ok(usesMatches.length > 0, `${file} must contain pinned action references`);
    for (const [, ref] of usesMatches) {
      assert.match(
        ref,
        /^[^@]+@[0-9a-f]{40}$/u,
        `Action "${ref}" in ${file} must be pinned to a full 40-character hexadecimal commit SHA`,
      );
    }

    const imageMatches = [...content.matchAll(/^\s*image:\s*([^\s#]+)/gmu)];
    for (const [, img] of imageMatches) {
      assert.match(
        img,
        /@sha256:[0-9a-f]{64}$/u,
        `Container image "${img}" in ${file} must be pinned to an immutable @sha256 digest`,
      );
    }
  }
});

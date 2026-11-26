/**
 * Module: Bộ Kiểm Thử Hồi Quy Toàn Diện Khắc Phục Lỗi Bảo Mật & Đồng Thời `BUG-042` .. `BUG-050`
 * Thuật toán: Kiểm chứng độc lập từng bất biến bảo mật, chống đua tranh cache, chống tự khóa chết pool CSDL,
 *   bảo toàn giao dịch tuần tự hóa `40001` và bộ giải mâu thuẫn đại số ABAC.
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';

process.env.DATABASE_URL ??= 'postgresql://postgres:fixture-password@127.0.0.1:5432/sda_unit_test';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import * as OTPAuth from 'otpauth';
import { ConflictException, ForbiddenException } from '@nestjs/common';
import { withSerializableTransaction } from '@sda/database';
import { baselineAbacPolicies } from '../../../packages/database/prisma/seed-catalog.ts';
import { AppConfigService } from '../dist/config/config.service.js';
import { AbacAuditService } from '../dist/modules/abac/abac-audit.service.js';
import { CONTEXT_ATTRIBUTES } from '../dist/modules/abac/attribute-registry.js';
import { compilePolicy } from '../dist/modules/abac/policy-compiler.js';
import { hasContradiction } from '../dist/modules/abac/policy-contradiction-solver.js';
import { validatePolicy } from '../dist/modules/abac/policy-validator.js';
import { evaluatePepSessionRisk } from '../dist/modules/abac/session-risk-scorer.helper.js';
import { AccessGrantAuditService } from '../dist/modules/access-grants/access-grant-audit.service.js';
import {
  executeForgotPassword,
  GENERIC_RESET_RESPONSE,
} from '../dist/modules/auth/auth-password.helper.js';
import { evaluateSessionSecurityPosture } from '../dist/modules/auth/auth-session-posture.helper.js';
import {
  activateMfaAuthSession,
  completeAuthLoginSession,
  rotateSessionRefreshToken,
} from '../dist/modules/auth/auth-session.repository.js';
import { touchAuthSessionActivity } from '../dist/modules/auth/auth-sessions-management.helper.js';
import {
  consumeUserPasswordReset,
  findPasswordResetTokenOwner,
} from '../dist/modules/auth/auth-user.repository.js';
import { AuthRepository } from '../dist/modules/auth/auth.repository.js';
import { AuthService } from '../dist/modules/auth/auth.service.js';
import { LoginRateLimitService } from '../dist/modules/auth/login-rate-limit.service.js';
import { MfaService } from '../dist/modules/auth/mfa.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';
import { TokenService } from '../dist/modules/auth/token.service.js';
import { DistributedStateService } from '../dist/modules/concurrency/distributed-state.service.js';
import { DocumentPepService } from '../dist/modules/documents/document-pep.service.js';
import { isRestrictedNonBusinessRole } from '../dist/modules/documents/pep-context-builder.js';
import { AuthorizationCache } from '../dist/modules/rbac/authorization-cache.js';
import { AuthorizationService } from '../dist/modules/rbac/authorization.service.js';
import {
  executeAssignUserRole,
  executeRevokeUserRole,
} from '../dist/modules/rbac/rbac-assignments.helper.js';
import { RbacAuditService } from '../dist/modules/rbac/rbac-audit.service.js';
import { RealtimeEventsService } from '../dist/modules/realtime/realtime-events.service.js';
import { syncUserClearanceAssignment } from '../dist/modules/users/users-clearance-assignment.helper.js';
import {
  executeChangeUserStatus,
  executeUpdateUser,
} from '../dist/modules/users/users-mutations.helper.js';
import { config as makeAuthConfig } from './helpers/auth-security-mocks.mjs';

const BUSINESS_HOURS = new Date('2026-06-15T03:00:00.000Z'); // 10:00 ICT

test('BUG-042 — immutable login_ip_address & login_user_agent survive AuthGuard touch, token refresh, and MFA rotation so SESSION_IP_DRIFT (+25) and SESSION_UA_DRIFT (+15) trigger accurately', async () => {
  const sessions = new Map();
  const refreshTokens = new Map();
  const mockDb = {
    user: {
      update: async () => ({}),
      findUnique: async () => ({ failed_login_count: 0 }),
    },
    authSession: {
      findMany: async () => [],
      create: async ({ data }) => {
        const row = { status: 'ACTIVE', created_at: new Date(), ...data };
        sessions.set(data.id, row);
        return row;
      },
      findFirst: async ({ where }) => {
        const s = sessions.get(where.id);
        return s && s.status === 'ACTIVE' ? s : null;
      },
      findUnique: async ({ where }) => sessions.get(where.id) ?? null,
      updateMany: async ({ where, data }) => {
        const s = sessions.get(where.id);
        if (!s || s.status !== 'ACTIVE') return { count: 0 };
        sessions.set(where.id, { ...s, ...data });
        return { count: 1 };
      },
      update: async ({ where, data }) => {
        const s = sessions.get(where.id);
        sessions.set(where.id, { ...s, ...data });
        return sessions.get(where.id);
      },
    },
    refreshToken: {
      create: async ({ data }) => {
        refreshTokens.set(data.token_hash, { ...data });
        return data;
      },
      findUnique: async ({ where }) => {
        const rt = refreshTokens.get(where.token_hash);
        if (!rt) return null;
        const sess = sessions.get(rt.auth_session_id);
        return {
          ...rt,
          auth_sessions: {
            ...sess,
            users: { status: 'ACTIVE', locked_until: null },
          },
        };
      },
      updateMany: async ({ where, data }) => {
        let count = 0;
        for (const [hash, rt] of refreshTokens.entries()) {
          const matchId = where.id === undefined || rt.id === where.id;
          const matchFamily =
            where.token_family_id === undefined || rt.token_family_id === where.token_family_id;
          const matchUnused = where.used_at !== null || !rt.used_at;
          const matchUnrevoked = where.revoked_at !== null || !rt.revoked_at;
          if (matchId && matchFamily && matchUnused && matchUnrevoked) {
            refreshTokens.set(hash, { ...rt, ...data });
            count += 1;
          }
        }
        return { count };
      },
    },
    securityAlert: { findMany: async () => [] },
    accessSession: { findFirst: async () => ({ id: 'known-device' }) },
    mfaMethod: { count: async () => 1 },
    $transaction: async (fn) => fn(mockDb),
  };

  const initialSessionId = randomUUID();
  const initialFamilyId = randomUUID();
  await completeAuthLoginSession(
    mockDb,
    {
      userId: 10n,
      sessionId: initialSessionId,
      familyId: initialFamilyId,
      sessionExpiresAt: new Date(Date.now() + 3600_000),
      mfaVerified: false,
      context: {
        ip: '10.0.0.10',
        userAgent: 'CorpChrome/128.0',
        correlationId: 'c-login',
      },
    },
    async () => {},
  );

  // 1. Upgrade to MFA session -> must inherit login_ip_address & login_user_agent
  const mfaRefreshHash = 'a'.repeat(64);
  const rotatedSessionId = await activateMfaAuthSession(mockDb, initialSessionId, 10n, {
    id: randomUUID(),
    hash: mfaRefreshHash,
    expiresAt: new Date(Date.now() + 86_400_000),
  });
  assert.ok(rotatedSessionId);
  assert.equal(sessions.get(rotatedSessionId).login_ip_address, '10.0.0.10');
  assert.equal(sessions.get(rotatedSessionId).login_user_agent, 'CorpChrome/128.0');

  // 2. AuthGuard touches activity with drifted IP, and /auth/refresh updates latest ip_address & user_agent
  await touchAuthSessionActivity(mockDb, rotatedSessionId, 10n, new Date(), '10.0.0.99');
  const nextRefreshHash = 'b'.repeat(64);
  const rotRes = await rotateSessionRefreshToken(
    mockDb,
    mfaRefreshHash,
    { id: randomUUID(), hash: nextRefreshHash, expiresAt: new Date(Date.now() + 86_400_000) },
    async () => ({
      id: 10n,
      username: 'reader',
      email: 'reader@test.local',
      passwordHash: 'h',
      fullName: 'Reader',
      status: 'ACTIVE',
      lockedUntil: null,
      failedLoginCount: 0,
      roles: ['DOCUMENT_READER'],
      requiresMfa: true,
      mfaMethod: { id: 'm1', encryptedSecret: 'e', recoveryCodeHashes: [] },
    }),
    { ipAddress: '10.0.0.99', userAgent: 'DriftedFirefox/130.0' },
  );
  assert.equal(rotRes.kind, 'rotated');
  // Latest activity trace updated for /sessions:
  assert.equal(sessions.get(rotatedSessionId).ip_address, '10.0.0.99');
  assert.equal(sessions.get(rotatedSessionId).user_agent, 'DriftedFirefox/130.0');
  // Immutable login baseline preserved:
  assert.equal(sessions.get(rotatedSessionId).login_ip_address, '10.0.0.10');
  assert.equal(sessions.get(rotatedSessionId).login_user_agent, 'CorpChrome/128.0');

  // 3. PEP & SessionPosture detect BOTH SESSION_IP_DRIFT (+25) and SESSION_UA_DRIFT (+15) = 40
  const cfg = new AppConfigService({ ABAC_TRUSTED_NETWORK_CIDRS: '10.0.0.0/8' });
  const principal = {
    userId: 10n,
    sessionId: rotatedSessionId,
    username: 'reader',
    roles: ['DOCUMENT_READER'],
    mfa: true,
  };
  const driftedCtx = {
    ip: '10.0.0.99',
    userAgent: 'DriftedFirefox/130.0',
    correlationId: 'c-pep',
  };
  const pepRisk = await evaluatePepSessionRisk({
    database: mockDb,
    principal,
    context: driftedCtx,
    trustedNetwork: true,
    classificationRank: 2,
    deviceFingerprint: 'dfp-1234567890abcdef',
    now: BUSINESS_HOURS,
  });
  assert.equal(pepRisk.riskScore, 40);
  assert.deepEqual(pepRisk.factors, ['SESSION_IP_DRIFT', 'SESSION_UA_DRIFT']);

  const posture = await evaluateSessionSecurityPosture({
    database: mockDb,
    config: cfg,
    principal,
    context: driftedCtx,
    deviceFingerprint: 'dfp-1234567890abcdef',
    now: BUSINESS_HOURS,
  });
  assert.equal(posture.riskScore, 40);
  assert.deepEqual(posture.riskFactors, ['SESSION_IP_DRIFT', 'SESSION_UA_DRIFT']);
});

test('BUG-043 — AuthorizationCache bumps generation on Pub/Sub invalidation and blocks stale DB reads from poisoning L1/L2 under new epochs (with Lua CAS & no-eval fallback)', async () => {
  // 1. In-memory state store: external Pub/Sub epoch bump increments generation and rejects stale cache.set
  const cfg = new AppConfigService({ NODE_ENV: 'test' });
  const stateStore = new DistributedStateService(cfg);
  const cache = new AuthorizationCache(cfg, stateStore);

  let dbAssignments = [
    {
      scope_department_id: null,
      valid_to: null,
      roles: {
        id: 2n,
        code: 'DOCUMENT_OWNER',
        role_permissions: [
          {
            permissions: {
              id: 10n,
              code: 'DOCUMENT_UPLOAD',
              resource_type: 'DOCUMENT',
              action: 'UPLOAD',
            },
          },
        ],
      },
    },
  ];

  let releaseSlowQuery;
  const slowQueryEntered = new Promise((resolve) => {
    releaseSlowQuery = resolve;
  });
  let resumeDbReturn;
  const allowDbReturn = new Promise((resolve) => {
    resumeDbReturn = resolve;
  });

  const authzService = new AuthorizationService(cache);
  authzService.database = {
    userRole: {
      findMany: async () => {
        const snapshot = [...dbAssignments];
        releaseSlowQuery();
        await allowDbReturn;
        return snapshot;
      },
    },
  };

  // Start slow request reading old permissions BEFORE revocation
  const slowRequestPromise = authzService.effectiveGrants(42n);
  await slowQueryEntered;

  // Concurrent revocation on another pod bumps rbac-user:42 epoch via stateStore
  const genBefore = cache.currentGeneration();
  dbAssignments = [];
  await stateStore.bumpNamespaceEpoch('rbac-user:42');
  assert.equal(cache.currentGeneration(), genBefore + 1);

  // Allow slow request to finish -> must NOT poison L1 or L2 cache with revoked permission!
  resumeDbReturn();
  await slowRequestPromise;
  assert.equal(await cache.get(42n), undefined);

  // 2. Custom Redis mock WITHOUT eval (fallback path) AND simulated delayed Pub/Sub: epoch mismatch still aborts L2 write
  const redisKv = new Map([
    ['sda:epoch:rbac-global', '1'],
    ['sda:epoch:rbac-user:99', '2'],
  ]);
  const noEvalRedisMock = {
    mget: async (...keys) => keys.map((k) => redisKv.get(k) ?? null),
    get: async (k) => redisKv.get(k) ?? null,
    set: async (k, v) => {
      redisKv.set(k, v);
      return 'OK';
    },
    incr: async (k) => {
      const next = Number(redisKv.get(k) ?? '0') + 1;
      redisKv.set(k, String(next));
      return next;
    },
    pexpire: async () => 1,
    del: async (k) => (redisKv.delete(k) ? 1 : 0),
    disconnect: () => {},
  };
  const customStore = new DistributedStateService(cfg, noEvalRedisMock);
  const podACache = new AuthorizationCache(cfg, customStore);
  const staleStamp = await podACache.captureStamp(99n);
  assert.deepEqual(staleStamp, { generation: 0, globalEpoch: 1, userEpoch: 2 });

  // Simulate Pod B bumping Redis epoch directly before Pub/Sub reaches Pod A (so Pod A generation is still 0!)
  redisKv.set('sda:epoch:rbac-user:99', '3');
  await podACache.set(
    99n,
    [
      {
        permissionId: 1n,
        code: 'USER_MANAGE',
        resource: 'USER',
        action: 'MANAGE',
        roleId: 1n,
        roleCode: 'SYSTEM_ADMIN',
        scopeDepartmentId: null,
        validTo: null,
      },
    ],
    60_000,
    Date.now(),
    staleStamp,
  );
  assert.equal(redisKv.get('sda:state:rbac-grants:99'), undefined);
  assert.equal(await podACache.get(99n), undefined);
});

test('BUG-044 — normal session expiration/logout refresh produces zero false REFRESH_TOKEN_REUSE alerts, true replay & repeat REFRESH_REUSE still alert, and all revoke/expire branches invalidate cache', async () => {
  const alerts = [];
  const invalidated = [];
  let tokenRow = null;
  let sessionRow = null;

  const mockDb = {
    refreshToken: {
      findUnique: async () =>
        tokenRow
          ? {
              ...tokenRow,
              auth_sessions: sessionRow,
            }
          : null,
      updateMany: async ({ data }) => {
        if (tokenRow) tokenRow = { ...tokenRow, ...data };
        return { count: 1 };
      },
    },
    authSession: {
      findFirst: async () => sessionRow,
      updateMany: async ({ data }) => {
        if (sessionRow) sessionRow = { ...sessionRow, ...data };
        return { count: 1 };
      },
    },
    detectionRuleConfig: { findUnique: async () => null },
    securityAlert: {
      findFirst: async () => null,
      create: async ({ data }) => {
        alerts.push(data);
        return data;
      },
    },
    $transaction: async (fn) => fn(mockDb),
  };

  const repo = new AuthRepository(makeAuthConfig());
  repo.database = mockDb;
  repo.invalidateSessionCache = async (uid, sid) => {
    invalidated.push({ uid, sid });
  };
  repo.findUserById = async () => ({
    id: 7n,
    username: 'u7',
    email: 'u7@test.local',
    passwordHash: 'h',
    fullName: 'U7',
    status: 'ACTIVE',
    lockedUntil: null,
    failedLoginCount: 0,
    roles: ['DOCUMENT_READER'],
    requiresMfa: false,
    mfaMethod: null,
  });

  const now = new Date();
  const future = new Date(now.getTime() + 3600_000);

  // 1. Revoked due to normal reasons (IDLE_SESSION_EXPIRED, USER_LOGOUT, PASSWORD_CHANGED, MAX_CONCURRENT_SESSIONS_EXCEEDED) -> kind: 'invalid', 0 alerts!
  for (const reason of [
    'IDLE_SESSION_EXPIRED',
    'USER_LOGOUT',
    'PASSWORD_CHANGED',
    'MAX_CONCURRENT_SESSIONS_EXCEEDED',
  ]) {
    sessionRow = {
      id: 'sess-normal',
      user_id: 7n,
      token_family_id: 'fam-1',
      status: 'REVOKED',
      expires_at: future,
      last_seen_at: now,
      users: { status: 'ACTIVE', locked_until: null },
    };
    tokenRow = {
      id: 'rt-1',
      token_family_id: 'fam-1',
      token_hash: 'c'.repeat(64),
      used_at: null,
      revoked_at: now,
      revocation_reason: reason,
      expires_at: future,
    };
    const res = await repo.rotateRefreshToken('c'.repeat(64), {
      id: randomUUID(),
      hash: 'd'.repeat(64),
      expiresAt: future,
    });
    assert.equal(res.kind, 'invalid');
  }
  assert.equal(alerts.length, 0, 'Normal session revocations must NOT trigger SOC alerts');
  assert.equal(
    invalidated.length,
    4,
    'Every non-rotated session branch must invalidate session cache',
  );

  // 2. Disabled and Locked branches also call invalidateSessionCache
  invalidated.length = 0;
  sessionRow = {
    id: 'sess-disabled',
    user_id: 7n,
    token_family_id: 'fam-2',
    status: 'ACTIVE',
    expires_at: future,
    last_seen_at: now,
    users: { status: 'DISABLED', locked_until: null },
  };
  tokenRow = {
    id: 'rt-2',
    token_family_id: 'fam-2',
    token_hash: 'e'.repeat(64),
    used_at: null,
    revoked_at: null,
    revocation_reason: null,
    expires_at: future,
  };
  assert.equal(
    (
      await repo.rotateRefreshToken('e'.repeat(64), {
        id: randomUUID(),
        hash: 'f'.repeat(64),
        expiresAt: future,
      })
    ).kind,
    'disabled',
  );
  assert.equal(invalidated.length, 1);

  // 3. Genuine ROTATED replay AND repeat REFRESH_REUSE attempt BOTH return kind: 'reuse' & alert SOC
  sessionRow = {
    id: 'sess-stolen',
    user_id: 7n,
    token_family_id: 'fam-3',
    status: 'ACTIVE',
    expires_at: future,
    last_seen_at: now,
    users: { status: 'ACTIVE', locked_until: null },
  };
  tokenRow = {
    id: 'rt-3',
    token_family_id: 'fam-3',
    token_hash: '1'.repeat(64),
    used_at: now,
    revoked_at: now,
    revocation_reason: 'ROTATED',
    expires_at: future,
  };
  const firstTheft = await repo.rotateRefreshToken('1'.repeat(64), {
    id: randomUUID(),
    hash: '2'.repeat(64),
    expiresAt: future,
  });
  assert.equal(firstTheft.kind, 'reuse');
  assert.equal(alerts.length, 1);

  // Second attempt on sibling token in the already REFRESH_REUSE-revoked family (used_at: null, revocation_reason: 'REFRESH_REUSE')
  tokenRow = {
    id: 'rt-3-sibling',
    token_family_id: 'fam-3',
    token_hash: '3'.repeat(64),
    used_at: null,
    revoked_at: now,
    revocation_reason: 'REFRESH_REUSE',
    expires_at: future,
  };
  const secondTheft = await repo.rotateRefreshToken('3'.repeat(64), {
    id: randomUUID(),
    hash: '4'.repeat(64),
    expiresAt: future,
  });
  assert.equal(secondTheft.kind, 'reuse');
  assert.equal(alerts.length, 2);
});

test('BUG-045 — password reset blocks LOCKED/PENDING/locked_until accounts with constant 1250ms anti-enumeration floor, bumps version atomically, and Admin lock/disable revokes unused reset tokens', async () => {
  let sentEmails = 0;
  let createdResetTokens = 0;
  const futureLock = new Date(Date.now() + 600_000);

  const lockedUser = {
    id: 15n,
    username: 'locked.staff',
    email: 'locked@test.local',
    passwordHash: 'h',
    fullName: 'Locked Staff',
    status: 'ACTIVE',
    lockedUntil: futureLock,
    failedLoginCount: 6,
    roles: ['DOCUMENT_READER'],
    mfaMethod: null,
  };

  // 1. executeForgotPassword silently skips lockedUntil > now without throwing 403 and waits >= 1250ms floor
  const startedAt = Date.now();
  const res = await executeForgotPassword(
    {
      repository: {
        findUserByIdentifier: async () => lockedUser,
        createPasswordReset: async () => {
          createdResetTokens += 1;
        },
      },
      passwords: { burnEquivalentWork: async () => {} },
      tokens: new TokenService(makeAuthConfig()),
      rateLimit: new LoginRateLimitService(makeAuthConfig()),
      audit: { record: async () => {} },
      mailer: {
        send: async () => {
          sentEmails += 1;
        },
      },
      resetTtl: 900,
    },
    'locked.staff',
    { ip: '198.51.100.77', correlationId: 'c-reset-1' },
  );
  const elapsed = Date.now() - startedAt;
  assert.equal(res.message, GENERIC_RESET_RESPONSE);
  assert.equal(sentEmails, 0);
  assert.equal(createdResetTokens, 0);
  assert.ok(elapsed >= 1200, `Expected anti-enumeration floor ~1250ms, got ${elapsed}ms`);

  // 2. consumeUserPasswordReset blocks LOCKED, PENDING, and ACTIVE with locked_until > now, and bumps version on eligible ACTIVE
  let currentStatus = 'LOCKED';
  let currentLockedUntil = futureLock;
  let userVersion = 4;
  let tokenUsedAt = null;
  const resetDb = {
    passwordResetToken: {
      findUnique: async () => ({
        id: 'prt-1',
        user_id: 15n,
        token_hash: '9'.repeat(64),
        used_at: tokenUsedAt,
        expires_at: new Date(Date.now() + 600_000),
        users: {
          id: 15n,
          username: 'locked.staff',
          email: 'locked@test.local',
          status: currentStatus,
          locked_until: currentLockedUntil,
        },
      }),
      updateMany: async ({ data }) => {
        if (tokenUsedAt) return { count: 0 };
        tokenUsedAt = data.used_at;
        return { count: 1 };
      },
    },
    user: {
      updateMany: async ({ where, data }) => {
        if (currentStatus !== where.status) return { count: 0 };
        if (currentLockedUntil && currentLockedUntil > new Date()) return { count: 0 };
        currentLockedUntil = data.locked_until;
        userVersion += data.version?.increment ?? 0;
        return { count: 1 };
      },
    },
    authSession: { findMany: async () => [] },
    $transaction: async (fn) => fn(resetDb),
  };

  for (const [st, lock] of [
    ['LOCKED', null],
    ['PENDING', null],
    ['ACTIVE', futureLock],
  ]) {
    currentStatus = st;
    currentLockedUntil = lock;
    assert.equal(await findPasswordResetTokenOwner(resetDb, '9'.repeat(64)), null);
    assert.equal(await consumeUserPasswordReset(resetDb, '9'.repeat(64), 'new-hash'), null);
    assert.equal(tokenUsedAt, null);
  }

  // Eligible ACTIVE user with expired lock -> succeeds and increments version
  currentStatus = 'ACTIVE';
  currentLockedUntil = new Date(Date.now() - 1_000);
  assert.equal(await consumeUserPasswordReset(resetDb, '9'.repeat(64), 'new-hash'), 15n);
  assert.equal(userVersion, 5);

  // 3. Admin locking account revokes unused password_reset_tokens
  let resetTokensRevoked = 0;
  const lockTx = {
    user: {
      findUnique: async () => ({
        id: 15n,
        department_id: 1n,
        status: 'ACTIVE',
        version: 5,
        username: 'u',
        full_name: 'U',
      }),
      findUniqueOrThrow: async () => ({
        id: 15n,
        department_id: 1n,
        status: 'LOCKED',
        version: 6,
        username: 'u',
        full_name: 'U',
      }),
      updateMany: async () => ({ count: 1 }),
    },
    userRole: { count: async () => 0, findMany: async () => [] },
    passwordResetToken: {
      updateMany: async ({ where, data }) => {
        if (where.user_id === 15n && where.used_at === null && data.used_at instanceof Date) {
          resetTokensRevoked += 1;
        }
        return { count: 1 };
      },
    },
    refreshToken: { updateMany: async () => ({ count: 0 }) },
    authSession: { updateMany: async () => ({ count: 0 }) },
    accessSession: { updateMany: async () => ({ count: 0 }) },
  };
  await executeChangeUserStatus({
    database: { $transaction: async (fn) => fn(lockTx) },
    authorization: {
      effectiveGrants: async () => [
        {
          permissionId: 1n,
          code: 'USER_MANAGE',
          resource: 'USER',
          action: 'MANAGE',
          roleId: 1n,
          roleCode: 'SYSTEM_ADMIN',
          scopeDepartmentId: null,
          validTo: null,
        },
      ],
      hasPermission: async () => true,
      invalidateUser: async () => {},
    },
    audit: { record: async () => {} },
    principal: {
      userId: 1n,
      sessionId: 's-admin',
      username: 'admin',
      roles: ['SYSTEM_ADMIN'],
      mfa: true,
    },
    id: 15n,
    expectedVersion: 5,
    status: 'LOCKED',
    action: 'USER_LOCKED',
    context: { ip: '10.0.0.1', correlationId: 'c-lock' },
  });
  assert.equal(resetTokensRevoked, 1);
});

test('BUG-046 — MFA enrollment revokes other unverified sessions while protecting enrolling /mfa tab (excludeSessionId: rotatedSessionId), and /auth/refresh rejects unverified sessions when MFA is enabled', async () => {
  const cfg = makeAuthConfig();
  const passwords = new PasswordService();
  const tokens = new TokenService(cfg);
  const mfa = new MfaService(cfg);
  const enrollment = mfa.createEnrollment('owner@corp.test');
  const totp = new OTPAuth.TOTP({
    issuer: 'Secure Document Access',
    label: 'owner@corp.test',
    secret: OTPAuth.Secret.fromBase32(enrollment.secret),
  });

  const enrollingOldSessionId = '11111111-1111-4111-8111-000000000001';
  const rotatedNewSessionId = '11111111-1111-4111-8111-000000000002';
  const otherDeviceSessionId = '11111111-1111-4111-8111-000000000099';

  const realtime = new RealtimeEventsService();
  const closedSockets = [];
  // Register SSE client 1: enrolling tab on /mfa (opened with enrollingOldSessionId before rotation)
  realtime.registerClient({
    userId: '25',
    sessionId: enrollingOldSessionId,
    roles: ['DOCUMENT_OWNER'],
    writeFrame: () => true,
    close: () => closedSockets.push('enrolling-tab-old-sid'),
  });
  // Register SSE client 2: post-upgrade session ID
  realtime.registerClient({
    userId: '25',
    sessionId: rotatedNewSessionId,
    roles: ['DOCUMENT_OWNER'],
    writeFrame: () => true,
    close: () => closedSockets.push('enrolling-tab-rotated-sid'),
  });
  // Register SSE client 3: another browser logged in earlier without MFA
  realtime.registerClient({
    userId: '25',
    sessionId: otherDeviceSessionId,
    roles: ['DOCUMENT_OWNER'],
    writeFrame: () => true,
    close: () => closedSockets.push('other-unverified-device'),
  });

  let excludeArgPassedToRepo = null;
  let capturedPublish = null;
  const origPublish = realtime.publish.bind(realtime);
  realtime.publish = (input) => {
    capturedPublish = input;
    return origPublish(input);
  };

  const repository = {
    getActiveMfaMethods: async () => [],
    pendingMfaMethod: async () => ({
      id: 'mfa-pending',
      encryptedSecret: enrollment.encryptedSecret,
    }),
    enableMfa: async () => {},
    activateMfaSession: async () => rotatedNewSessionId,
    findUserById: async () => ({ id: 25n, profile: null }),
    revokeOtherUnverifiedMfaSessions: async (_uid, excludeSid) => {
      excludeArgPassedToRepo = excludeSid;
      return {
        revokedCount: 1,
        revokedSessionIds: [otherDeviceSessionId],
        preservedSessionIds: [],
      };
    },
  };

  const authService = new AuthService(
    repository,
    passwords,
    tokens,
    mfa,
    new LoginRateLimitService(cfg),
    { record: async () => {} },
    {},
    cfg,
    undefined,
    undefined,
    realtime,
  );

  const enrolled = await authService.verifyMfaEnrollment(
    {
      userId: 25n,
      sessionId: enrollingOldSessionId,
      username: 'owner',
      roles: ['DOCUMENT_OWNER'],
      mfa: false,
    },
    totp.generate(),
    { ip: '10.0.0.5', correlationId: 'c-mfa-enroll' },
  );
  assert.equal(enrolled.recoveryCodes.length, 10);
  assert.equal(excludeArgPassedToRepo, rotatedNewSessionId);
  assert.equal(capturedPublish.type, 'USER_SESSION_REVOKED');
  assert.equal(capturedPublish.excludeSessionId, rotatedNewSessionId);
  // CRITICAL UI INVARIANT: Only the other unverified device is disconnected; enrolling tab stays alive to copy recoveryCodes!
  assert.deepEqual(closedSockets, ['other-unverified-device']);
  realtime.onModuleDestroy();

  // Also verify rotateSessionRefreshToken immediately revokes mfa_verified_at === null session when user has MFA enabled
  let revokedReason = null;
  const refreshDb = {
    refreshToken: {
      findUnique: async () => ({
        id: 'rt-unverified',
        token_family_id: 'fam-unverified',
        token_hash: '7'.repeat(64),
        used_at: null,
        revoked_at: null,
        revocation_reason: null,
        expires_at: new Date(Date.now() + 3600_000),
        auth_sessions: {
          id: otherDeviceSessionId,
          user_id: 25n,
          token_family_id: 'fam-unverified',
          status: 'ACTIVE',
          mfa_verified_at: null,
          last_seen_at: new Date(),
          expires_at: new Date(Date.now() + 3600_000),
          users: { status: 'ACTIVE', locked_until: null },
        },
      }),
      updateMany: async ({ data }) => {
        revokedReason = data.revocation_reason;
        return { count: 1 };
      },
    },
    authSession: { updateMany: async () => ({ count: 1 }) },
    $transaction: async (fn) => fn(refreshDb),
  };
  const blockedRefresh = await rotateSessionRefreshToken(
    refreshDb,
    '7'.repeat(64),
    { id: randomUUID(), hash: '8'.repeat(64), expiresAt: new Date(Date.now() + 3600_000) },
    async () => ({
      id: 25n,
      username: 'owner',
      email: 'owner@corp.test',
      passwordHash: 'h',
      fullName: 'Owner',
      status: 'ACTIVE',
      lockedUntil: null,
      failedLoginCount: 0,
      roles: ['DOCUMENT_OWNER'],
      requiresMfa: true,
      mfaMethod: { id: 'mfa-active', encryptedSecret: 'enc', recoveryCodeHashes: [] },
    }),
  );
  assert.equal(blockedRefresh.kind, 'invalid');
  assert.equal(revokedReason, 'MFA_REQUIRED_UNVERIFIED_SESSION');
});

test('BUG-047 — enforces all 4 RBAC/Clearance cascade scenarios (custom privileged PEP block, clearance floor on ROLE grant assignment, role-revoke session termination, and ROLE grant + PENDING request cascade on clearance downgrade)', async () => {
  const now = new Date();

  // 1. Custom privileged role blocked at PEP (both via principal flag and live DB capability lookup)
  assert.equal(
    isRestrictedNonBusinessRole(
      ['CUSTOM_SOC_LEAD'],
      [{ code: 'ALERT_MANAGE', resource_type: 'SECURITY_ALERT', action: 'MANAGE' }],
    ),
    true,
  );
  const pep = new DocumentPepService(
    { evaluate: async () => ({ decision: 'PERMIT', obligations: [] }) },
    {},
    { record: async () => {} },
    {
      userRole: {
        findMany: async () => [
          {
            roles: {
              code: 'CUSTOM_SOC_LEAD',
              role_permissions: [
                {
                  permissions: {
                    code: 'ALERT_MANAGE',
                    resource_type: 'SECURITY_ALERT',
                    action: 'MANAGE',
                  },
                },
              ],
            },
          },
        ],
      },
    },
    new AppConfigService({ NODE_ENV: 'test' }),
  );
  await assert.rejects(
    () =>
      pep.enforceAccess(
        randomUUID(),
        {
          userId: 60n,
          sessionId: 's-60',
          username: 'soc.custom',
          roles: ['CUSTOM_SOC_LEAD'],
          mfa: true,
        },
        { ip: '10.0.0.1', correlationId: 'c-pep-sod' },
        { action: 'VIEW', now },
      ),
    ForbiddenException,
  );

  // 2. Assigning low-clearance user (rank 1) to Role holding SECRET (rank 3) ROLE grant -> blocked 409 without revoking Role grant
  const sysAdmin = {
    userId: 1n,
    sessionId: 's-1',
    username: 'sys',
    roles: ['SYSTEM_ADMIN'],
    mfa: true,
  };
  const sysAuthz = {
    effectiveGrants: async () => [
      {
        permissionId: 1n,
        code: 'ROLE_MANAGE',
        resource: 'ROLE',
        action: 'MANAGE',
        roleId: 1n,
        roleCode: 'SYSTEM_ADMIN',
        scopeDepartmentId: null,
        validTo: null,
      },
      {
        permissionId: 2n,
        code: 'USER_MANAGE',
        resource: 'USER',
        action: 'MANAGE',
        roleId: 1n,
        roleCode: 'SYSTEM_ADMIN',
        scopeDepartmentId: null,
        validTo: null,
      },
    ],
    assertPermission: async () => {},
    departmentWithinScope: async () => true,
    invalidateUser: async () => {},
  };
  let userClearanceRank = 1;
  const assignLowClearanceTx = {
    user: { findUnique: async () => ({ id: 70n, status: 'ACTIVE', department_id: 10n }) },
    role: {
      findFirst: async () => ({
        id: 12n,
        code: 'RND_READERS',
        is_active: true,
        role_permissions: [
          {
            permission_id: 50n,
            permissions: {
              id: 50n,
              code: 'DOCUMENT_VIEW',
              resource_type: 'DOCUMENT',
              action: 'VIEW',
            },
          },
        ],
      }),
    },
    userRole: {
      findMany: async () => [],
      create: async ({ data }) => ({ id: 800n, ...data }),
    },
    accessGrant: {
      findMany: async () => [
        {
          id: 'role-grant-secret',
          principal_type: 'ROLE',
          principal_role_id: 12n,
          status: 'ACTIVE',
          documents: { classification_history: [{ classification_levels: { rank: 3 } }] },
        },
      ],
    },
    userAttributeAssignment: {
      findFirst: async () => ({
        attribute_definitions: { is_active: true },
        attribute_options: {
          id: 1n,
          value_code: 'INTERNAL',
          display_name: 'Nội bộ',
          numeric_rank: userClearanceRank,
          is_active: true,
        },
      }),
    },
  };
  await assert.rejects(
    () =>
      executeAssignUserRole(
        sysAuthz,
        { record: async () => {} },
        sysAdmin,
        70n,
        { roleId: 12n, scopeDepartmentId: null, validFrom: now, validTo: null },
        { ip: '10.0.0.1', correlationId: 'c-low-clr' },
        { $transaction: async (fn) => fn(assignLowClearanceTx) },
      ),
    ConflictException,
  );
  userClearanceRank = 3;
  const assignedAfterUpgrade = await executeAssignUserRole(
    sysAuthz,
    { record: async () => {} },
    sysAdmin,
    70n,
    { roleId: 12n, scopeDepartmentId: null, validFrom: now, validTo: null },
    { ip: '10.0.0.1', correlationId: 'c-ok-clr' },
    { $transaction: async (fn) => fn(assignLowClearanceTx) },
  );
  assert.equal(assignedAfterUpgrade.id, '800');

  // 3. Revoking Role from user terminates ACTIVE AccessSessions opened via that Role's ROLE grants
  let terminatedRoleSessionArgs = null;
  const revokeRoleTx = {
    userRole: {
      findFirst: async () => ({
        id: 800n,
        user_id: 70n,
        role_id: 12n,
        scope_department_id: null,
        valid_from: new Date(now.getTime() - 60_000),
        valid_to: null,
        roles: { code: 'RND_READERS', is_active: true, role_permissions: [] },
      }),
      findMany: async () => [],
      count: async () => 0,
      update: async ({ data }) => ({
        id: 800n,
        user_id: 70n,
        role_id: 12n,
        scope_department_id: null,
        valid_from: new Date(now.getTime() - 60_000),
        valid_to: data.valid_to,
      }),
    },
    user: { findUniqueOrThrow: async () => ({ id: 70n, department_id: 10n, status: 'ACTIVE' }) },
    accessGrant: { findMany: async () => [{ id: 'role-grant-secret' }] },
    accessSession: {
      updateMany: async (args) => {
        terminatedRoleSessionArgs = args;
        return { count: 1 };
      },
    },
  };
  await executeRevokeUserRole(
    sysAuthz,
    { record: async () => {} },
    sysAdmin,
    70n,
    800n,
    { ip: '10.0.0.1', correlationId: 'c-rev-role' },
    { $transaction: async (fn) => fn(revokeRoleTx) },
  );
  assert.deepEqual(terminatedRoleSessionArgs?.where, {
    user_id: 70n,
    status: 'ACTIVE',
    access_grant_id: { in: ['role-grant-secret'] },
  });
  assert.equal(terminatedRoleSessionArgs?.data?.status, 'TERMINATED');
  assert.ok(terminatedRoleSessionArgs?.data?.ended_at instanceof Date);

  // 4. Downgrading user clearance revokes ROLE grants (with revoked_by/revoked_at/revoke_reason) AND cancels PENDING AccessRequests above newRank
  const revokedGrants = [];
  const cancelledRequests = [];
  const downgradeTx = {
    attributeDefinition: { findUnique: async () => ({ id: 1n, is_active: true }) },
    attributeOption: {
      findFirst: async () => ({
        id: 1n,
        value_code: 'INTERNAL',
        display_name: 'Nội bộ',
        numeric_rank: 1,
      }),
    },
    userAttributeAssignment: {
      findMany: async () => [
        {
          id: 500n,
          option_id: 3n,
          valid_from: new Date(now.getTime() - 60_000),
          valid_to: null,
          attribute_options: {
            id: 3n,
            value_code: 'SECRET',
            display_name: 'Tối mật',
            numeric_rank: 3,
            is_active: true,
          },
        },
      ],
      updateMany: async () => ({ count: 1 }),
      create: async ({ data }) => ({ id: 501n, ...data }),
    },
    userRole: { findMany: async () => [{ role_id: 12n }] },
    accessGrant: {
      findMany: async ({ where }) => {
        if (where.principal_type === 'ROLE') {
          return [
            {
              id: 'rg-secret',
              principal_type: 'ROLE',
              principal_role_id: 12n,
              status: 'ACTIVE',
              documents: { classification_history: [{ classification_levels: { rank: 3 } }] },
            },
          ];
        }
        return [];
      },
      update: async ({ where, data }) => {
        assert.ok(data.revoked_by && data.revoked_at && data.revoke_reason);
        revokedGrants.push(where.id);
        return { id: where.id, ...data };
      },
    },
    accessSession: {
      findMany: async () => [],
      updateMany: async () => ({ count: 1 }),
    },
    accessRequest: {
      findMany: async () => [
        {
          id: 'req-secret',
          documents: { classification_history: [{ classification_levels: { rank: 3 } }] },
        },
        {
          id: 'req-internal',
          documents: { classification_history: [{ classification_levels: { rank: 1 } }] },
        },
      ],
      updateMany: async ({ where, data }) => {
        assert.equal(data.status, 'CANCELLED');
        assert.ok(data.cancelled_at instanceof Date);
        cancelledRequests.push(...where.id.in);
        return { count: where.id.in.length };
      },
    },
  };
  const downgradeRes = await syncUserClearanceAssignment({
    transaction: downgradeTx,
    userId: 70n,
    clearanceOptionId: 1n,
    actorUserId: 1n,
    now,
  });
  assert.equal(downgradeRes.revokedGrantsCount, 1);
  assert.deepEqual(revokedGrants, ['rg-secret']);
  assert.deepEqual(cancelledRequests, ['req-secret']);
});

test('BUG-048 — N > pool_max concurrent SERIALIZABLE Users/RBAC mutations reuse TransactionClient with 0 extra pool connections (no self-deadlock)', async () => {
  // Simulate strict connection pool with max = 2 connections and N = 6 concurrent SERIALIZABLE mutations!
  const POOL_MAX = 2;
  let activeConnections = 0;
  let rootPoolQueriesWhileTxOpen = 0;
  const waitQueue = [];

  const acquire = async () => {
    if (activeConnections < POOL_MAX) {
      activeConnections += 1;
      return;
    }
    await new Promise((resolve) => waitQueue.push(resolve));
  };
  const release = () => {
    if (waitQueue.length > 0) {
      const next = waitQueue.shift();
      next();
    } else {
      activeConnections -= 1;
    }
  };

  let userVersion = 0;
  const makeQueryApi = (isRootPool) => ({
    $queryRaw: async () => {
      if (isRootPool && activeConnections > 0) rootPoolQueriesWhileTxOpen += 1;
      return [{ id: 1n }];
    },
    department: {
      findUnique: async () => {
        if (isRootPool && activeConnections > 0) rootPoolQueriesWhileTxOpen += 1;
        return { id: 1n, parent_id: null };
      },
      findFirst: async () => ({ id: 1n, is_active: true }),
    },
    user: {
      findUnique: async ({ where }) => ({
        id: where.id,
        username: `u${where.id}`,
        full_name: 'Staff',
        department_id: 1n,
        status: 'ACTIVE',
        version: userVersion,
      }),
      findUniqueOrThrow: async ({ where }) => ({
        id: where.id,
        username: `u${where.id}`,
        full_name: 'Staff Updated',
        department_id: 1n,
        status: 'ACTIVE',
        version: userVersion,
      }),
      updateMany: async () => {
        await new Promise((r) => setTimeout(r, 10));
        userVersion += 1;
        return { count: 1 };
      },
    },
    userRole: {
      findMany: async () => {
        if (isRootPool && activeConnections > 0) rootPoolQueriesWhileTxOpen += 1;
        return [
          {
            scope_department_id: null,
            valid_to: null,
            roles: {
              id: 1n,
              code: 'SYSTEM_ADMIN',
              role_permissions: [
                {
                  permissions: {
                    id: 1n,
                    code: 'USER_MANAGE',
                    resource_type: 'USER',
                    action: 'MANAGE',
                  },
                },
                {
                  permissions: {
                    id: 2n,
                    code: 'ROLE_MANAGE',
                    resource_type: 'ROLE',
                    action: 'MANAGE',
                  },
                },
              ],
            },
          },
        ];
      },
    },
    userAttributeAssignment: { findFirst: async () => null },
  });

  const txClient = makeQueryApi(false);
  const pooledDb = {
    ...makeQueryApi(true),
    $transaction: async (fn) => {
      await acquire();
      try {
        return await fn(txClient);
      } finally {
        release();
      }
    },
  };

  const cache = new AuthorizationCache(new AppConfigService({ NODE_ENV: 'test' }));
  const realAuthz = new AuthorizationService(cache);
  realAuthz.database = pooledDb;

  const principal = {
    userId: 1n,
    sessionId: 's-1',
    username: 'admin',
    roles: ['SYSTEM_ADMIN'],
    mfa: true,
  };
  const ctx = { ip: '10.0.0.1', correlationId: 'c-pool' };

  // Run 6 concurrent SERIALIZABLE updates on a pool of size 2 — if AuthorizationService acquired a 2nd connection from pooledDb, this would deadlock forever!
  await Promise.all(
    Array.from({ length: 6 }, (_, idx) =>
      executeUpdateUser({
        database: pooledDb,
        authorization: realAuthz,
        audit: { record: async () => {} },
        principal,
        id: BigInt(idx + 10),
        input: { expectedVersion: 0, fullName: `Staff ${idx}` },
        context: ctx,
      }),
    ),
  );
  assert.equal(
    rootPoolQueriesWhileTxOpen,
    0,
    'AuthorizationService must reuse open TransactionClient and make 0 root-pool queries inside withSerializableTransaction',
  );
});

test('BUG-049 — RbacAuditService, AbacAuditService, and AccessGrantAuditService do not retry on an open aborted TransactionClient (preventing 25P02 from masking 40001)', async () => {
  const cfg = new AppConfigService({ NODE_ENV: 'test' });
  const rbacAudit = new RbacAuditService(cfg);
  const abacAudit = new AbacAuditService(cfg);
  const grantAudit = new AccessGrantAuditService(cfg);
  const principal = {
    userId: 1n,
    sessionId: 's-1',
    username: 'admin',
    roles: ['SYSTEM_ADMIN'],
    mfa: true,
  };
  const ctx = { ip: '10.0.0.1', correlationId: randomUUID() };

  for (const [label, runAudit] of [
    [
      'RbacAuditService',
      (tx) =>
        rbacAudit.record(
          tx,
          { action: 'ROLE_UPDATED', objectType: 'ROLE', objectId: '1', before: null, after: null },
          principal,
          ctx,
        ),
    ],
    [
      'AbacAuditService',
      (tx) =>
        abacAudit.record(
          tx,
          {
            action: 'POLICY_UPDATED',
            objectType: 'POLICY',
            objectId: '1',
            outcome: 'SUCCESS',
            details: {},
          },
          principal,
          ctx,
        ),
    ],
    [
      'AccessGrantAuditService',
      (tx) =>
        grantAudit.record(
          { action: 'GRANT_REVOKED', outcome: 'SUCCESS', objectId: randomUUID() },
          principal,
          ctx,
          tx,
        ),
    ],
  ]) {
    let txAttempt = 0;
    const fakeDb = {
      $transaction: async (fn) => {
        txAttempt += 1;
        let aborted = false;
        const openTx = {
          $queryRawUnsafe: async () => {
            if (aborted) {
              const err25P02 = new Error('current transaction is aborted');
              err25P02.code = '25P02';
              throw err25P02;
            }
            if (txAttempt === 1) {
              aborted = true;
              const err40001 = new Error('could not serialize access due to concurrent update');
              err40001.code = '40001';
              throw err40001;
            }
            return [{ entry_hash: null, chain_sequence: 0n }];
          },
          auditLog: {
            create: async () => ({
              id: 1n,
              entry_hash: 'a'.repeat(64),
              chain_partition: 'TEST',
              chain_sequence: 1n,
            }),
          },
        };
        return fn(openTx);
      },
    };

    await withSerializableTransaction((tx) => runAudit(tx), {
      client: fakeDb,
      baseDelayMs: 1,
    });
    assert.equal(
      txAttempt,
      2,
      `${label} must propagate 40001 cleanly so withSerializableTransaction retries`,
    );
  }
});

test('BUG-050 — PolicyContradictionSolver handles multi-valued subject.projects, scalar IN/EQ intersections minus NEQ/NOT_IN, unified [lower, upper] bounds, and passes all 3 baseline seed policies', () => {
  // 1. Multi-valued array (subject.projects): multiple EQ is satisfiable, forbidden required element or exhausted IN is contradictory
  assert.equal(
    hasContradiction([
      { id: '1', attribute: 'subject.projects', operator: 'EQ', expected: 'PRJ-A' },
      { id: '2', attribute: 'subject.projects', operator: 'EQ', expected: 'PRJ-B' },
    ]),
    false,
  );
  assert.equal(
    hasContradiction([
      { id: '1', attribute: 'subject.projects', operator: 'EQ', expected: 'PRJ-A' },
      { id: '2', attribute: 'subject.projects', operator: 'NOT_IN', expected: ['PRJ-X', 'PRJ-A'] },
    ]),
    true,
  );
  assert.equal(
    hasContradiction([
      { id: '1', attribute: 'subject.projects', operator: 'IN', expected: ['PRJ-A', 'PRJ-B'] },
      { id: '2', attribute: 'subject.projects', operator: 'NEQ', expected: 'PRJ-A' },
      { id: '3', attribute: 'subject.projects', operator: 'NOT_IN', expected: ['PRJ-B', 'PRJ-C'] },
    ]),
    true,
  );

  // 2. Scalar discrete set intersection (IN ∩ IN ∩ EQ) \ (NEQ ∪ NOT_IN)
  assert.equal(
    hasContradiction([
      {
        id: '1',
        attribute: 'subject.employmentStatus',
        operator: 'IN',
        expected: ['ACTIVE', 'CONTRACTOR'],
      },
      { id: '2', attribute: 'subject.employmentStatus', operator: 'IN', expected: ['SUSPENDED'] },
    ]),
    true,
  );
  assert.equal(
    hasContradiction([
      {
        id: '1',
        attribute: 'subject.employmentStatus',
        operator: 'IN',
        expected: ['ACTIVE', 'CONTRACTOR'],
      },
      {
        id: '2',
        attribute: 'subject.employmentStatus',
        operator: 'IN',
        expected: ['CONTRACTOR', 'SUSPENDED'],
      },
      { id: '3', attribute: 'subject.employmentStatus', operator: 'NEQ', expected: 'CONTRACTOR' },
    ]),
    true,
  );

  // 3. Unified [lower, upper] bounds from GTE, LTE, BETWEEN, EQ + collapsed forbidden point + discrete allowedSet outside bounds
  assert.equal(
    hasContradiction([
      { id: '1', attribute: 'environment.riskScore', operator: 'BETWEEN', expected: [10, 50] },
      { id: '2', attribute: 'environment.riskScore', operator: 'GTE', expected: 60 },
    ]),
    true,
  );
  assert.equal(
    hasContradiction([
      { id: '1', attribute: 'environment.riskScore', operator: 'EQ', expected: 25 },
      { id: '2', attribute: 'environment.riskScore', operator: 'GTE', expected: 30 },
    ]),
    true,
  );
  assert.equal(
    hasContradiction([
      { id: '1', attribute: 'environment.riskScore', operator: 'GTE', expected: 40 },
      { id: '2', attribute: 'environment.riskScore', operator: 'LTE', expected: 40 },
      { id: '3', attribute: 'environment.riskScore', operator: 'NEQ', expected: 40 },
    ]),
    true,
  );
  assert.equal(
    hasContradiction([
      { id: '1', attribute: 'environment.riskScore', operator: 'IN', expected: [10, 20, 90] },
      { id: '2', attribute: 'environment.riskScore', operator: 'BETWEEN', expected: [30, 80] },
    ]),
    true,
  );
  assert.equal(
    hasContradiction([
      { id: '1', attribute: 'environment.riskScore', operator: 'IN', expected: [10, 50, 90] },
      { id: '2', attribute: 'environment.riskScore', operator: 'BETWEEN', expected: [30, 80] },
    ]),
    false,
  );

  // 4. Verify all 3 default seed rules in seed-catalog.ts pass validatePolicy cleanly
  const compiledSeed = compilePolicy(
    1n,
    ['SUBJECT_DEPARTMENT', 'EMPLOYMENT_STATUS'],
    baselineAbacPolicies.map((rule, idx) => ({
      id: BigInt(idx + 1),
      code: rule.code,
      effect: rule.effect,
      priority: rule.priority,
      targetResource: rule.target_resource,
      targetAction: rule.target_action,
      combiningAlgorithm: rule.combining_algorithm,
      obligations: [...rule.obligations],
      validFrom: new Date('2026-01-01T00:00:00.000Z'),
      validTo: null,
      conditions: rule.conditions.map((cond, cIdx) => ({
        id: BigInt(idx * 10 + cIdx + 1),
        definitionCode: null,
        group: cond.condition_group,
        sequence: cond.sequence_no,
        contextKey: cond.context_key,
        operator: cond.operator,
        expectedValue: Array.isArray(cond.expected_value)
          ? [...cond.expected_value]
          : cond.expected_value,
      })),
    })),
  );
  assert.deepEqual(validatePolicy(compiledSeed, CONTEXT_ATTRIBUTES), []);
});

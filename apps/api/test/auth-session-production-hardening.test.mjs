import 'reflect-metadata';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { Reflector } from '@nestjs/core';
import { resolveTrustProxyConfig, validateEnv } from '../dist/config/env.schema.js';
import { AuthGuard } from '../dist/modules/auth/auth.guard.js';
import {
  createAuthSession,
  rotateSessionRefreshToken,
} from '../dist/modules/auth/auth-session.repository.js';
import {
  MAX_LISTED_ACTIVE_SESSIONS,
  queryActiveUserSessions,
} from '../dist/modules/auth/auth-sessions-management.helper.js';
import { TokenService } from '../dist/modules/auth/token.service.js';
import { config } from './helpers/auth-security-mocks.mjs';

/**
 * Thuật toán: Kiểm Chứng Gia Cố Vòng Đời Phiên Production (`auth-session-production-hardening`)
 * Mục đích: Xác minh 5 bất biến vận hành thực tế:
 *   1. `queryActiveUserSessions` chặn trần `take` và lọc phiên vượt ngưỡng nhàn rỗi (`idleTtlSeconds`).
 *   2. `createAuthSession` cưỡng chế giới hạn số phiên đồng thời (`maxConcurrentSessions`) bằng cách thu hồi phiên cũ nhất.
 *   3. `rotateSessionRefreshToken` từ chối + đánh dấu `EXPIRED` phiên nhàn rỗi, đồng thời cập nhật IP/UA hợp lệ khi xoay vòng.
 *   4. `AuthGuard` cập nhật `last_seen_at` có điều tiết trên cùng IP và cập nhật ngay lập tức khi thiết bị đổi IP.
 *   5. `TRUST_PROXY` hỗ trợ kết hợp preset (`loopback,uniquelocal`) trong môi trường `production` mà vẫn chặn wildcard/hop.
 */

test('queryActiveUserSessions bounds take limit and excludes idle-expired sessions', async () => {
  let capturedArgs = null;
  const now = new Date('2026-11-25T12:00:00.000Z');
  const currentId = randomUUID();
  const mockDb = {
    authSession: {
      findMany: async (args) => {
        capturedArgs = args;
        return [
          {
            id: currentId,
            ip_address: '203.0.113.10',
            user_agent: 'Mozilla/5.0',
            created_at: new Date('2026-11-25T10:00:00.000Z'),
            last_seen_at: new Date('2026-11-25T11:55:00.000Z'),
            expires_at: new Date('2026-12-02T10:00:00.000Z'),
            mfa_verified_at: new Date('2026-11-25T10:01:00.000Z'),
          },
        ];
      },
    },
  };

  const sessions = await queryActiveUserSessions(mockDb, 11n, currentId, {
    idleTtlSeconds: 3600,
    now,
  });

  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].isCurrent, true);
  assert.equal(sessions[0].mfaVerified, true);
  assert.equal(capturedArgs.take, MAX_LISTED_ACTIVE_SESSIONS);
  assert.deepEqual(capturedArgs.where.last_seen_at, {
    gt: new Date('2026-11-25T11:00:00.000Z'),
  });

  // Explicit limit > 100 must still be clamped to 100
  await queryActiveUserSessions(mockDb, 11n, currentId, { limit: 999, now });
  assert.equal(capturedArgs.take, 100);
});

test('createAuthSession evicts oldest excess sessions when exceeding maxConcurrentSessions', async () => {
  const revokedSessionIds = [];
  const revokedFamilies = [];
  const createdSessions = [];
  const existing = [
    { id: 'sess-newest', token_family_id: 'fam-newest' },
    { id: 'sess-middle', token_family_id: 'fam-middle' },
    { id: 'sess-oldest', token_family_id: 'fam-oldest' },
  ];

  const tx = {
    authSession: {
      findMany: async () => existing,
      updateMany: async ({ where, data }) => {
        revokedSessionIds.push({ id: where.id, reason: data.revocation_reason });
        return { count: 1 };
      },
      create: async ({ data }) => {
        createdSessions.push(data);
        return data;
      },
    },
    refreshToken: {
      updateMany: async ({ where }) => {
        revokedFamilies.push(where.token_family_id);
        return { count: 1 };
      },
      create: async () => ({}),
    },
  };
  const mockDb = { $transaction: async (fn) => fn(tx) };

  const evicted = await createAuthSession(mockDb, {
    userId: 7n,
    sessionId: randomUUID(),
    familyId: randomUUID(),
    sessionExpiresAt: new Date(Date.now() + 86_400_000),
    mfaVerified: false,
    maxConcurrentSessions: 2,
    context: { ip: '198.51.100.77', userAgent: 'Chrome', correlationId: 'c-cap' },
  });

  // Keeping maxConcurrentSessions - 1 = 1 newest session before creating the new one -> evicts 2 oldest
  assert.deepEqual(evicted, ['sess-middle', 'sess-oldest']);
  assert.deepEqual(revokedFamilies, ['fam-middle', 'fam-oldest']);
  assert.equal(revokedSessionIds.length, 2);
  assert.equal(revokedSessionIds[0].reason, 'MAX_CONCURRENT_SESSIONS_EXCEEDED');
  assert.equal(createdSessions.length, 1);
  assert.equal(createdSessions[0].ip_address, '198.51.100.77');
});

test('rotateSessionRefreshToken expires idle sessions and updates valid IP/UA on active rotation', async () => {
  const future = new Date(Date.now() + 86_400_000);
  const expiredCalls = [];
  const idleTx = {
    refreshToken: {
      findUnique: async () => ({
        id: 'rt-1',
        token_family_id: 'fam-idle',
        expires_at: future,
        used_at: null,
        revoked_at: null,
        auth_sessions: {
          id: 'sess-idle',
          user_id: 9n,
          status: 'ACTIVE',
          expires_at: future,
          last_seen_at: new Date(Date.now() - 4000 * 1_000),
          mfa_verified_at: new Date(),
          users: { status: 'ACTIVE', locked_until: null },
        },
      }),
      updateMany: async ({ data }) => {
        expiredCalls.push({ table: 'refreshToken', data });
        return { count: 1 };
      },
    },
    authSession: {
      updateMany: async ({ data }) => {
        expiredCalls.push({ table: 'authSession', data });
        return { count: 1 };
      },
    },
  };

  const idleResult = await rotateSessionRefreshToken(
    { $transaction: async (fn) => fn(idleTx) },
    'old-hash',
    { id: 'rt-2', hash: 'new-hash', expiresAt: future },
    async () => null,
    { idleTtlSeconds: 3600, ipAddress: '203.0.113.55' },
  );
  assert.equal(idleResult.kind, 'invalid');
  assert.equal(
    expiredCalls.some(
      (c) =>
        c.table === 'authSession' &&
        c.data.status === 'EXPIRED' &&
        c.data.revocation_reason === 'IDLE_SESSION_EXPIRED',
    ),
    true,
  );

  // Active rotation updates last_seen_at, valid IP, and UA (ignoring invalid non-INET IP)
  let updatedSessionData = null;
  const activeTx = {
    refreshToken: {
      findUnique: async () => ({
        id: 'rt-active-1',
        token_family_id: 'fam-active',
        expires_at: future,
        used_at: null,
        revoked_at: null,
        auth_sessions: {
          id: 'sess-active',
          user_id: 9n,
          status: 'ACTIVE',
          expires_at: future,
          last_seen_at: new Date(),
          mfa_verified_at: new Date(),
          users: { status: 'ACTIVE', locked_until: null },
        },
      }),
      updateMany: async () => ({ count: 1 }),
      create: async () => ({}),
    },
    authSession: {
      update: async ({ data }) => {
        updatedSessionData = data;
        return data;
      },
    },
  };
  const rotated = await rotateSessionRefreshToken(
    { $transaction: async (fn) => fn(activeTx) },
    'old-hash',
    { id: 'rt-active-2', hash: 'new-hash', expiresAt: future },
    async () => ({
      id: 9n,
      username: 'alice',
      email: 'alice@test.local',
      passwordHash: 'x',
      fullName: 'Alice',
      status: 'ACTIVE',
      lockedUntil: null,
      failedLoginCount: 0,
      roles: ['DOCUMENT_READER'],
      mfaMethod: null,
    }),
    { idleTtlSeconds: 3600, ipAddress: '2001:db8::42', userAgent: 'UpdatedUA/2.0' },
  );
  assert.equal(rotated.kind, 'rotated');
  assert.equal(updatedSessionData.ip_address, '2001:db8::42');
  assert.equal(updatedSessionData.user_agent, 'UpdatedUA/2.0');
  assert.ok(updatedSessionData.last_seen_at instanceof Date);
});

test('AuthGuard throttles last_seen_at touches on same IP and updates immediately on IP change', async () => {
  const tokens = new TokenService(config());
  const sessionId = randomUUID();
  const touches = [];
  const guard = new AuthGuard(
    new Reflector(),
    tokens,
    {
      principalForSession: async () => ({
        userId: 42n,
        sessionId,
        username: 'alice',
        roles: ['DOCUMENT_READER'],
        mfa: true,
        mfaPending: false,
      }),
      touchSessionActivity: async (userId, sid, ip) => {
        touches.push({ userId, sid, ip });
      },
    },
    undefined,
    config({ AUTH_SESSION_TOUCH_INTERVAL_SECONDS: 60 }),
  );
  const accessToken = await tokens.issueAccessToken(42n, sessionId, true);
  const handler = () => undefined;
  const makeContext = (ip) => ({
    getHandler: () => handler,
    switchToHttp: () => ({
      getRequest: () => ({ cookies: { sda_access: accessToken }, ip }),
    }),
  });

  assert.equal(await guard.canActivate(makeContext('203.0.113.1')), true);
  assert.equal(await guard.canActivate(makeContext('203.0.113.1')), true);
  assert.equal(touches.length, 1, 'Second request from same IP within window must be throttled');

  // Device switches network (Wi-Fi -> 4G): must touch immediately with new IP
  assert.equal(await guard.canActivate(makeContext('198.51.100.88')), true);
  assert.equal(touches.length, 2);
  assert.equal(touches[1].ip, '198.51.100.88');
});

test('TRUST_PROXY accepts combined strict presets (loopback,uniquelocal) in production', () => {
  assert.deepEqual(resolveTrustProxyConfig('loopback,uniquelocal'), [
    '127.0.0.0/8',
    '::1/128',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    'fc00::/7',
  ]);

  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const prodEnv = {
    NODE_ENV: 'production',
    TRUST_PROXY: 'loopback,uniquelocal',
    AUTH_SIGNING_PRIVATE_KEY_PEM: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    AUTH_SIGNING_PUBLIC_KEYS_JSON: JSON.stringify([
      {
        kid: 'prod-k1',
        publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      },
    ]),
    APP_ENCRYPTION_MASTER_KEY: 'prod-random-master-key-value-with-more-than-32-bytes-entropy',
    DOCUMENT_AUDIT_HMAC_KEY: 'prod-doc-audit-hmac-key-with-sufficient-length-32b',
    AUTH_AUDIT_HMAC_KEY: 'prod-auth-audit-hmac-key-with-sufficient-length-32b',
    AUDIT_INTEGRITY_KEY: 'prod-audit-integrity-key-with-sufficient-length-32b',
    STORAGE_ACCESS_KEY: 'prod-s3-access-key',
    STORAGE_SECRET_KEY: 'prod-s3-secret-key-value',
    DATABASE_SSL_REJECT_UNAUTHORIZED: 'true',
    ABAC_TRUSTED_NETWORK_CIDRS: '10.20.0.0/16',
  };
  const validated = validateEnv(prodEnv);
  assert.equal(validated.TRUST_PROXY, 'loopback,uniquelocal');
  assert.equal(validated.AUTH_SESSION_IDLE_TTL_SECONDS, 28_800);
  assert.equal(validated.AUTH_SESSION_TOUCH_INTERVAL_SECONDS, 60);
  assert.equal(validated.AUTH_MAX_CONCURRENT_SESSIONS, 10);
});

import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { AuthorizationCache } from '../dist/modules/rbac/authorization-cache.js';
import { DocumentsService } from '../dist/modules/documents/documents.service.js';
import { AuthService } from '../dist/modules/auth/auth.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';
import { TokenService } from '../dist/modules/auth/token.service.js';
import { MfaService } from '../dist/modules/auth/mfa.service.js';
import { LoginRateLimitService } from '../dist/modules/auth/login-rate-limit.service.js';
import { config as authMockConfig } from './helpers/auth-security-mocks.mjs';

const ownerPrincipal = {
  userId: 101n,
  sessionId: 'sess-101',
  username: 'owner.concurrent',
  roles: ['DOCUMENT_OWNER'],
  mfa: true,
};
const ctx = { ip: '10.0.0.99', correlationId: 'corr-concurrency' };

test('Concurrency Scenario 4 — real DocumentsService.reclassifyDocument revokes grants & terminates sessions of under-cleared users', async () => {
  const docId = randomUUID();
  const aliceSession = { id: 'sess-alice', user_id: 10n, status: 'ACTIVE' };
  const bobSession = { id: 'sess-bob', user_id: 20n, status: 'ACTIVE' };
  const revokedGrantIds = [];
  const terminatedGrantIds = [];

  const mockDb = {
    document: {
      findUnique: async () => ({ id: docId, owner_id: 101n, department_id: 1n, status: 'ACTIVE' }),
    },
    classificationLevel: {
      findUnique: async () => ({
        id: 4n,
        code: 'TOP_SECRET',
        name: 'Tuyệt mật',
        rank: 4,
        is_active: true,
        allow_download: false,
      }),
    },
    businessCategory: {
      findUnique: async () => ({ id: 1n, code: 'SEC', name: 'An ninh', is_active: true }),
    },
    documentClassificationHistory: {
      findFirst: async () => ({
        id: 1n,
        document_id: docId,
        effective_to: null,
        classification_levels: { id: 2n, rank: 2 },
      }),
      update: async () => {},
      create: async () => {},
    },
    accessGrant: {
      findMany: async () => [
        {
          id: 'grant-alice',
          principal_type: 'USER',
          principal_user_id: 10n,
          status: 'ACTIVE',
        },
        {
          id: 'grant-bob',
          principal_type: 'USER',
          principal_user_id: 20n,
          status: 'ACTIVE',
        },
      ],
      update: async ({ where }) => {
        revokedGrantIds.push(where.id);
        return { id: where.id, status: 'REVOKED' };
      },
    },
    userAttributeAssignment: {
      findFirst: async ({ where }) =>
        where.user_id === 20n
          ? { attribute_options: { numeric_rank: 4, is_active: true } }
          : { attribute_options: { numeric_rank: 2, is_active: true } },
    },
    accessSession: {
      updateMany: async ({ where }) => {
        terminatedGrantIds.push(where.access_grant_id);
        if (where.access_grant_id === 'grant-alice') aliceSession.status = 'TERMINATED';
        return { count: 1 };
      },
    },
    accessGrantPermission: {
      deleteMany: async () => ({ count: 1 }),
    },
    $executeRawUnsafe: async () => 1,
    $transaction: async (fn) => fn(mockDb),
  };

  const service = new DocumentsService(
    { record: async () => {} },
    { hasPermission: async () => true },
    new AuthorizationCache(),
    mockDb,
  );

  await service.reclassifyDocument(
    docId,
    { classificationLevelId: 4n, businessCategoryId: 1n, reason: 'Escalate to TOP_SECRET' },
    ownerPrincipal,
    ctx,
  );

  assert.deepEqual(revokedGrantIds, ['grant-alice']);
  assert.deepEqual(terminatedGrantIds, ['grant-alice']);
  assert.equal(aliceSession.status, 'TERMINATED');
  assert.equal(bobSession.status, 'ACTIVE');
});

test('Concurrency Scenario 5 — real AuthService.refresh revokes entire token family and records REFRESH_REUSE on replay', async () => {
  const cfg = authMockConfig();
  const audits = [];
  let tokenUsed = false;
  let familyRevoked = false;

  const repository = {
    rotateRefreshToken: async () => {
      if (!tokenUsed) {
        tokenUsed = true;
        return {
          kind: 'rotated',
          user: {
            id: 77n,
            username: 'bob',
            email: 'bob@corp.test',
            passwordHash: 'unused',
            fullName: 'Bob',
            status: 'ACTIVE',
            lockedUntil: null,
            failedLoginCount: 0,
            roles: ['DOCUMENT_READER'],
            mfaMethod: null,
          },
          sessionId: 'sess-77',
          mfa: true,
        };
      }
      familyRevoked = true;
      return {
        kind: 'reuse',
        userId: 77n,
        sessionId: 'sess-77',
      };
    },
  };

  const authService = new AuthService(
    repository,
    new PasswordService(),
    new TokenService(cfg),
    new MfaService(cfg),
    new LoginRateLimitService(),
    { record: async (ev) => audits.push(ev) },
    {},
    cfg,
  );

  const firstRotation = await authService.refresh('raw-refresh-token-v1', ctx);
  assert.ok(firstRotation.accessToken);
  assert.ok(firstRotation.refreshToken);

  const [replay1, replay2] = await Promise.allSettled([
    authService.refresh('raw-refresh-token-v1', ctx),
    authService.refresh('raw-refresh-token-v1', ctx),
  ]);

  assert.equal(replay1.status, 'rejected');
  assert.equal(replay2.status, 'rejected');
  assert.equal(familyRevoked, true);
  assert.ok(audits.some((e) => e.action === 'REFRESH_REUSE'));
});

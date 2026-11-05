import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { ForbiddenException } from '@nestjs/common';
import { resolveAndEnforceSessionPolicy } from '../dist/modules/documents/session-policy-resolver.helper.js';
import { resolveTrustProxyConfig, validateEnv } from '../dist/config/env.schema.js';
import { LoginRateLimitService } from '../dist/modules/auth/login-rate-limit.service.js';
import {
  advanceWebAuthnCounterAtomic,
  consumeMfaRecoveryCodeAtomic,
} from '../dist/modules/auth/auth-mfa.repository.js';

const principal = {
  userId: 7n,
  username: 'reader.sec',
  departmentId: 10n,
  sessionId: randomUUID(),
  roles: ['DOCUMENT_READER'],
  mfa: true,
};
const reqContext = {
  ip: '198.51.100.25',
  userAgent: 'Mozilla/5.0',
  correlationId: randomUUID(),
};

test('[HIGH-01] resolveAndEnforceSessionPolicy re-hydrates obligations after restart & fails closed when unverifiable', async () => {
  const sessionId = randomUUID();
  const startedAt = new Date(Date.now() - 10 * 60_000);
  const cache = new Map();

  // 1. Cache miss after API restart: re-hydrates forbidDownload=true from audit_logs + live ABAC
  const mockDb = {
    auditLog: {
      findFirst: async () => ({
        details: {
          grantedAction: 'VIEW',
          forbidDownload: true,
          expiresAtMs: Date.now() + 30 * 60_000,
        },
      }),
    },
    userAttributeAssignment: {
      findFirst: async () => ({ attribute_options: { numeric_rank: 3 } }),
      findMany: async () => [],
    },
  };
  const mockAbac = {
    evaluate: async () => ({
      decision: 'PERMIT',
      reasonCode: 'POLICY_PERMIT',
      obligations: [{ type: 'FORBID_DOWNLOAD' }, { type: 'MAX_SESSION_MINUTES', minutes: 5 }],
    }),
  };
  const mockSession = {
    id: sessionId,
    started_at: startedAt,
    document_versions: {
      document: {
        owner_id: 99n,
        status: 'ACTIVE',
        department_id: 10n,
        classification_history: [
          { classification_levels: { rank: 2 }, business_categories: { code: 'GEN' } },
        ],
      },
    },
  };

  // MAX_SESSION_MINUTES=5 anchored to startedAt (10 min ago) must reject as expired!
  await assert.rejects(
    resolveAndEnforceSessionPolicy({
      sessionPolicies: cache,
      database: mockDb,
      abac: mockAbac,
      config: undefined,
      session: mockSession,
      requiredAction: 'VIEW',
      now: new Date(),
      principal,
      context: reqContext,
    }),
    (err) => err instanceof ForbiddenException && /maximum policy duration/i.test(err.message),
  );

  // Fresh session re-hydrated with forbidDownload=true must block DOWNLOAD
  const freshCache = new Map();
  await assert.rejects(
    resolveAndEnforceSessionPolicy({
      sessionPolicies: freshCache,
      database: mockDb,
      abac: {
        evaluate: async () => ({
          decision: 'PERMIT',
          reasonCode: 'POLICY_PERMIT',
          obligations: [{ type: 'FORBID_DOWNLOAD' }],
        }),
      },
      config: undefined,
      session: { ...mockSession, started_at: new Date() },
      requiredAction: 'DOWNLOAD',
      now: new Date(),
      principal,
      context: reqContext,
    }),
    (err) => err instanceof ForbiddenException,
  );

  // Fail-closed when both cache and audit/ABAC sources are unavailable
  await assert.rejects(
    resolveAndEnforceSessionPolicy({
      sessionPolicies: new Map(),
      database: {},
      abac: undefined,
      config: undefined,
      session: { id: randomUUID(), started_at: new Date() },
      requiredAction: 'VIEW',
      now: new Date(),
      principal,
      context: reqContext,
    }),
    (err) => err instanceof ForbiddenException,
  );
});

test('[HIGH-02] TRUST_PROXY config & LoginRateLimitService prevent proxy-wide DoS and loopback trustedNetwork bypass', () => {
  assert.deepEqual(resolveTrustProxyConfig('loopback'), ['127.0.0.0/8', '::1/128']);
  assert.equal(resolveTrustProxyConfig('false'), false);
  const hopFn = resolveTrustProxyConfig('2');
  assert.equal(typeof hopFn, 'function');
  assert.equal(hopFn('10.0.0.1', 2), true);
  assert.equal(hopFn('10.0.0.1', 3), false);

  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const baseProdEnv = {
    NODE_ENV: 'production',
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

  assert.throws(() => validateEnv({ ...baseProdEnv, TRUST_PROXY: 'true' }), /TRUST_PROXY/);
  assert.throws(
    () => validateEnv({ ...baseProdEnv, ABAC_TRUSTED_NETWORK_CIDRS: '127.0.0.0/8,10.20.0.0/16' }),
    /ABAC_TRUSTED_NETWORK_CIDRS/,
  );

  // Proxy loopback IP must NOT lock out unrelated accounts
  const limiter = new LoginRateLimitService();
  for (let i = 0; i < 6; i++) {
    limiter.recordFailure('127.0.0.1', 'attacker.user');
  }
  assert.throws(() => limiter.assertAllowed('127.0.0.1', 'attacker.user'));
  assert.doesNotThrow(() => limiter.assertAllowed('127.0.0.1', 'legit.victim'));
});

test('[HIGH-03] consumeMfaRecoveryCodeAtomic & advanceWebAuthnCounterAtomic serialize concurrent requests via FOR UPDATE', async () => {
  let storedHashes = ['hash-code-1', 'hash-code-2'];
  let lockChain = Promise.resolve();
  const mockDb = {
    $transaction: async (fn) => {
      const prev = lockChain;
      let release;
      lockChain = new Promise((r) => {
        release = r;
      });
      await prev;
      try {
        return await fn({
          $queryRaw: async () => [{ id: 'mfa-1', recovery_code_hashes: [...storedHashes] }],
          mfaMethod: {
            update: async ({ data }) => {
              storedHashes = [...data.recovery_code_hashes];
            },
          },
        });
      } finally {
        release();
      }
    },
  };

  const [resA, resB, resC] = await Promise.all([
    consumeMfaRecoveryCodeAtomic(mockDb, 7n, 'code-1', (hashes) =>
      hashes.includes('hash-code-1') ? hashes.filter((h) => h !== 'hash-code-1') : null,
    ),
    consumeMfaRecoveryCodeAtomic(mockDb, 7n, 'code-1', (hashes) =>
      hashes.includes('hash-code-1') ? hashes.filter((h) => h !== 'hash-code-1') : null,
    ),
    consumeMfaRecoveryCodeAtomic(mockDb, 7n, 'code-1', (hashes) =>
      hashes.includes('hash-code-1') ? hashes.filter((h) => h !== 'hash-code-1') : null,
    ),
  ]);

  assert.equal([resA, resB, resC].filter(Boolean).length, 1);
  assert.deepEqual(storedHashes, ['hash-code-2']);

  let storedSecret = JSON.stringify({ counter: 10 });
  const webauthnDb = {
    $transaction: async (fn) =>
      fn({
        $queryRaw: async () => [{ id: 'mfa-w1', secret_encrypted: storedSecret }],
        mfaMethod: {
          update: async ({ data }) => {
            storedSecret = data.secret_encrypted;
          },
        },
      }),
  };
  const firstStep = await advanceWebAuthnCounterAtomic(
    webauthnDb,
    randomUUID(),
    7n,
    11,
    (s) => JSON.parse(s),
    (obj) => JSON.stringify(obj),
  );
  const replayStep = await advanceWebAuthnCounterAtomic(
    webauthnDb,
    randomUUID(),
    7n,
    11,
    (s) => JSON.parse(s),
    (obj) => JSON.stringify(obj),
  );
  assert.equal(firstStep, 'updated');
  assert.equal(replayStep, 'clone_detected');
});

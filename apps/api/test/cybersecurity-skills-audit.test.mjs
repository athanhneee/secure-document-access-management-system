import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { BadRequestException, ForbiddenException } from '@nestjs/common';

process.env.STORAGE_MOCK = 'true';
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgresql://localhost:5432/secure_docs?schema=public';
process.env.APP_ENCRYPTION_MASTER_KEY = 'test-master-key-32-chars-long-000000000';

import { AppConfigService } from '../dist/config/config.service.js';
import { AuthService } from '../dist/modules/auth/auth.service.js';
import { MfaService } from '../dist/modules/auth/mfa.service.js';
import { WebAuthnService } from '../dist/modules/auth/webauthn.service.js';
import { AccessGrantsService } from '../dist/modules/access-grants/access-grants.service.js';

function createTestConfig(overrides = {}) {
  return new AppConfigService({
    NODE_ENV: 'test',
    APP_ENCRYPTION_MASTER_KEY: 'test-master-key-32-chars-long-000000000',
    AUDIT_INTEGRITY_KEY: 'test-unified-audit-hmac-key-000000000000',
    AUTH_ACCESS_TTL_SECONDS: 900,
    AUTH_REFRESH_TTL_SECONDS: 86400,
    AUTH_RESET_TTL_SECONDS: 1800,
    GRANT_MAX_DURATION_DAYS: 90,
    ...overrides,
  });
}

test('AuthService.beginMfaEnrollment blocks unverified pre-MFA session when active MFA already exists', async () => {
  const config = createTestConfig();
  const mfa = new MfaService(config);
  let auditRecorded = null;

  const mockRepository = {
    getActiveMfaMethods: async () => [{ id: 10n, encryptedSecret: 'enc', label: 'Primary TOTP' }],
    createMfaEnrollment: async () => {
      assert.fail('Should never create MFA enrollment when pre-MFA session already has active MFA');
    },
  };
  const mockAudit = {
    record: async (evt) => {
      auditRecorded = evt;
    },
  };

  const service = new AuthService(
    mockRepository,
    {},
    {},
    mfa,
    { assertAllowed: () => {}, recordFailure: () => 0, clearAccount: () => {} },
    mockAudit,
    {},
    config,
  );

  const preMfaPrincipal = {
    userId: 42n,
    username: 'admin.demo',
    sessionId: randomUUID(),
    roles: ['SYSTEM_ADMIN'],
    mfa: false,
    mfaPending: true,
    departmentId: 1n,
  };

  await assert.rejects(
    () =>
      service.beginMfaEnrollment(preMfaPrincipal, 'Attacker TOTP', {
        ip: '10.0.0.5',
        userAgent: 'Test',
        correlationId: randomUUID(),
      }),
    (err) => err instanceof ForbiddenException,
  );
  assert.ok(auditRecorded);
  assert.equal(auditRecorded.outcome, 'DENIED');
});

test('WebAuthnService.verifyChallengeToken rejects replayed challenge tokens', () => {
  const config = createTestConfig();
  const mfa = new MfaService(config);
  const webauthn = new WebAuthnService(mfa, config);

  const token = webauthn.createChallengeToken('random-challenge-abc-123', 99n);
  const extracted = webauthn.verifyChallengeToken(token, 99n);
  assert.equal(extracted, 'random-challenge-abc-123');

  assert.throws(
    () => webauthn.verifyChallengeToken(token, 99n),
    (err) => err instanceof BadRequestException && /already been used/i.test(err.message),
  );
});

test('AccessGrantsService.assertGrantValidForAccess blocks cross-document grantId BOLA', async () => {
  const config = createTestConfig();
  const docA = randomUUID();
  const docB = randomUUID();
  const grantId = randomUUID();
  const now = new Date();

  const mockDb = {
    accessGrant: {
      findUnique: async () => ({
        id: grantId,
        document_id: docA,
        principal_type: 'USER',
        principal_user_id: 7n,
        principal_role_id: null,
        status: 'ACTIVE',
        valid_from: new Date(now.getTime() - 60_000),
        valid_until: new Date(now.getTime() + 3_600_000),
        access_grant_permissions: [{ permission: 'VIEW' }],
        documents: {
          id: docA,
          status: 'ACTIVE',
          classification_history: [
            {
              classification_levels: {
                rank: 2,
                allow_download: true,
              },
            },
          ],
        },
      }),
    },
  };

  const service = new AccessGrantsService({}, {}, {}, {}, config, mockDb);

  await assert.rejects(
    () => service.assertGrantValidForAccess(grantId, 7n, 'VIEW', now, docB),
    (err) =>
      err instanceof ForbiddenException &&
      /does not belong to the requested document/i.test(JSON.stringify(err.getResponse())),
  );
});

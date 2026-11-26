import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import * as OTPAuth from 'otpauth';
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import {
  disableSingleUserMfaMethodAtomic,
  disableUserMfaMethodsAtomic,
} from '../dist/modules/auth/auth-mfa.repository.js';
import { AuthController } from '../dist/modules/auth/auth.controller.js';
import { AuthService } from '../dist/modules/auth/auth.service.js';
import { LoginRateLimitService } from '../dist/modules/auth/login-rate-limit.service.js';
import { MfaService } from '../dist/modules/auth/mfa.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';
import { TokenService } from '../dist/modules/auth/token.service.js';
import { config } from './helpers/auth-security-mocks.mjs';

test('[CRITICAL-06] DELETE /auth/mfa blocks mandatory-MFA roles and enforces password + live TOTP step-up verification', async () => {
  const passwords = new PasswordService();
  const mfa = new MfaService(config());
  const passwordPlain = 'correct horse battery staple';
  const passwordHash = await passwords.hash(passwordPlain);
  const enrollment = mfa.createEnrollment('reader@corp.test');
  const totp = new OTPAuth.TOTP({
    issuer: 'Secure Document Access',
    label: 'reader@corp.test',
    secret: OTPAuth.Secret.fromBase32(enrollment.secret),
  });

  let disabledCount = 0;
  let revokedCount = 0;
  let currentRoles = ['DOCUMENT_READER'];
  const repository = {
    findUserById: async () => ({
      id: 21n,
      username: 'reader',
      email: 'reader@corp.test',
      passwordHash,
      fullName: 'Reader',
      status: 'ACTIVE',
      lockedUntil: null,
      failedLoginCount: 0,
      roles: currentRoles,
      mfaMethod: null,
    }),
    getActiveMfaMethods: async () => [
      {
        id: 'm1',
        methodType: 'TOTP',
        encryptedSecret: enrollment.encryptedSecret,
        recoveryCodeHashes: [],
      },
    ],
    disableMfa: async () => {
      disabledCount += 1;
      return true;
    },
    revokeAllSessions: async () => {
      revokedCount += 1;
      return 1;
    },
  };

  const service = new AuthService(
    repository,
    passwords,
    new TokenService(config()),
    mfa,
    new LoginRateLimitService(),
    { record: async () => undefined },
    {},
    config(),
  );
  const controller = new AuthController(service, { assertRequest: () => undefined }, config());
  const ctx = { ip: '198.51.100.20', correlationId: randomUUID() };
  const reply = {
    clearCookie() {
      return this;
    },
  };

  // 1. Missing body / missing step-up credentials rejected by controller schema
  await assert.rejects(
    controller.disableMfa(
      {},
      {
        auth: {
          userId: 21n,
          sessionId: 's1',
          username: 'reader',
          roles: ['DOCUMENT_READER'],
          mfa: true,
        },
        ip: ctx.ip,
        headers: {},
      },
      reply,
    ),
    /validation failed/iu,
  );

  // 2. Mandatory-MFA roles (SYSTEM_ADMIN, SECURITY_OFFICER, AUDITOR) cannot disable MFA
  for (const mandatoryRole of ['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'AUDITOR']) {
    currentRoles = [mandatoryRole];
    await assert.rejects(
      service.disableMfa(
        { userId: 21n, sessionId: 's1', username: 'priv', roles: [mandatoryRole], mfa: true },
        passwordPlain,
        totp.generate(),
        undefined,
        ctx,
      ),
      ForbiddenException,
    );
  }
  assert.equal(disabledCount, 0);

  // 3. Regular role: wrong password or wrong TOTP rejected; valid password + valid TOTP succeeds
  currentRoles = ['DOCUMENT_READER'];
  const readerPrincipal = {
    userId: 21n,
    sessionId: 's1',
    username: 'reader',
    roles: ['DOCUMENT_READER'],
    mfa: true,
  };
  await assert.rejects(
    service.disableMfa(readerPrincipal, 'wrong password phrase', totp.generate(), undefined, ctx),
    UnauthorizedException,
  );
  await assert.rejects(
    service.disableMfa(readerPrincipal, passwordPlain, '000000', undefined, ctx),
    UnauthorizedException,
  );
  assert.equal(disabledCount, 0);

  await service.disableMfa(readerPrincipal, passwordPlain, totp.generate(), undefined, ctx);
  assert.equal(disabledCount, 1);
  assert.equal(revokedCount, 1);
});

test('[BUG-003] DELETE /auth/mfa/methods/:methodId enforces password + live MFA step-up, rate limiting, and session revocation on last factor', async () => {
  const passwords = new PasswordService();
  const mfa = new MfaService(config());
  const passwordPlain = 'correct horse battery staple';
  const passwordHash = await passwords.hash(passwordPlain);
  const enrollment = mfa.createEnrollment('reader@corp.test');
  const recovery = mfa.createRecoveryCodes(4);
  const methodId1 = '11111111-1111-4111-8111-111111111111';
  const methodId2 = '22222222-2222-4222-8222-222222222222';

  let activeMethods = [
    {
      id: methodId1,
      methodType: 'TOTP',
      encryptedSecret: enrollment.encryptedSecret,
      label: 'Authenticator',
      recoveryCodeHashes: [...recovery.hashes],
      createdAt: new Date(),
    },
    {
      id: methodId2,
      methodType: 'WEBAUTHN',
      encryptedSecret: 'webauthn-payload',
      label: 'YubiKey',
      recoveryCodeHashes: [],
      createdAt: new Date(),
    },
  ];
  let revokedCount = 0;
  let clearedCookies = 0;
  const publishedEvents = [];

  const repository = {
    findUserById: async () => ({
      id: 31n,
      username: 'reader2',
      email: 'reader2@corp.test',
      passwordHash,
      fullName: 'Reader Two',
      status: 'ACTIVE',
      lockedUntil: null,
      failedLoginCount: 0,
      roles: ['DOCUMENT_READER'],
      hasMandatoryMfaRole: false,
      mfaMethod: null,
    }),
    getActiveMfaMethods: async () => activeMethods,
    consumeRecoveryCode: async (id, remaining) => {
      const target = activeMethods.find((m) => m.id === id);
      if (target) target.recoveryCodeHashes = remaining;
    },
    disableSingleMfaMethodAtomic: async (_userId, id) => {
      const target = activeMethods.find((m) => m.id === id);
      if (!target) return { kind: 'not_found' };
      activeMethods = activeMethods.filter((m) => m.id !== id);
      return {
        kind: 'disabled',
        remainingCount: activeMethods.length,
        methodType: target.methodType,
        label: target.label,
      };
    },
    revokeAllSessions: async () => {
      revokedCount += 1;
      return 1;
    },
  };

  const realtime = {
    publish: (event) => publishedEvents.push(event),
  };
  const service = new AuthService(
    repository,
    passwords,
    new TokenService(config()),
    mfa,
    new LoginRateLimitService(),
    { record: async () => undefined },
    {},
    config(),
    undefined,
    undefined,
    realtime,
  );
  const controller = new AuthController(service, { assertRequest: () => undefined }, config());
  const ctx = { ip: '198.51.100.21', correlationId: randomUUID() };
  const principal = {
    userId: 31n,
    sessionId: 's-31',
    username: 'reader2',
    roles: ['DOCUMENT_READER'],
    mfa: true,
  };
  const reply = {
    clearCookie() {
      clearedCookies += 1;
      return this;
    },
  };

  // 1. Passwordless / bodyless DELETE /auth/mfa/methods/:id is rejected by controller schema
  await assert.rejects(
    controller.removeMfaMethod(methodId2, {}, { auth: principal, ip: ctx.ip, headers: {} }, reply),
    /validation failed/iu,
  );

  // 2. Wrong password or wrong MFA code rejected without deleting method
  await assert.rejects(
    service.removeMfaMethod(
      principal,
      methodId2,
      'wrong password phrase',
      undefined,
      recovery.plaintext[0],
      ctx,
    ),
    UnauthorizedException,
  );
  await assert.rejects(
    service.removeMfaMethod(principal, methodId2, passwordPlain, '000000', undefined, ctx),
    UnauthorizedException,
  );
  assert.equal(activeMethods.length, 2);

  // 3. Valid step-up removes 1 of 2 factors WITHOUT revoking sessions or clearing cookies
  await controller.removeMfaMethod(
    methodId2,
    { currentPassword: passwordPlain, recoveryCode: recovery.plaintext[0] },
    { auth: principal, ip: ctx.ip, headers: {} },
    reply,
  );
  assert.equal(activeMethods.length, 1);
  assert.equal(revokedCount, 0);
  assert.equal(clearedCookies, 0);
  assert.equal(publishedEvents.length, 0);

  // 4. Valid step-up removes LAST remaining factor -> revokes all sessions, emits SSE, clears cookies
  await controller.removeMfaMethod(
    methodId1,
    { currentPassword: passwordPlain, recoveryCode: recovery.plaintext[1] },
    { auth: principal, ip: ctx.ip, headers: {} },
    reply,
  );
  assert.equal(activeMethods.length, 0);
  assert.equal(revokedCount, 1);
  assert.equal(publishedEvents.length, 1);
  assert.equal(publishedEvents[0].type, 'USER_SESSION_REVOKED');
  assert.ok(clearedCookies > 0);
});

test('[BUG-003] Custom privileged roles cannot bypass mandatory MFA via listMfaMethods, disableMfa, or removeMfaMethod', async () => {
  const passwords = new PasswordService();
  const mfa = new MfaService(config());
  const passwordPlain = 'correct horse battery staple';
  const passwordHash = await passwords.hash(passwordPlain);
  const enrollment = mfa.createEnrollment('custom.admin@corp.test');
  const totp = new OTPAuth.TOTP({
    issuer: 'Secure Document Access',
    label: 'custom.admin@corp.test',
    secret: OTPAuth.Secret.fromBase32(enrollment.secret),
  });
  const soleMethodId = '33333333-3333-4333-8333-333333333333';

  let userPermissions = ['USER:MANAGE'];
  let userHasMandatoryFlag = false;
  let disabledAllCount = 0;

  const repository = {
    findUserById: async () => ({
      id: 41n,
      username: 'custom_admin',
      email: 'custom.admin@corp.test',
      passwordHash,
      fullName: 'Custom Admin',
      status: 'ACTIVE',
      lockedUntil: null,
      failedLoginCount: 0,
      roles: ['CUSTOM_GOVERNANCE_LEAD'],
      hasMandatoryMfaRole: userHasMandatoryFlag,
      profile: { permissions: userPermissions },
      mfaMethod: null,
    }),
    getActiveMfaMethods: async () => [
      {
        id: soleMethodId,
        methodType: 'TOTP',
        encryptedSecret: enrollment.encryptedSecret,
        label: 'Authenticator',
        recoveryCodeHashes: [],
        createdAt: new Date(),
      },
    ],
    disableMfa: async () => {
      disabledAllCount += 1;
      return true;
    },
    disableSingleMfaMethod: async () => true,
    revokeAllSessions: async () => 1,
  };

  const service = new AuthService(
    repository,
    passwords,
    new TokenService(config()),
    mfa,
    new LoginRateLimitService(),
    { record: async () => undefined },
    {},
    config(),
  );
  const ctx = { ip: '198.51.100.22', correlationId: randomUUID() };
  const principal = {
    userId: 41n,
    sessionId: 's-41',
    username: 'custom_admin',
    roles: ['CUSTOM_GOVERNANCE_LEAD'],
    mfa: true,
  };

  // Custom role carrying USER:MANAGE (privileged capability) must keep MFA enabled
  const listedPrivileged = await service.listMfaMethods(principal);
  assert.equal(listedPrivileged.canDisableMfa, false);
  await assert.rejects(
    service.disableMfa(principal, passwordPlain, totp.generate(), undefined, ctx),
    ForbiddenException,
  );
  await assert.rejects(
    service.removeMfaMethod(
      principal,
      soleMethodId,
      passwordPlain,
      totp.generate(),
      undefined,
      ctx,
    ),
    ForbiddenException,
  );
  assert.equal(disabledAllCount, 0);

  // Also blocked via explicit DB flag hasMandatoryMfaRole even without profile.permissions
  userPermissions = [];
  userHasMandatoryFlag = true;
  assert.equal((await service.listMfaMethods(principal)).canDisableMfa, false);
  await assert.rejects(
    service.disableMfa(principal, passwordPlain, totp.generate(), undefined, ctx),
    ForbiddenException,
  );

  // Non-privileged custom business role (DOCUMENT:VIEW + AUDIT_LOG:VIEW) IS permitted to disable MFA
  userHasMandatoryFlag = false;
  userPermissions = ['DOCUMENT:VIEW', 'AUDIT_LOG:VIEW'];
  assert.equal((await service.listMfaMethods(principal)).canDisableMfa, true);
  await service.disableMfa(principal, passwordPlain, totp.generate(), undefined, ctx);
  assert.equal(disabledAllCount, 1);
});

test('[BUG-003] Concurrent DELETE /auth/mfa/methods/:id under SERIALIZABLE + FOR UPDATE never strips all MFA factors from privileged accounts', async () => {
  const methodA = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const methodB = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const activeRows = new Map([
    [methodA, { id: methodA, method_type: 'TOTP', label: 'Authenticator' }],
    [methodB, { id: methodB, method_type: 'WEBAUTHN', label: 'Passkey' }],
  ]);

  let sawSerializable = false;
  let sawUserForUpdate = false;
  let sawMfaForUpdate = false;
  let serializedLock = Promise.resolve();
  let injectedSerializationConflictOnce = false;

  const mockDb = {
    $transaction: async (operation, options) => {
      assert.equal(options?.isolationLevel, 'Serializable');
      sawSerializable = true;

      // Serialize critical sections just like PostgreSQL FOR UPDATE + inject one 40001 conflict to prove retry safety
      const runTx = async () => {
        const snapshot = new Map(activeRows);
        let didFirstQuery = false;
        const tx = {
          $queryRaw: async (strings) => {
            const sql = strings.join(' ');
            if (sql.includes('FROM public.users') && sql.includes('FOR UPDATE')) {
              sawUserForUpdate = true;
              return [{ id: 99n }];
            }
            if (sql.includes('FROM public.mfa_methods') && sql.includes('FOR UPDATE')) {
              sawMfaForUpdate = true;
              if (!didFirstQuery && !injectedSerializationConflictOnce && activeRows.size === 1) {
                didFirstQuery = true;
                injectedSerializationConflictOnce = true;
                throw Object.assign(
                  new Error('could not serialize access due to concurrent update'),
                  {
                    code: '40001',
                  },
                );
              }
              return [...snapshot.values()];
            }
            return [];
          },
          userRole: {
            findMany: async () => [
              {
                roles: {
                  code: 'CUSTOM_SEC_LEAD',
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
          mfaMethod: {
            updateMany: async ({ where }) => {
              if (where.id) {
                if (!activeRows.has(where.id)) return { count: 0 };
                activeRows.delete(where.id);
                return { count: 1 };
              }
              const count = activeRows.size;
              activeRows.clear();
              return { count };
            },
          },
        };
        return operation(tx);
      };

      const chained = serializedLock.then(runTx, runTx);
      serializedLock = chained.then(
        () => undefined,
        () => undefined,
      );
      return chained;
    },
  };

  const [resA, resB] = await Promise.all([
    disableSingleUserMfaMethodAtomic(mockDb, 99n, methodA),
    disableSingleUserMfaMethodAtomic(mockDb, 99n, methodB),
  ]);

  assert.equal(sawSerializable, true);
  assert.equal(sawUserForUpdate, true);
  assert.equal(sawMfaForUpdate, true);
  assert.equal(injectedSerializationConflictOnce, true);

  const outcomes = [resA.kind, resB.kind].sort();
  assert.deepEqual(outcomes, ['disabled', 'mandatory_role_last_factor']);
  assert.equal(
    activeRows.size,
    1,
    'Privileged account must always retain at least 1 active MFA factor',
  );

  // disableUserMfaMethodsAtomic also blocks custom privileged role inside SERIALIZABLE transaction
  const disableAllOutcome = await disableUserMfaMethodsAtomic(mockDb, 99n);
  assert.deepEqual(disableAllOutcome, { kind: 'mandatory_role_blocked' });
  assert.equal(activeRows.size, 1);
});

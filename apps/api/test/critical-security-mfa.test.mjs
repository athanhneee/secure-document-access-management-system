import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import * as OTPAuth from 'otpauth';
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
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

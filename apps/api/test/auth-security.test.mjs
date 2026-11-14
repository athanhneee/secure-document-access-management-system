import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as OTPAuth from 'otpauth';
import { AuthService } from '../dist/modules/auth/auth.service.js';
import { CsrfService } from '../dist/modules/auth/csrf.service.js';
import { LoginRateLimitService } from '../dist/modules/auth/login-rate-limit.service.js';
import { MfaService } from '../dist/modules/auth/mfa.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';
import { TokenService } from '../dist/modules/auth/token.service.js';
import { config, externallySignedToken } from './helpers/auth-security-mocks.mjs';

test('access token verifies Ed25519 signature, issuer, audience and expiry', async () => {
  const service = new TokenService(config());
  const valid = await service.issueAccessToken(42n, '11111111-1111-4111-8111-111111111111', true);
  assert.equal((await service.verifyAccessToken(valid)).sub, '42');
  await assert.rejects(
    service.verifyAccessToken(await externallySignedToken({}, { issuer: 'wrong' })),
  );
  await assert.rejects(
    service.verifyAccessToken(await externallySignedToken({}, { audience: 'wrong' })),
  );
  await assert.rejects(
    service.verifyAccessToken(
      await externallySignedToken({}, { exp: Math.floor(Date.now() / 1000) - 30 }),
    ),
  );
  const jwks = await service.jwks();
  assert.equal(jwks.keys[0].kid, 'test-key');
  assert.equal(jwks.keys[0].kty, 'OKP');
  assert.equal(jwks.keys[0].d, undefined);
});

test('passwords use Argon2id and reject short or common values', async () => {
  const service = new PasswordService();
  assert.throws(() => service.validate('Password1'));
  assert.throws(() => service.validate('password'));
  service.validate('correct horse battery staple');
  const hash = await service.hash('correct horse battery staple');
  assert.match(hash, /^\$argon2id\$v=19\$m=65536,p=1,t=3\$/);
  assert.equal(await service.verify(hash, 'correct horse battery staple'), true);
  assert.equal(await service.verify(hash, 'incorrect value'), false);
});

test('TOTP secrets are encrypted, prevent same-step replay, and recovery codes are one-time hashes', async () => {
  const service = new MfaService(config());
  const enrollment = service.createEnrollment('admin@example.test');
  assert.doesNotMatch(enrollment.encryptedSecret, new RegExp(enrollment.secret));
  const totp = new OTPAuth.TOTP({
    issuer: 'Secure Document Access',
    label: 'admin@example.test',
    secret: OTPAuth.Secret.fromBase32(enrollment.secret),
  });
  const code = totp.generate();
  assert.equal(await service.verifyTotp(enrollment.encryptedSecret, code, '42'), true);
  assert.equal(await service.verifyTotp(enrollment.encryptedSecret, code, '42'), false);
  const recovery = service.createRecoveryCodes(2);
  assert.notEqual(recovery.hashes[0], recovery.plaintext[0]);
  const remaining = service.consumeRecoveryCode(recovery.hashes, recovery.plaintext[0]);
  assert.equal(remaining.length, 1);
  assert.equal(service.consumeRecoveryCode(remaining, recovery.plaintext[0]), null);
});

test('CSRF requires an allowed Origin and matching double-submit token', () => {
  const service = new CsrfService(config());
  const token = 'a'.repeat(43);
  assert.doesNotThrow(() =>
    service.assertRequest({
      headers: { origin: 'https://app.internal.test', 'x-csrf-token': token },
      cookies: { sda_csrf: token },
    }),
  );
  assert.throws(() =>
    service.assertRequest({
      headers: { origin: 'https://evil.test', 'x-csrf-token': token },
      cookies: { sda_csrf: token },
    }),
  );
  assert.throws(() =>
    service.assertRequest({
      headers: { origin: 'https://app.internal.test', 'x-csrf-token': 'b'.repeat(43) },
      cookies: { sda_csrf: token },
    }),
  );
});

test('brute-force limiter keys attempts by both IP and normalized account', async () => {
  const limiter = new LoginRateLimitService(config());
  await limiter.recordFailure('192.0.2.1', 'alice', 1_000);
  await limiter.recordFailure('192.0.2.1', 'alice', 1_001);
  const delay = await limiter.recordFailure('192.0.2.1', 'alice', 1_002);
  assert.equal(delay, 250);
  await assert.rejects(
    () => limiter.assertAllowed('192.0.2.1', 'different', 1_100),
    /temporarily/u,
  );
  await assert.rejects(() => limiter.assertAllowed('198.51.100.1', 'alice', 1_100), /temporarily/u);
  await limiter.assertAllowed('198.51.100.1', 'different', 1_100);
});

/**
 * Thuật toán kiểm thử [CRITICAL 1.1]: Đăng nhập chỉ bằng mật khẩu luôn gán `mfaVerified = false`
 * (`mfa: false` trong JWT) và chỉ nâng cấp lên `mfa: true` sau khi xác minh thành công nhân tố thứ hai.
 */
test('password-only login issues mfa:false and only verified second factor upgrades session to mfa:true', async () => {
  const cfg = config();
  const passwords = new PasswordService();
  const tokens = new TokenService(cfg);
  const mfa = new MfaService(cfg);
  const passwordPlain = 'correct horse battery staple';
  const passwordHash = await passwords.hash(passwordPlain);
  const enrollment = mfa.createEnrollment('reader@example.test');
  const totp = new OTPAuth.TOTP({
    issuer: 'Secure Document Access',
    label: 'reader@example.test',
    secret: OTPAuth.Secret.fromBase32(enrollment.secret),
  });

  const createdSessions = [];
  let activatedSessionId = null;
  let hasEnrolledMfa = false;

  const repository = {
    findUserByIdentifier: async () => ({
      id: 77n,
      username: 'reader',
      email: 'reader@example.test',
      passwordHash,
      fullName: 'Doc Reader',
      status: 'ACTIVE',
      lockedUntil: null,
      failedLoginCount: 0,
      roles: ['DOCUMENT_READER'],
      requiresMfa: false,
      mfaMethod: hasEnrolledMfa
        ? {
            id: 'mfa-77',
            methodType: 'TOTP',
            encryptedSecret: enrollment.encryptedSecret,
            recoveryCodeHashes: [],
          }
        : null,
    }),
    clearLoginFailures: async () => undefined,
    recordLoginSuccess: async () => undefined,
    createSession: async (input) => {
      createdSessions.push(input);
    },
    getActiveMfaMethods: async () =>
      hasEnrolledMfa
        ? [
            {
              id: 'mfa-77',
              methodType: 'TOTP',
              encryptedSecret: enrollment.encryptedSecret,
              recoveryCodeHashes: [],
            },
          ]
        : [],
    activateMfaSession: async (sessionId) => {
      activatedSessionId = sessionId;
      return true;
    },
    findUserById: async () => ({
      id: 77n,
      username: 'reader',
      email: 'reader@example.test',
      passwordHash,
      fullName: 'Doc Reader',
      status: 'ACTIVE',
      lockedUntil: null,
      failedLoginCount: 0,
      roles: ['DOCUMENT_READER'],
      requiresMfa: false,
      mfaMethod: null,
    }),
  };

  const authService = new AuthService(
    repository,
    passwords,
    tokens,
    mfa,
    new LoginRateLimitService(cfg),
    { record: async () => undefined },
    {},
    cfg,
  );
  const ctx = { ip: '198.51.100.44', correlationId: '55555555-5555-4555-8555-555555555555' };

  // 1. Password-only user without enrolled MFA gets mfaVerified=false and JWT claim mfa=false
  const pwdSession = await authService.login('reader', passwordPlain, ctx);
  assert.equal(pwdSession.mfaRequired, false);
  assert.equal(createdSessions[0].mfaVerified, false);
  const pwdClaims = await tokens.verifyAccessToken(pwdSession.accessToken);
  assert.equal(pwdClaims.mfa, false);

  // 2. Reader with enrolled MFA enters pre-MFA challenge with mfa=false, then upgrades to mfa=true on verifyMfa
  hasEnrolledMfa = true;
  const preMfaSession = await authService.login('reader', passwordPlain, ctx);
  assert.equal(preMfaSession.mfaRequired, true);
  assert.equal(createdSessions[1].mfaVerified, false);
  const preClaims = await tokens.verifyAccessToken(preMfaSession.accessToken);
  assert.equal(preClaims.mfa, false);

  const upgraded = await authService.verifyMfa(
    {
      userId: 77n,
      sessionId: preClaims.sid,
      username: 'reader',
      roles: ['DOCUMENT_READER'],
      mfa: false,
      mfaPending: true,
    },
    totp.generate(),
    undefined,
    ctx,
  );
  assert.equal(activatedSessionId, preClaims.sid);
  const upgradedClaims = await tokens.verifyAccessToken(upgraded.accessToken);
  assert.equal(upgradedClaims.mfa, true);
});

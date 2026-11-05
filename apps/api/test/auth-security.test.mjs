import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as OTPAuth from 'otpauth';
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

test('TOTP secrets are encrypted and recovery codes are one-time hashes', () => {
  const service = new MfaService(config());
  const enrollment = service.createEnrollment('admin@example.test');
  assert.doesNotMatch(enrollment.encryptedSecret, new RegExp(enrollment.secret));
  const totp = new OTPAuth.TOTP({
    issuer: 'Secure Document Access',
    label: 'admin@example.test',
    secret: OTPAuth.Secret.fromBase32(enrollment.secret),
  });
  assert.equal(service.verifyTotp(enrollment.encryptedSecret, totp.generate()), true);
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

test('brute-force limiter keys attempts by both IP and normalized account', () => {
  const limiter = new LoginRateLimitService();
  limiter.recordFailure('192.0.2.1', 'alice', 1_000);
  limiter.recordFailure('192.0.2.1', 'alice', 1_001);
  const delay = limiter.recordFailure('192.0.2.1', 'alice', 1_002);
  assert.equal(delay, 250);
  assert.throws(() => limiter.assertAllowed('192.0.2.1', 'different', 1_100), /temporarily/u);
  assert.throws(() => limiter.assertAllowed('198.51.100.1', 'alice', 1_100), /temporarily/u);
  assert.doesNotThrow(() => limiter.assertAllowed('198.51.100.1', 'different', 1_100));
});

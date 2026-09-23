import 'reflect-metadata';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { Reflector } from '@nestjs/core';
import { importPKCS8, SignJWT } from 'jose';
import * as OTPAuth from 'otpauth';
import { AuthController } from '../dist/modules/auth/auth.controller.js';
import { AuthGuard } from '../dist/modules/auth/auth.guard.js';
import { AuthService } from '../dist/modules/auth/auth.service.js';
import { CsrfService } from '../dist/modules/auth/csrf.service.js';
import { LoginRateLimitService } from '../dist/modules/auth/login-rate-limit.service.js';
import { MfaService } from '../dist/modules/auth/mfa.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';
import { TokenService } from '../dist/modules/auth/token.service.js';

const pair = generateKeyPairSync('ed25519');
const privatePem = pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
const publicPem = pair.publicKey.export({ format: 'pem', type: 'spki' }).toString();

function config(overrides = {}) {
  const values = {
    AUTH_ACTIVE_KID: 'test-key',
    AUTH_ACCESS_TTL_SECONDS: 300,
    AUTH_REFRESH_TTL_SECONDS: 604800,
    AUTH_RESET_TTL_SECONDS: 900,
    AUTH_ISSUER: 'test-issuer',
    AUTH_AUDIENCE: 'test-audience',
    AUTH_SIGNING_PRIVATE_KEY_PEM: privatePem,
    AUTH_SIGNING_PUBLIC_KEYS_JSON: JSON.stringify([{ kid: 'test-key', publicKeyPem: publicPem }]),
    APP_ENCRYPTION_MASTER_KEY: 'test-master-key-that-is-at-least-thirty-two-characters',
    ...overrides,
  };
  return {
    get: (key) => values[key],
    corsOrigins: ['https://app.internal.test'],
    isProduction: true,
  };
}

async function externallySignedToken(claims = {}, options = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sid: '11111111-1111-4111-8111-111111111111', mfa: true, ...claims })
    .setProtectedHeader({ alg: 'EdDSA', kid: 'test-key' })
    .setSubject('42')
    .setIssuer(options.issuer ?? 'test-issuer')
    .setAudience(options.audience ?? 'test-audience')
    .setIssuedAt(now - 60)
    .setExpirationTime(options.exp ?? now + 60)
    .setJti('22222222-2222-4222-8222-222222222222')
    .sign(await importPKCS8(privatePem, 'EdDSA'));
}

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

test('production cookies are HttpOnly, Secure, SameSite strict and path-scoped', async () => {
  const cookies = [];
  const controller = new AuthController(
    {
      login: async () => ({
        accessToken: 'access-secret',
        refreshToken: 'refresh-secret',
        csrfToken: 'csrf-value',
        accessMaxAge: 300,
        refreshMaxAge: 604800,
        mfaRequired: false,
        enrollmentRequired: false,
      }),
    },
    {},
    config(),
  );
  const reply = {
    setCookie(name, value, options) {
      cookies.push({ name, value, options });
      return this;
    },
    clearCookie() {
      return this;
    },
  };
  const response = await controller.login(
    { identifier: 'alice', password: 'fixture-password-not-returned' },
    { ip: '192.0.2.1', headers: {}, correlationId: 'test' },
    reply,
  );
  assert.equal(response.authenticated, true);
  const access = cookies.find((cookie) => cookie.name === 'sda_access');
  const refresh = cookies.find((cookie) => cookie.name === 'sda_refresh');
  const csrf = cookies.find((cookie) => cookie.name === 'sda_csrf');
  assert.deepEqual(
    [access.options.httpOnly, access.options.secure, access.options.sameSite, access.options.path],
    [true, true, 'strict', '/api/v1'],
  );
  assert.deepEqual(
    [refresh.options.httpOnly, refresh.options.secure, refresh.options.path],
    [true, true, '/api/v1/auth'],
  );
  assert.equal(csrf.options.httpOnly, false);
  assert.equal(JSON.stringify(response).includes('secret'), false);
});

test('revoked database session is rejected even when JWT is cryptographically valid', async () => {
  const tokens = new TokenService(config());
  const guard = new AuthGuard(new Reflector(), tokens, {
    principalForSession: async () => null,
  });
  const token = await tokens.issueAccessToken(42n, '11111111-1111-4111-8111-111111111111', true);
  const handler = () => undefined;
  const context = {
    getHandler: () => handler,
    switchToHttp: () => ({
      getRequest: () => ({ cookies: { sda_access: token } }),
    }),
  };
  await assert.rejects(guard.canActivate(context), /Session is no longer valid/u);
});

test('login failure message and password-work timing do not enumerate accounts', async () => {
  const passwords = new PasswordService();
  const passwordHash = await passwords.hash('valid internal password phrase');
  await passwords.burnEquivalentWork('warm-up-value');
  const activeUser = {
    id: 42n,
    username: 'alice',
    email: 'alice@example.test',
    passwordHash,
    fullName: 'Alice',
    status: 'ACTIVE',
    lockedUntil: null,
    failedLoginCount: 0,
    roles: [],
    mfaMethod: null,
  };
  const repository = {
    findUserByIdentifier: async (identifier) => (identifier === 'alice' ? activeUser : null),
    recordLoginFailure: async () => undefined,
  };
  const audit = { record: async () => undefined };
  const service = new AuthService(
    repository,
    passwords,
    new TokenService(config()),
    new MfaService(config()),
    new LoginRateLimitService(),
    audit,
    {},
    config(),
  );
  async function failedLogin(identifier, ip) {
    const started = performance.now();
    let message;
    try {
      await service.login(identifier, 'wrong password value', {
        ip,
        correlationId: '33333333-3333-4333-8333-333333333333',
      });
    } catch (error) {
      message = error.message;
    }
    return { message, elapsed: performance.now() - started };
  }
  const existing = await failedLogin('alice', '192.0.2.10');
  const missing = await failedLogin('missing', '192.0.2.11');
  assert.equal(existing.message, missing.message);
  assert.ok(Math.abs(existing.elapsed - missing.elapsed) < 250, { existing, missing });
});

test('refresh rotates an opaque token and rejects reuse with an audit event', async () => {
  let calls = 0;
  let reuseAudited = false;
  const user = {
    id: 42n,
    username: 'alice',
    email: 'alice@example.test',
    passwordHash: 'unused',
    fullName: 'Alice',
    status: 'ACTIVE',
    lockedUntil: null,
    failedLoginCount: 0,
    roles: [],
    mfaMethod: null,
  };
  const repository = {
    rotateRefreshToken: async () => {
      calls += 1;
      return calls === 1
        ? { kind: 'rotated', user, sessionId: 'session-1', mfa: true }
        : { kind: 'reuse', userId: 42n, sessionId: 'session-1' };
    },
  };
  const service = new AuthService(
    repository,
    new PasswordService(),
    new TokenService(config()),
    new MfaService(config()),
    new LoginRateLimitService(),
    {
      record: async (event) => {
        if (event.action === 'REFRESH_REUSE') reuseAudited = true;
      },
    },
    {},
    config(),
  );
  const context = {
    ip: '192.0.2.20',
    correlationId: '44444444-4444-4444-8444-444444444444',
  };
  const rotated = await service.refresh('old-opaque-token', context);
  assert.notEqual(rotated.refreshToken, 'old-opaque-token');
  assert.ok(rotated.refreshToken.length >= 43);
  await assert.rejects(service.refresh('old-opaque-token', context), /no longer valid/u);
  assert.equal(reuseAudited, true);
});

test('web source never stores authentication tokens in localStorage', async () => {
  const webRoot = new URL('../../web/', import.meta.url);
  const entries = await readdir(webRoot, { recursive: true, withFileTypes: true });
  const sourceFiles = entries.filter(
    (entry) => entry.isFile() && /\.(?:js|jsx|ts|tsx)$/u.test(entry.name),
  );
  for (const entry of sourceFiles) {
    const contents = await readFile(`${entry.parentPath}/${entry.name}`, 'utf8');
    assert.doesNotMatch(
      contents,
      /localStorage\s*\.\s*(?:setItem|getItem)\s*\([^)]*(?:access|refresh)[_-]?token/iu,
    );
  }
});

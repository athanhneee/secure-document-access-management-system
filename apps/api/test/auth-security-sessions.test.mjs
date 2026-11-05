import 'reflect-metadata';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { Reflector } from '@nestjs/core';
import { AuthController } from '../dist/modules/auth/auth.controller.js';
import { AuthGuard } from '../dist/modules/auth/auth.guard.js';
import { AuthService } from '../dist/modules/auth/auth.service.js';
import { LoginRateLimitService } from '../dist/modules/auth/login-rate-limit.service.js';
import { MfaService } from '../dist/modules/auth/mfa.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';
import { TokenService } from '../dist/modules/auth/token.service.js';
import { config } from './helpers/auth-security-mocks.mjs';

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
  await passwords.verify(passwordHash, 'warm-up-value');
  await passwords.burnEquivalentWork('warm-up-value');
  let dummyWorkCount = 0;
  const originalBurn = passwords.burnEquivalentWork.bind(passwords);
  passwords.burnEquivalentWork = async (password) => {
    dummyWorkCount += 1;
    return originalBurn(password);
  };
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
  assert.equal(dummyWorkCount, 1);
  assert.ok(
    Math.abs(existing.elapsed - missing.elapsed) < 1500,
    `Login timing delta exceeded bound: existing=${existing.elapsed}ms, missing=${missing.elapsed}ms`,
  );
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
    (entry) =>
      entry.isFile() &&
      /\.(?:js|jsx|ts|tsx)$/u.test(entry.name) &&
      !/[\\/](?:node_modules|\.next)(?:[\\/]|$)/u.test(entry.parentPath),
  );
  for (const entry of sourceFiles) {
    const contents = await readFile(`${entry.parentPath}/${entry.name}`, 'utf8');
    assert.doesNotMatch(
      contents,
      /localStorage\s*\.\s*(?:setItem|getItem)\s*\([^)]*(?:access|refresh)[_-]?token/iu,
    );
  }
});

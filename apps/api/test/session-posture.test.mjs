import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AppConfigService } from '../dist/config/config.service.js';
import {
  evaluateSessionSecurityPosture,
  sanitizeDeviceFingerprintHeader,
} from '../dist/modules/auth/auth-session-posture.helper.js';
import { AuthController } from '../dist/modules/auth/auth.controller.js';
import { CsrfService } from '../dist/modules/auth/csrf.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';
import { UsersService } from '../dist/modules/users/users.service.js';

const BUSINESS_HOURS_DATE = new Date('2026-06-15T03:00:00.000Z');
const OFF_HOURS_DATE = new Date('2026-06-15T16:30:00.000Z');

test('sanitizeDeviceFingerprintHeader trims valid fingerprints and rejects empty/oversized/non-string values', () => {
  assert.equal(
    sanitizeDeviceFingerprintHeader('  dfp-0123456789abcdef0123456789abcdef  '),
    'dfp-0123456789abcdef0123456789abcdef',
  );
  assert.equal(sanitizeDeviceFingerprintHeader('   '), undefined);
  assert.equal(sanitizeDeviceFingerprintHeader('a'.repeat(256)), undefined);
  assert.equal(sanitizeDeviceFingerprintHeader(undefined), undefined);
});

test('evaluateSessionSecurityPosture reflects MFA, trusted network, deviceFingerprint trust, and high-risk blocking', async () => {
  const config = new AppConfigService({
    ABAC_TRUSTED_NETWORK_CIDRS: '127.0.0.0/8,10.0.0.0/8',
  });
  const knownFingerprint = 'dfp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

  const db = {
    authSession: {
      findUnique: async () => ({ ip_address: '10.0.0.5', user_agent: 'CorpBrowser/1.0' }),
    },
    user: {
      findUnique: async () => ({ failed_login_count: 0 }),
    },
    securityAlert: {
      findMany: async () => [],
    },
    accessSession: {
      findFirst: async ({ where }) =>
        where.device_fingerprint === knownFingerprint ? { id: 'known-sess-1' } : null,
    },
    mfaMethod: {
      count: async () => 1,
    },
  };

  // Trusted network + known device + MFA verified -> risk 0, all clear
  const clean = await evaluateSessionSecurityPosture({
    database: db,
    config,
    principal: {
      userId: 10n,
      sessionId: 'auth-1',
      username: 'reader',
      roles: ['DOCUMENT_READER'],
      mfa: true,
    },
    context: { ip: '10.0.0.5', userAgent: 'CorpBrowser/1.0', correlationId: 'c1' },
    deviceFingerprint: knownFingerprint,
    now: BUSINESS_HOURS_DATE,
  });
  assert.equal(clean.mfaVerified, true);
  assert.equal(clean.mfaEnabled, true);
  assert.equal(clean.trustedNetwork, true);
  assert.equal(clean.deviceTrust, true);
  assert.equal(clean.riskScore, 0);
  assert.equal(clean.sensitiveRiskScore, 0);
  assert.equal(clean.highRiskBlocked, false);
  assert.equal(clean.topSecretRequiresMfa, false);

  // External network + off-hours + no MFA + unseen device + 1 HIGH alert -> risk 90 >= 80 (highRiskBlocked)
  const riskyDb = {
    ...db,
    securityAlert: {
      findMany: async () => [{ severity: 'HIGH' }],
    },
  };
  const risky = await evaluateSessionSecurityPosture({
    database: riskyDb,
    config,
    principal: {
      userId: 10n,
      sessionId: 'auth-2',
      username: 'reader',
      roles: ['DOCUMENT_READER'],
      mfa: false,
    },
    context: { ip: '203.0.113.20', userAgent: 'CorpBrowser/1.0', correlationId: 'c2' },
    deviceFingerprint: 'dfp-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    now: OFF_HOURS_DATE,
  });
  assert.equal(risky.mfaVerified, false);
  assert.equal(risky.trustedNetwork, false);
  assert.equal(risky.deviceTrust, false);
  assert.equal(risky.highRiskBlocked, true);
  assert.ok(risky.riskScore >= 80);
  assert.equal(risky.sensitiveRiskScore, 100);
  assert.ok(risky.riskFactors.includes('UNTRUSTED_NETWORK'));
  assert.ok(risky.riskFactors.includes('NO_MFA'));
  assert.ok(risky.riskFactors.includes('ACTIVE_HIGH_SECURITY_ALERT'));
});

test('AuthController.getSessionPosture forwards sanitized x-device-fingerprint and UsersService.currentUser exposes mfaVerified', async () => {
  let capturedFingerprint = null;
  const mockAuthService = {
    getSessionPosture: async (_principal, _ctx, fp) => {
      capturedFingerprint = fp;
      return {
        mfaVerified: false,
        mfaEnabled: true,
        trustedNetwork: true,
        deviceTrust: true,
        riskScore: 15,
        sensitiveRiskScore: 25,
        riskThreshold: 80,
        highRiskBlocked: false,
        sensitiveHighRiskBlocked: false,
        topSecretRequiresMfa: true,
        riskFactors: ['NO_MFA'],
        evaluatedAt: BUSINESS_HOURS_DATE.toISOString(),
      };
    },
  };
  const config = new AppConfigService({ NODE_ENV: 'test' });
  const controller = new AuthController(mockAuthService, new CsrfService(config), config);

  const posture = await controller.getSessionPosture({
    auth: {
      userId: 5n,
      sessionId: 's-1',
      username: 'reader.test',
      roles: ['DOCUMENT_READER'],
      mfa: false,
    },
    ip: '127.0.0.1',
    headers: { 'x-device-fingerprint': 'dfp-11112222333344445555666677778888' },
  });
  assert.equal(capturedFingerprint, 'dfp-11112222333344445555666677778888');
  assert.equal(posture.mfaVerified, false);
  assert.equal(posture.topSecretRequiresMfa, true);

  const mockDb = {
    user: {
      findUnique: async () => ({
        id: 5n,
        username: 'reader.test',
        email: 'reader@local.invalid',
        full_name: 'Reader Test',
        department_id: 1n,
        status: 'ACTIVE',
        version: 1,
        departments: { id: 1n, name: 'Khối Kỹ Thuật' },
      }),
    },
    mfaMethod: { count: async () => 1 },
    userAttributeAssignment: { findFirst: async () => null },
  };
  const usersService = new UsersService(
    { effectiveGrants: async () => [] },
    new PasswordService(),
    { record: async () => {} },
    mockDb,
  );
  const meWithoutMfa = await usersService.currentUser({
    userId: 5n,
    sessionId: 's-1',
    username: 'reader.test',
    roles: ['DOCUMENT_READER'],
    mfa: false,
  });
  assert.equal(meWithoutMfa.mfaEnabled, true);
  assert.equal(meWithoutMfa.mfaVerified, false);

  const meWithMfa = await usersService.currentUser({
    userId: 5n,
    sessionId: 's-2',
    username: 'reader.test',
    roles: ['DOCUMENT_READER'],
    mfa: true,
  });
  assert.equal(meWithMfa.mfaEnabled, true);
  assert.equal(meWithMfa.mfaVerified, true);
});

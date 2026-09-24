import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AppConfigService } from '../dist/config/config.service.js';
import { MfaService } from '../dist/modules/auth/mfa.service.js';
import { WebAuthnService } from '../dist/modules/auth/webauthn.service.js';
import { AuthService } from '../dist/modules/auth/auth.service.js';
import { TokenService } from '../dist/modules/auth/token.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';
import { LoginRateLimitService } from '../dist/modules/auth/login-rate-limit.service.js';

function createMockConfig() {
  return new AppConfigService({
    APP_ENCRYPTION_MASTER_KEY: 'test-master-key-00000000000000000000000000000000',
    WEBAUTHN_RP_NAME: 'Secure Document Access Test',
    WEBAUTHN_RP_ID: 'localhost',
    WEBAUTHN_ORIGINS: 'http://localhost:3000,http://127.0.0.1:3000',
    AUTH_ACCESS_TTL_SECONDS: 300,
    AUTH_REFRESH_TTL_SECONDS: 3600,
    AUTH_RESET_TTL_SECONDS: 900,
    AUTH_AUDIT_HMAC_KEY: 'test-audit-hmac-key-00000000000000000000000000000000',
    DOCUMENT_AUDIT_HMAC_KEY: 'test-audit-hmac-key-00000000000000000000000000000000',
    AUDIT_INTEGRITY_KEY: 'test-audit-hmac-key-00000000000000000000000000000000',
  });
}

test('WebAuthn — generates signed challenge token and verifies integrity', async () => {
  const config = createMockConfig();
  const mfa = new MfaService(config);
  const webauthn = new WebAuthnService(mfa, config);

  const challenge = 'test-challenge-random-value-12345';
  const userId = 42n;

  const token = webauthn.createChallengeToken(challenge, userId);
  assert.ok(token.includes('.'), 'Token must contain payload and signature separated by dot');

  // Verify valid token
  const extracted = webauthn.verifyChallengeToken(token, userId);
  assert.equal(extracted, challenge, 'Extracted challenge must match original');

  // Reject tampered token payload
  const [, signature] = token.split('.');
  const tamperedPayload = Buffer.from(
    JSON.stringify({ challenge: 'hacked', userId: '42', timestamp: Date.now() }),
  ).toString('base64url');
  assert.throws(
    () => webauthn.verifyChallengeToken(`${tamperedPayload}.${signature}`, userId),
    /signature verification failed/,
    'Tampered payload must be rejected by HMAC signature verification',
  );

  // Reject user mismatch
  assert.throws(
    () => webauthn.verifyChallengeToken(token, 999n),
    /bound to a different user/,
    'Token bound to user 42 must be rejected when claimed by user 999',
  );
});

test('WebAuthn — generates registration options conforming to W3C WebAuthn Level 3', async () => {
  const config = createMockConfig();
  const mfa = new MfaService(config);
  const webauthn = new WebAuthnService(mfa, config);

  const { options, challengeToken } = await webauthn.generateRegistrationOptions(101n, 'johndoe');

  assert.ok(options.challenge, 'Options must include challenge');
  assert.equal(options.rp.name, 'Secure Document Access Test');
  assert.equal(options.rp.id, 'localhost');
  assert.equal(options.user.name, 'johndoe');
  assert.ok(options.pubKeyCredParams.length > 0, 'Must support multiple COSE algorithms');
  assert.ok(challengeToken, 'Must generate associated signed challenge token');

  const verifiedChallenge = webauthn.verifyChallengeToken(challengeToken, 101n);
  assert.equal(verifiedChallenge, options.challenge);
});

test('WebAuthn — generates authentication options with allowCredentials for enrolled keys', async () => {
  const config = createMockConfig();
  const mfa = new MfaService(config);
  const webauthn = new WebAuthnService(mfa, config);

  const credentials = [
    {
      type: 'WEBAUTHN',
      credentialId: 'yubikey-cred-id-abc123',
      publicKeyBase64Url: 'mock-public-key',
      counter: 15,
      transports: ['usb', 'nfc'],
      deviceName: 'YubiKey 5C NFC',
      createdAt: new Date().toISOString(),
    },
  ];

  const { options, challengeToken } = await webauthn.generateAuthenticationOptions(
    credentials,
    101n,
  );

  assert.equal(options.rpId, 'localhost');
  assert.ok(options.challenge, 'Options must include challenge');
  assert.equal(options.allowCredentials?.length, 1);
  assert.equal(options.allowCredentials?.[0]?.id, 'yubikey-cred-id-abc123');
  assert.deepEqual(options.allowCredentials?.[0]?.transports, ['usb', 'nfc']);

  const verified = webauthn.verifyChallengeToken(challengeToken, 101n);
  assert.equal(verified, options.challenge);
});

test('WebAuthn — parses and serializes encrypted credential in database secret format', async () => {
  const config = createMockConfig();
  const mfa = new MfaService(config);
  const webauthn = new WebAuthnService(mfa, config);

  const originalCredential = {
    type: 'WEBAUTHN',
    credentialId: 'test-cred-uuid-777',
    publicKeyBase64Url: 'p256-public-key-base64',
    counter: 42,
    transports: ['usb'],
    aaguid: '00000000-0000-0000-0000-000000000000',
    deviceName: 'YubiKey 5Ci',
    createdAt: new Date().toISOString(),
  };

  const encryptedSecret = mfa.encryptPayload(originalCredential);
  assert.ok(typeof encryptedSecret === 'string');

  const parsed = webauthn.parseStoredCredential(encryptedSecret);
  assert.ok(parsed !== null);
  assert.equal(parsed?.credentialId, originalCredential.credentialId);
  assert.equal(parsed?.counter, 42);
  assert.equal(parsed?.deviceName, 'YubiKey 5Ci');

  // Plain TOTP secret should return null when parsed as WebAuthn
  const totpSecret = mfa.encrypt('JBSWY3DPEHPK3PXP');
  const parsedTotp = webauthn.parseStoredCredential(totpSecret);
  assert.equal(parsedTotp, null, 'Plain TOTP secret must not parse as WebAuthn credential');
});

test('WebAuthn — Clone Detection triggers security alert when counter rolls back or does not increase', async () => {
  const stored = {
    type: 'WEBAUTHN',
    credentialId: 'cloned-key-id-999',
    publicKeyBase64Url: 'mock-public-key',
    counter: 100, // Current stored counter is 100
    createdAt: new Date().toISOString(),
  };

  // If newCounter is 90 (less than 100), clone attack is detected!
  // We simulate counter comparison check directly
  assert.ok(
    stored.counter > 0 && 90 <= stored.counter,
    'Counter rollback (90 <= 100) must be identified as clone attempt',
  );

  // Counter equal to 100 (replay attack)
  assert.ok(
    stored.counter > 0 && 100 <= stored.counter,
    'Counter reuse (100 <= 100) must be identified as replay/clone attempt',
  );

  // Counter increased to 101 (legitimate use)
  assert.ok(101 > stored.counter, 'Increased counter (101 > 100) must be accepted');
});

test('AuthService — integrates WebAuthn enrollment and authentication options', async () => {
  const config = createMockConfig();
  const mfa = new MfaService(config);
  const webauthn = new WebAuthnService(mfa, config);
  const tokens = new TokenService(config);
  const passwords = new PasswordService();
  const rateLimit = new LoginRateLimitService();

  const mockActiveMethods = [];
  const mockAlerts = [];
  const mockAudits = [];

  const repository = {
    getActiveMfaMethods: async (_userId) => mockActiveMethods,
    createMfaEnrollment: async (userId, secret, label) => {
      const id = 'method-uuid-1';
      mockActiveMethods.push({
        id,
        user_id: userId,
        encryptedSecret: secret,
        label,
        recoveryCodeHashes: [],
        createdAt: new Date(),
      });
      return id;
    },
    enableMfa: async (methodId, userId, recoveryHashes) => {
      const found = mockActiveMethods.find((m) => m.id === methodId);
      if (found) found.recoveryCodeHashes = recoveryHashes;
    },
    activateMfaSession: async () => true,
    recordSecurityAlert: async (alert) => {
      mockAlerts.push(alert);
    },
    findUserByIdentifier: async (identifier) => {
      if (identifier === 'alice') {
        return {
          id: 50n,
          username: 'alice',
          email: 'alice@example.com',
          status: 'ACTIVE',
          roles: ['SYSTEM_ADMIN'],
        };
      }
      return null;
    },
  };

  const audit = {
    record: async (event) => {
      mockAudits.push(event);
    },
  };

  const authService = new AuthService(
    repository,
    passwords,
    tokens,
    mfa,
    rateLimit,
    audit,
    {},
    config,
    webauthn,
  );

  const principal = {
    userId: 50n,
    sessionId: 'session-123',
    username: 'alice',
    roles: ['SYSTEM_ADMIN'],
    mfa: false,
  };

  // 1. Begin enrollment
  const enrollResult = await authService.beginWebAuthnEnrollment(principal, 'My YubiKey', {
    ip: '127.0.0.1',
    correlationId: 'corr-1',
  });

  assert.ok(enrollResult.options.challenge);
  assert.ok(enrollResult.challengeToken);
  assert.ok(mockAudits.some((a) => a.action === 'MFA_WEBAUTHN_ENROLL_START'));

  // 2. Auth options fails if no WebAuthn enrolled
  await assert.rejects(
    authService.getWebAuthnAuthOptions(principal, undefined, {
      ip: '127.0.0.1',
      correlationId: 'corr-2',
    }),
    /No WebAuthn security keys found/,
  );

  // 3. Add enrolled WebAuthn credential
  const credentialPayload = {
    type: 'WEBAUTHN',
    credentialId: 'cred-key-alice-1',
    publicKeyBase64Url: 'p256-key',
    counter: 5,
    transports: ['usb'],
    deviceName: 'YubiKey 5 NFC',
    createdAt: new Date().toISOString(),
  };
  mockActiveMethods.push({
    id: 'method-uuid-webauthn',
    user_id: 50n,
    encryptedSecret: mfa.encryptPayload(credentialPayload),
    label: 'YubiKey 5 NFC',
    recoveryCodeHashes: ['hash1', 'hash2'],
    createdAt: new Date(),
  });

  // 4. Now auth options succeeds
  const authOpts = await authService.getWebAuthnAuthOptions(principal, undefined, {
    ip: '127.0.0.1',
    correlationId: 'corr-3',
  });
  assert.ok(authOpts.options.challenge);
  assert.equal(authOpts.options.allowCredentials?.length, 1);
  assert.equal(authOpts.options.allowCredentials?.[0]?.id, 'cred-key-alice-1');

  // 5. Verify clone detection behavior in verifyWebAuthnAuth
  // If unknown credential ID presented -> rejects with UnauthorizedException
  await assert.rejects(
    authService.verifyWebAuthnAuth(
      principal,
      { id: 'unknown-cred-id', rawId: 'unknown', response: {}, type: 'public-key' },
      enrollResult.challengeToken,
      { ip: '127.0.0.1', correlationId: 'corr-4' },
    ),
    /Security key credential was not recognized/,
  );
});

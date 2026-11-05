import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createWebAuthnAuthHarness, createWebAuthnPair } from './helpers/webauthn-mocks.mjs';

test('WebAuthn — generates signed challenge token and verifies integrity', async () => {
  const { webauthn } = createWebAuthnPair();

  const challenge = 'test-challenge-random-value-12345';
  const userId = 42n;

  const token = webauthn.createChallengeToken(challenge, userId);
  assert.ok(token.includes('.'), 'Token must contain payload and signature separated by dot');

  const extracted = webauthn.verifyChallengeToken(token, userId);
  assert.equal(extracted, challenge, 'Extracted challenge must match original');

  const [, signature] = token.split('.');
  const tamperedPayload = Buffer.from(
    JSON.stringify({ challenge: 'hacked', userId: '42', timestamp: Date.now() }),
  ).toString('base64url');
  assert.throws(
    () => webauthn.verifyChallengeToken(`${tamperedPayload}.${signature}`, userId),
    /signature verification failed/,
    'Tampered payload must be rejected by HMAC signature verification',
  );

  assert.throws(
    () => webauthn.verifyChallengeToken(token, 999n),
    /bound to a different user/,
    'Token bound to user 42 must be rejected when claimed by user 999',
  );
});

test('WebAuthn — generates registration options conforming to W3C WebAuthn Level 3', async () => {
  const { webauthn } = createWebAuthnPair();

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
  const { webauthn } = createWebAuthnPair();

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
  const { mfa, webauthn } = createWebAuthnPair();

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

  const totpSecret = mfa.encrypt('JBSWY3DPEHPK3PXP');
  const parsedTotp = webauthn.parseStoredCredential(totpSecret);
  assert.equal(parsedTotp, null, 'Plain TOTP secret must not parse as WebAuthn credential');
});

test('WebAuthn — Clone Detection triggers CRITICAL security alert & audit via real AuthService when counter rolls back', async () => {
  const { mfa, authService, webauthn, mockActiveMethods, mockAlerts, mockAudits } =
    createWebAuthnAuthHarness();

  const stored = {
    type: 'WEBAUTHN',
    credentialId: 'cloned-key-id-999',
    publicKeyBase64Url: Buffer.alloc(32, 7).toString('base64url'),
    counter: 100,
    transports: ['usb'],
    deviceName: 'Cloned YubiKey',
    createdAt: new Date().toISOString(),
  };
  mockActiveMethods.push({
    id: 'method-cloned-999',
    user_id: 50n,
    encryptedSecret: mfa.encryptPayload(stored),
    label: 'Cloned YubiKey',
    recoveryCodeHashes: [],
    createdAt: new Date(),
  });

  const challengeToken = webauthn.createChallengeToken('challenge-clone-check-123456', 50n);
  const originalVerify = webauthn.verifyAuthentication.bind(webauthn);
  webauthn.verifyAuthentication = async () => ({
    verified: true,
    newCounter: 90,
    cloneDetected: true,
    updatedEncryptedSecret: mfa.encryptPayload({ ...stored, counter: 90 }),
  });

  try {
    await assert.rejects(
      async () =>
        authService.verifyWebAuthnAuth(
          {
            userId: 50n,
            sessionId: 'sess-clone-50',
            username: 'alice',
            roles: ['SYSTEM_ADMIN'],
            mfa: false,
          },
          { id: 'cloned-key-id-999', rawId: 'cloned-key-id-999', response: {}, type: 'public-key' },
          challengeToken,
          { ip: '198.51.100.77', correlationId: 'corr-clone-1' },
        ),
      /Security key cloning or replay attack detected/i,
    );
  } finally {
    webauthn.verifyAuthentication = originalVerify;
  }

  assert.equal(mockAlerts.length, 1);
  assert.equal(mockAlerts[0].alertType, 'WEBAUTHN_CLONE_DETECTED');
  assert.equal(mockAlerts[0].severity, 'CRITICAL');
  assert.ok(
    mockAudits.some(
      (a) =>
        a.action === 'MFA_WEBAUTHN_VERIFY' &&
        a.outcome === 'DENIED' &&
        a.reasonCode === 'CLONE_DETECTED',
    ),
  );
});

test('AuthService — integrates WebAuthn enrollment and authentication options', async () => {
  const { mfa, authService, mockActiveMethods, mockAudits } = createWebAuthnAuthHarness();

  const principal = {
    userId: 50n,
    sessionId: 'session-123',
    username: 'alice',
    roles: ['SYSTEM_ADMIN'],
    mfa: false,
  };

  const enrollResult = await authService.beginWebAuthnEnrollment(principal, 'My YubiKey', {
    ip: '127.0.0.1',
    correlationId: 'corr-1',
  });

  assert.ok(enrollResult.options.challenge);
  assert.ok(enrollResult.challengeToken);
  assert.ok(mockAudits.some((a) => a.action === 'MFA_WEBAUTHN_ENROLL_START'));

  await assert.rejects(
    authService.getWebAuthnAuthOptions(principal, undefined, {
      ip: '127.0.0.1',
      correlationId: 'corr-2',
    }),
    /No WebAuthn security keys found/,
  );

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

  const authOpts = await authService.getWebAuthnAuthOptions(principal, undefined, {
    ip: '127.0.0.1',
    correlationId: 'corr-3',
  });
  assert.ok(authOpts.options.challenge);
  assert.equal(authOpts.options.allowCredentials?.length, 1);
  assert.equal(authOpts.options.allowCredentials?.[0]?.id, 'cred-key-alice-1');

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

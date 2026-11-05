import { AppConfigService } from '../../dist/config/config.service.js';
import { MfaService } from '../../dist/modules/auth/mfa.service.js';
import { WebAuthnService } from '../../dist/modules/auth/webauthn.service.js';
import { AuthService } from '../../dist/modules/auth/auth.service.js';
import { TokenService } from '../../dist/modules/auth/token.service.js';
import { PasswordService } from '../../dist/modules/auth/password.service.js';
import { LoginRateLimitService } from '../../dist/modules/auth/login-rate-limit.service.js';

export function createMockConfig() {
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

export function createWebAuthnPair() {
  const config = createMockConfig();
  const mfa = new MfaService(config);
  const webauthn = new WebAuthnService(mfa, config);
  return { config, mfa, webauthn };
}

export function createWebAuthnAuthHarness() {
  const { config, mfa, webauthn } = createWebAuthnPair();
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
    enableMfa: async (methodId, _userId, recoveryHashes) => {
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

  return { mfa, webauthn, authService, mockActiveMethods, mockAlerts, mockAudits };
}

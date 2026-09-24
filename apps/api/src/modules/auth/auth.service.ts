import { randomBytes, randomUUID } from 'node:crypto';
import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Optional,
  UnauthorizedException,
} from '@nestjs/common';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { AppConfigService } from '../../config/config.service.js';
import { AuthAuditService } from './auth-audit.service.js';
import { AuthRepository } from './auth.repository.js';
import { MFA_REQUIRED_ROLES, type AuthPrincipal, type RequestContext } from './auth.types.js';
import { LoginRateLimitService } from './login-rate-limit.service.js';
import { MfaService } from './mfa.service.js';
import { PasswordService } from './password.service.js';
import { ResetMailerService } from './reset-mailer.service.js';
import { TokenService } from './token.service.js';
import { WebAuthnService, type StoredWebAuthnCredential } from './webauthn.service.js';

export interface SessionArtifacts {
  accessToken: string;
  refreshToken?: string | undefined;
  csrfToken: string;
  accessMaxAge: number;
  refreshMaxAge: number;
  mfaRequired: boolean;
  enrollmentRequired: boolean;
}

const GENERIC_LOGIN_ERROR = 'Unable to authenticate with the supplied credentials.';
const GENERIC_RESET_RESPONSE =
  'If the account is eligible, password reset instructions will be sent.';

@Injectable()
export class AuthService {
  private readonly accessTtl: number;
  private readonly refreshTtl: number;
  private readonly resetTtl: number;
  private readonly webauthn: WebAuthnService;

  constructor(
    private readonly repository: AuthRepository,
    private readonly passwords: PasswordService,
    private readonly tokens: TokenService,
    private readonly mfa: MfaService,
    private readonly rateLimit: LoginRateLimitService,
    private readonly audit: AuthAuditService,
    private readonly mailer: ResetMailerService,
    config: AppConfigService,
    @Optional() webauthn?: WebAuthnService,
  ) {
    this.webauthn = webauthn ?? new WebAuthnService(this.mfa, config);
    this.accessTtl = config.get('AUTH_ACCESS_TTL_SECONDS');
    this.refreshTtl = config.get('AUTH_REFRESH_TTL_SECONDS');
    this.resetTtl = config.get('AUTH_RESET_TTL_SECONDS');
  }

  async login(
    identifier: string,
    password: string,
    context: RequestContext,
  ): Promise<SessionArtifacts> {
    const accountKey = identifier.normalize('NFKC').trim().toLowerCase();
    this.rateLimit.assertAllowed(context.ip, accountKey);
    const user = await this.repository.findUserByIdentifier(accountKey);
    const passwordMatches = user
      ? await this.passwords.verify(user.passwordHash, password)
      : (await this.passwords.burnEquivalentWork(password), false);
    const eligible =
      user?.status === 'ACTIVE' && (!user.lockedUntil || user.lockedUntil <= new Date());
    if (!user || !passwordMatches || !eligible) {
      const delayMs = this.rateLimit.recordFailure(context.ip, accountKey);
      if (user) await this.repository.recordLoginFailure(user);
      await this.audit.record(
        {
          action: 'LOGIN',
          outcome: 'DENIED',
          actorUserId: user?.id,
          actorUsername: user?.username ?? accountKey.slice(0, 80),
          reasonCode: 'INVALID_CREDENTIALS',
          details: { delayMs },
        },
        context,
      );
      throw new UnauthorizedException(GENERIC_LOGIN_ERROR);
    }

    this.rateLimit.clearAccount(accountKey);
    await this.repository.recordLoginSuccess(user.id);
    const mfaRequired = user.roles.some((role) => MFA_REQUIRED_ROLES.has(role));
    const artifacts = await this.startSession(user.id, context, !mfaRequired, mfaRequired);
    await this.audit.record(
      {
        action: 'LOGIN',
        outcome: 'SUCCESS',
        actorUserId: user.id,
        actorUsername: user.username,
        objectId: artifacts.sessionId,
        details: { mfaRequired },
      },
      context,
    );
    return {
      ...artifacts,
      mfaRequired,
      enrollmentRequired: mfaRequired && !user.mfaMethod,
    };
  }

  async refresh(refreshToken: string, context: RequestContext): Promise<SessionArtifacts> {
    const nextToken = this.tokens.newOpaqueToken();
    const result = await this.repository.rotateRefreshToken(
      this.tokens.hashOpaqueToken(refreshToken),
      {
        id: randomUUID(),
        hash: this.tokens.hashOpaqueToken(nextToken),
        expiresAt: new Date(Date.now() + this.refreshTtl * 1_000),
      },
    );
    if (result.kind === 'reuse') {
      await this.audit.record(
        {
          action: 'REFRESH_REUSE',
          outcome: 'DENIED',
          actorUserId: result.userId,
          objectId: result.sessionId,
          reasonCode: 'REFRESH_TOKEN_REUSE',
        },
        context,
      );
      throw new UnauthorizedException('Session is no longer valid.');
    }
    if (result.kind !== 'rotated') throw new UnauthorizedException('Session is no longer valid.');
    const accessToken = await this.tokens.issueAccessToken(
      result.user.id,
      result.sessionId,
      result.mfa,
    );
    await this.audit.record(
      {
        action: 'TOKEN_REFRESH',
        outcome: 'SUCCESS',
        actorUserId: result.user.id,
        objectId: result.sessionId,
      },
      context,
    );
    return {
      accessToken,
      refreshToken: nextToken,
      csrfToken: randomBytes(32).toString('base64url'),
      accessMaxAge: this.accessTtl,
      refreshMaxAge: this.refreshTtl,
      mfaRequired: false,
      enrollmentRequired: false,
    };
  }

  async logout(principal: AuthPrincipal, context: RequestContext): Promise<void> {
    await this.repository.revokeSession(principal.sessionId, principal.userId, 'USER_LOGOUT');
    await this.audit.record(
      {
        action: 'LOGOUT',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        objectId: principal.sessionId,
      },
      context,
    );
  }

  async logoutAll(principal: AuthPrincipal, context: RequestContext): Promise<void> {
    const count = await this.repository.revokeAllSessions(principal.userId, 'USER_LOGOUT_ALL');
    await this.audit.record(
      {
        action: 'LOGOUT_ALL',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        details: { revokedSessions: count },
      },
      context,
    );
  }

  async changePassword(
    principal: AuthPrincipal,
    currentPassword: string,
    newPassword: string,
    context: RequestContext,
  ): Promise<void> {
    const user = await this.repository.findUserById(principal.userId);
    if (!user || !(await this.passwords.verify(user.passwordHash, currentPassword))) {
      throw new UnauthorizedException(GENERIC_LOGIN_ERROR);
    }
    this.passwords.validate(newPassword, [user.username, user.email]);
    await this.repository.updatePassword(user.id, await this.passwords.hash(newPassword));
    await this.repository.revokeAllSessions(user.id, 'PASSWORD_CHANGED');
    await this.audit.record(
      { action: 'PASSWORD_CHANGE', outcome: 'SUCCESS', actorUserId: user.id },
      context,
    );
  }

  async forgotPassword(identifier: string, context: RequestContext): Promise<{ message: string }> {
    const startedAt = Date.now();
    const normalized = identifier.normalize('NFKC').trim().toLowerCase();
    await this.passwords.burnEquivalentWork(normalized);
    const user = await this.repository.findUserByIdentifier(normalized);
    if (user?.status === 'ACTIVE') {
      const token = this.tokens.newOpaqueToken();
      await this.repository.createPasswordReset(
        user.id,
        this.tokens.hashOpaqueToken(token),
        new Date(Date.now() + this.resetTtl * 1_000),
        context.ip,
      );
      try {
        await this.mailer.send(user.email, token);
        await this.audit.record(
          { action: 'PASSWORD_RESET_REQUEST', outcome: 'SUCCESS', actorUserId: user.id },
          context,
        );
      } catch {
        await this.audit.record(
          {
            action: 'PASSWORD_RESET_REQUEST',
            outcome: 'FAILED',
            actorUserId: user.id,
            reasonCode: 'DELIVERY_FAILED',
          },
          context,
        );
      }
    } else {
      await this.audit.record(
        { action: 'PASSWORD_RESET_REQUEST', outcome: 'SUCCESS', actorUsername: 'anonymous' },
        context,
      );
    }
    // Keep the externally visible response floor independent of lookup and SMTP outcome.
    const remainingDelay = 1_250 - (Date.now() - startedAt);
    if (remainingDelay > 0) await new Promise((resolve) => setTimeout(resolve, remainingDelay));
    return { message: GENERIC_RESET_RESPONSE };
  }

  async resetPassword(token: string, newPassword: string, context: RequestContext): Promise<void> {
    this.passwords.validate(newPassword);
    const userId = await this.repository.consumePasswordReset(
      this.tokens.hashOpaqueToken(token),
      await this.passwords.hash(newPassword),
    );
    if (!userId) throw new BadRequestException('Reset request is invalid or expired.');
    await this.audit.record(
      { action: 'PASSWORD_RESET', outcome: 'SUCCESS', actorUserId: userId },
      context,
    );
  }

  async beginMfaEnrollment(
    principal: AuthPrincipal,
    label: string | undefined,
    context: RequestContext,
  ): Promise<{ secret: string; uri: string }> {
    const enrollment = this.mfa.createEnrollment(principal.username);
    await this.repository.createMfaEnrollment(principal.userId, enrollment.encryptedSecret, label);
    await this.audit.record(
      { action: 'MFA_ENROLLMENT_STARTED', outcome: 'SUCCESS', actorUserId: principal.userId },
      context,
    );
    return { secret: enrollment.secret, uri: enrollment.uri };
  }

  async verifyMfaEnrollment(
    principal: AuthPrincipal,
    code: string,
    context: RequestContext,
  ): Promise<SessionArtifacts & { recoveryCodes: string[] }> {
    const pending = await this.repository.pendingMfaMethod(principal.userId);
    if (!pending || !this.mfa.verifyTotp(pending.encryptedSecret, code)) {
      throw new UnauthorizedException('MFA verification failed.');
    }
    const recovery = this.mfa.createRecoveryCodes();
    await this.repository.enableMfa(pending.id, principal.userId, recovery.hashes);
    const artifacts = await this.activateMfaSession(principal);
    await this.audit.record(
      { action: 'MFA_ENABLED', outcome: 'SUCCESS', actorUserId: principal.userId },
      context,
    );
    return { ...artifacts, recoveryCodes: recovery.plaintext };
  }

  async beginWebAuthnEnrollment(
    principal: AuthPrincipal,
    label: string | undefined,
    context: RequestContext,
  ) {
    const existing = await this.repository.getActiveMfaMethods(principal.userId);
    const existingCreds = existing
      .map((m) => this.webauthn.parseStoredCredential(m.encryptedSecret))
      .filter((c): c is StoredWebAuthnCredential => c !== null);

    const { options, challengeToken } = await this.webauthn.generateRegistrationOptions(
      principal.userId,
      principal.username,
      existingCreds,
    );

    await this.audit.record(
      {
        action: 'MFA_WEBAUTHN_ENROLL_START',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        details: { label: label ?? null },
      },
      context,
    );

    return { options, challengeToken };
  }

  async verifyWebAuthnEnrollment(
    principal: AuthPrincipal,
    response: RegistrationResponseJSON,
    challengeToken: string,
    label: string | undefined,
    context: RequestContext,
  ): Promise<SessionArtifacts & { recoveryCodes: string[] }> {
    const verification = await this.webauthn.verifyRegistration(
      response,
      challengeToken,
      principal.userId,
      label,
    );

    const recovery = this.mfa.createRecoveryCodes();
    const methodId = await this.repository.createMfaEnrollment(
      principal.userId,
      verification.encryptedSecret,
      label ?? 'FIDO2 / WebAuthn Key',
    );
    await this.repository.enableMfa(methodId, principal.userId, recovery.hashes);

    const artifacts = await this.activateMfaSession(principal);
    await this.audit.record(
      {
        action: 'MFA_WEBAUTHN_ENROLLED',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        objectId: methodId,
        details: {
          credentialId: verification.credential.credentialId,
          deviceName: verification.credential.deviceName ?? null,
          aaguid: verification.credential.aaguid ?? null,
        },
      },
      context,
    );

    return { ...artifacts, recoveryCodes: recovery.plaintext };
  }

  async getWebAuthnAuthOptions(
    principal: AuthPrincipal | undefined,
    username: string | undefined,
    context: RequestContext,
  ) {
    let userId: bigint | undefined = principal?.userId;
    if (!userId && username) {
      const user = await this.repository.findUserByIdentifier(username.trim().toLowerCase());
      if (user) userId = user.id;
    }

    if (!userId) {
      throw new BadRequestException('User identification is required for WebAuthn authentication.');
    }

    const activeMethods = await this.repository.getActiveMfaMethods(userId);
    const webauthnCreds = activeMethods
      .map((m) => this.webauthn.parseStoredCredential(m.encryptedSecret))
      .filter((c): c is StoredWebAuthnCredential => c !== null);

    if (webauthnCreds.length === 0) {
      throw new BadRequestException('No WebAuthn security keys found for this account.');
    }

    const { options, challengeToken } = await this.webauthn.generateAuthenticationOptions(
      webauthnCreds,
      userId,
    );

    await this.audit.record(
      {
        action: 'MFA_WEBAUTHN_AUTH_OPTIONS',
        outcome: 'SUCCESS',
        actorUserId: userId,
      },
      context,
    );

    return { options, challengeToken };
  }

  async verifyWebAuthnAuth(
    principal: AuthPrincipal,
    response: AuthenticationResponseJSON,
    challengeToken: string,
    context: RequestContext,
  ): Promise<SessionArtifacts> {
    const activeMethods = await this.repository.getActiveMfaMethods(principal.userId);
    let matchedMethod: (typeof activeMethods)[number] | null = null;
    let matchedCred: StoredWebAuthnCredential | null = null;

    for (const m of activeMethods) {
      const cred = this.webauthn.parseStoredCredential(m.encryptedSecret);
      if (cred && cred.credentialId === response.id) {
        matchedMethod = m;
        matchedCred = cred;
        break;
      }
    }

    if (!matchedMethod || !matchedCred) {
      await this.audit.record(
        {
          action: 'MFA_WEBAUTHN_VERIFY',
          outcome: 'DENIED',
          actorUserId: principal.userId,
          reasonCode: 'CREDENTIAL_NOT_FOUND',
        },
        context,
      );
      throw new UnauthorizedException('Security key credential was not recognized for this user.');
    }

    const result = await this.webauthn.verifyAuthentication(
      response,
      challengeToken,
      matchedCred,
      principal.userId,
    );

    if (result.cloneDetected) {
      await this.repository.recordSecurityAlert({
        alertType: 'WEBAUTHN_CLONE_DETECTED',
        severity: 'CRITICAL',
        title: 'FIDO2 / WebAuthn clone attack detected',
        description: `Authenticator counter rollback or cloned key detected for user ID ${principal.userId}.`,
        detectedUserId: principal.userId,
      });

      await this.audit.record(
        {
          action: 'MFA_WEBAUTHN_VERIFY',
          outcome: 'DENIED',
          actorUserId: principal.userId,
          reasonCode: 'CLONE_DETECTED',
          details: { credentialId: matchedCred.credentialId },
        },
        context,
      );

      throw new UnauthorizedException('Security key cloning or replay attack detected.');
    }

    await this.repository.updateMfaSecret(matchedMethod.id, result.updatedEncryptedSecret);

    const artifacts = await this.activateMfaSession(principal);
    await this.audit.record(
      {
        action: 'MFA_WEBAUTHN_VERIFY',
        outcome: 'SUCCESS',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        objectId: matchedMethod.id,
        details: {
          credentialId: matchedCred.credentialId,
          counter: result.newCounter,
        },
      },
      context,
    );

    return artifacts;
  }

  async verifyMfa(
    principal: AuthPrincipal,
    code: string | undefined,
    recoveryCode: string | undefined,
    context: RequestContext,
  ): Promise<SessionArtifacts> {
    const activeMethods = await this.repository.getActiveMfaMethods(principal.userId);
    if (activeMethods.length === 0) throw new UnauthorizedException('MFA verification failed.');

    let valid = false;
    if (code) {
      for (const method of activeMethods) {
        try {
          if (this.mfa.verifyTotp(method.encryptedSecret, code)) {
            valid = true;
            break;
          }
        } catch {
          // Ignore non-TOTP secrets
        }
      }
    }

    if (!valid && recoveryCode) {
      for (const method of activeMethods) {
        const remaining = this.mfa.consumeRecoveryCode(method.recoveryCodeHashes, recoveryCode);
        if (remaining) {
          await this.repository.consumeRecoveryCode(method.id, remaining);
          valid = true;
          break;
        }
      }
    }

    if (!valid) {
      await this.audit.record(
        { action: 'MFA_VERIFY', outcome: 'DENIED', actorUserId: principal.userId },
        context,
      );
      throw new UnauthorizedException('MFA verification failed.');
    }
    const artifacts = await this.activateMfaSession(principal);
    await this.audit.record(
      { action: 'MFA_VERIFY', outcome: 'SUCCESS', actorUserId: principal.userId },
      context,
    );
    return artifacts;
  }

  async disableMfa(principal: AuthPrincipal, context: RequestContext): Promise<void> {
    if (!principal.mfa) throw new ForbiddenException('Verified MFA is required.');
    await this.repository.disableMfa(principal.userId);
    await this.repository.revokeAllSessions(principal.userId, 'MFA_CHANGED');
    await this.audit.record(
      { action: 'MFA_DISABLED', outcome: 'SUCCESS', actorUserId: principal.userId },
      context,
    );
  }

  jwks(): ReturnType<TokenService['jwks']> {
    return this.tokens.jwks();
  }

  private async startSession(
    userId: bigint,
    context: RequestContext,
    issueRefresh: boolean,
    preMfa: boolean,
  ): Promise<SessionArtifacts & { sessionId: string }> {
    const sessionId = randomUUID();
    const familyId = randomUUID();
    const refreshToken = issueRefresh ? this.tokens.newOpaqueToken() : undefined;
    const lifetime = preMfa ? 300 : this.refreshTtl;
    await this.repository.createSession({
      userId,
      sessionId,
      familyId,
      refreshTokenId: refreshToken ? randomUUID() : undefined,
      refreshTokenHash: refreshToken ? this.tokens.hashOpaqueToken(refreshToken) : undefined,
      refreshExpiresAt: refreshToken ? new Date(Date.now() + this.refreshTtl * 1_000) : undefined,
      sessionExpiresAt: new Date(Date.now() + lifetime * 1_000),
      mfaVerified: !preMfa,
      context,
    });
    return {
      sessionId,
      accessToken: await this.tokens.issueAccessToken(userId, sessionId, !preMfa),
      refreshToken,
      csrfToken: randomBytes(32).toString('base64url'),
      accessMaxAge: preMfa ? 300 : this.accessTtl,
      refreshMaxAge: this.refreshTtl,
      mfaRequired: preMfa,
      enrollmentRequired: false,
    };
  }

  private async activateMfaSession(principal: AuthPrincipal): Promise<SessionArtifacts> {
    const refreshToken = this.tokens.newOpaqueToken();
    const activated = await this.repository.activateMfaSession(
      principal.sessionId,
      principal.userId,
      {
        id: randomUUID(),
        hash: this.tokens.hashOpaqueToken(refreshToken),
        expiresAt: new Date(Date.now() + this.refreshTtl * 1_000),
      },
    );
    if (!activated) throw new UnauthorizedException('Session is no longer valid.');
    return {
      accessToken: await this.tokens.issueAccessToken(principal.userId, principal.sessionId, true),
      refreshToken,
      csrfToken: randomBytes(32).toString('base64url'),
      accessMaxAge: this.accessTtl,
      refreshMaxAge: this.refreshTtl,
      mfaRequired: false,
      enrollmentRequired: false,
    };
  }
}

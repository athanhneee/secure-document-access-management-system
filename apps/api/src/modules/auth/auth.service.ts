/**
 * @module AuthService
 * Algorithm: Constant-Work Multi-Stage Login, RFC 9700 Token Rotation & Multi-Factor Authentication Facade.
 */
import { Injectable, Optional } from '@nestjs/common';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { AppConfigService } from '../../config/config.service.js';
import { AuthAuditService } from './auth-audit.service.js';
import {
  executeBeginMfaEnrollment,
  executeDisableMfa,
  executeVerifyMfa,
  executeVerifyMfaEnrollment,
} from './auth-mfa.helper.js';
import {
  executeChangePassword,
  executeForgotPassword,
  executeResetPassword,
} from './auth-password.helper.js';
import { executeLogin, executeRefresh } from './auth-session.helper.js';
import {
  executeBeginWebAuthnEnrollment,
  executeGetWebAuthnAuthOptions,
  executeVerifyWebAuthnAuth,
  executeVerifyWebAuthnEnrollment,
} from './auth-webauthn.helper.js';
import { AuthRepository } from './auth.repository.js';
import type { AuthPrincipal, RequestContext } from './auth.types.js';
import { LoginRateLimitService } from './login-rate-limit.service.js';
import { MfaService } from './mfa.service.js';
import { PasswordService } from './password.service.js';
import { ResetMailerService } from './reset-mailer.service.js';
import { TokenService } from './token.service.js';
import { WebAuthnService } from './webauthn.service.js';

export interface SessionArtifacts {
  accessToken: string;
  refreshToken?: string | undefined;
  csrfToken: string;
  accessMaxAge: number;
  refreshMaxAge: number;
  mfaRequired: boolean;
  enrollmentRequired: boolean;
}

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

  login(identifier: string, password: string, context: RequestContext): Promise<SessionArtifacts> {
    return executeLogin(this.deps(), identifier, password, context);
  }

  refresh(refreshToken: string, context: RequestContext): Promise<SessionArtifacts> {
    return executeRefresh(this.deps(), refreshToken, context);
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

  changePassword(
    principal: AuthPrincipal,
    currentPassword: string,
    newPassword: string,
    context: RequestContext,
  ): Promise<void> {
    return executeChangePassword(this.deps(), principal, currentPassword, newPassword, context);
  }

  forgotPassword(identifier: string, context: RequestContext): Promise<{ message: string }> {
    return executeForgotPassword(this.deps(), identifier, context);
  }

  resetPassword(token: string, newPassword: string, context: RequestContext): Promise<void> {
    return executeResetPassword(this.deps(), token, newPassword, context);
  }

  beginMfaEnrollment(
    principal: AuthPrincipal,
    label: string | undefined,
    context: RequestContext,
  ): Promise<{ secret: string; uri: string }> {
    return executeBeginMfaEnrollment(this.deps(), principal, label, context);
  }

  verifyMfaEnrollment(
    principal: AuthPrincipal,
    code: string,
    context: RequestContext,
  ): Promise<SessionArtifacts & { recoveryCodes: string[] }> {
    return executeVerifyMfaEnrollment(this.deps(), principal, code, context);
  }

  beginWebAuthnEnrollment(
    principal: AuthPrincipal,
    label: string | undefined,
    context: RequestContext,
  ) {
    return executeBeginWebAuthnEnrollment(this.deps(), principal, label, context);
  }

  verifyWebAuthnEnrollment(
    principal: AuthPrincipal,
    response: RegistrationResponseJSON,
    challengeToken: string,
    label: string | undefined,
    context: RequestContext,
  ): Promise<SessionArtifacts & { recoveryCodes: string[] }> {
    return executeVerifyWebAuthnEnrollment(
      this.deps(),
      principal,
      response,
      challengeToken,
      label,
      context,
    );
  }

  getWebAuthnAuthOptions(
    principal: AuthPrincipal | undefined,
    username: string | undefined,
    context: RequestContext,
  ) {
    return executeGetWebAuthnAuthOptions(this.deps(), principal, username, context);
  }

  verifyWebAuthnAuth(
    principal: AuthPrincipal,
    response: AuthenticationResponseJSON,
    challengeToken: string,
    context: RequestContext,
  ): Promise<SessionArtifacts> {
    return executeVerifyWebAuthnAuth(this.deps(), principal, response, challengeToken, context);
  }

  verifyMfa(
    principal: AuthPrincipal,
    code: string | undefined,
    recoveryCode: string | undefined,
    context: RequestContext,
  ): Promise<SessionArtifacts> {
    return executeVerifyMfa(this.deps(), principal, code, recoveryCode, context);
  }

  disableMfa(
    principal: AuthPrincipal,
    currentPassword: string,
    code: string | undefined,
    recoveryCode: string | undefined,
    context: RequestContext,
  ): Promise<void> {
    return executeDisableMfa(this.deps(), principal, currentPassword, code, recoveryCode, context);
  }

  jwks(): ReturnType<TokenService['jwks']> {
    return this.tokens.jwks();
  }

  private deps() {
    return {
      repository: this.repository,
      passwords: this.passwords,
      tokens: this.tokens,
      mfa: this.mfa,
      rateLimit: this.rateLimit,
      audit: this.audit,
      mailer: this.mailer,
      webauthn: this.webauthn,
      accessTtl: this.accessTtl,
      refreshTtl: this.refreshTtl,
      resetTtl: this.resetTtl,
    };
  }
}

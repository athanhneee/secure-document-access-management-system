import { randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import type { AuthPrincipal, AuthUser, RequestContext } from './auth.types.js';

interface SessionTokensInput {
  userId: bigint;
  sessionId: string;
  familyId: string;
  refreshTokenId?: string | undefined;
  refreshTokenHash?: string | undefined;
  refreshExpiresAt?: Date | undefined;
  sessionExpiresAt: Date;
  mfaVerified: boolean;
  context: RequestContext;
}

export type RotationResult =
  | { kind: 'rotated'; user: AuthUser; sessionId: string; mfa: boolean }
  | { kind: 'reuse'; userId: bigint; sessionId: string }
  | { kind: 'invalid' | 'disabled' };

@Injectable()
export class AuthRepository {
  private readonly database = getDatabaseClient();

  async findUserByIdentifier(identifier: string): Promise<AuthUser | null> {
    const user = await this.database.user.findFirst({
      where: {
        OR: [
          { username: { equals: identifier, mode: 'insensitive' } },
          { email: { equals: identifier, mode: 'insensitive' } },
        ],
      },
      include: {
        user_roles_user_roles_user_idTousers: {
          where: {
            valid_from: { lte: new Date() },
            AND: [
              { OR: [{ valid_to: null }, { valid_to: { gt: new Date() } }] },
              { OR: [{ scope_department_id: null }, { departments: { is: { is_active: true } } }] },
            ],
            roles: { is_active: true },
          },
          include: { roles: true },
        },
        mfa_methods: {
          where: { enabled_at: { not: null }, disabled_at: null },
          take: 1,
        },
      },
    });
    return user ? this.toAuthUser(user) : null;
  }

  async findUserById(userId: bigint): Promise<AuthUser | null> {
    const user = await this.database.user.findUnique({
      where: { id: userId },
      include: {
        user_roles_user_roles_user_idTousers: {
          where: {
            valid_from: { lte: new Date() },
            AND: [
              { OR: [{ valid_to: null }, { valid_to: { gt: new Date() } }] },
              { OR: [{ scope_department_id: null }, { departments: { is: { is_active: true } } }] },
            ],
            roles: { is_active: true },
          },
          include: { roles: true },
        },
        mfa_methods: {
          where: { enabled_at: { not: null }, disabled_at: null },
          take: 1,
        },
      },
    });
    return user ? this.toAuthUser(user) : null;
  }

  async recordLoginFailure(user: AuthUser): Promise<void> {
    const failures = user.failedLoginCount + 1;
    const lockSeconds = failures < 5 ? 0 : Math.min(900, 30 * 2 ** Math.min(failures - 5, 5));
    await this.database.user.update({
      where: { id: user.id },
      data: {
        failed_login_count: { increment: 1 },
        locked_until: lockSeconds > 0 ? new Date(Date.now() + lockSeconds * 1_000) : null,
      },
    });
  }

  async recordLoginSuccess(userId: bigint): Promise<void> {
    await this.database.user.update({
      where: { id: userId },
      data: { failed_login_count: 0, locked_until: null, last_login_at: new Date() },
    });
  }

  async createSession(input: SessionTokensInput): Promise<void> {
    await this.database.$transaction(async (transaction) => {
      await transaction.authSession.create({
        data: {
          id: input.sessionId,
          user_id: input.userId,
          token_family_id: input.familyId,
          ip_address: input.context.ip,
          user_agent: input.context.userAgent ?? null,
          mfa_verified_at: input.mfaVerified ? new Date() : null,
          expires_at: input.sessionExpiresAt,
        },
      });
      if (input.refreshTokenId && input.refreshTokenHash && input.refreshExpiresAt) {
        await transaction.refreshToken.create({
          data: {
            id: input.refreshTokenId,
            auth_session_id: input.sessionId,
            token_family_id: input.familyId,
            token_hash: input.refreshTokenHash,
            expires_at: input.refreshExpiresAt,
          },
        });
      }
    });
  }

  async activateMfaSession(
    sessionId: string,
    userId: bigint,
    refresh: { id: string; hash: string; expiresAt: Date },
  ): Promise<boolean> {
    return this.database.$transaction(async (transaction) => {
      const session = await transaction.authSession.findFirst({
        where: { id: sessionId, user_id: userId, status: 'ACTIVE', expires_at: { gt: new Date() } },
      });
      if (!session) return false;
      await transaction.authSession.update({
        where: { id: sessionId },
        data: {
          mfa_verified_at: new Date(),
          last_seen_at: new Date(),
          expires_at: refresh.expiresAt,
        },
      });
      await transaction.refreshToken.create({
        data: {
          id: refresh.id,
          auth_session_id: session.id,
          token_family_id: session.token_family_id,
          token_hash: refresh.hash,
          expires_at: refresh.expiresAt,
        },
      });
      return true;
    });
  }

  async rotateRefreshToken(
    oldHash: string,
    replacement: { id: string; hash: string; expiresAt: Date },
  ): Promise<RotationResult> {
    return this.database.$transaction(async (transaction) => {
      const current = await transaction.refreshToken.findUnique({
        where: { token_hash: oldHash },
        include: { auth_sessions: { include: { users: true } } },
      });
      if (!current) return { kind: 'invalid' };
      const session = current.auth_sessions;
      if (session.users.status === 'DISABLED') {
        await this.revokeFamily(
          transaction,
          current.token_family_id,
          session.id,
          'ACCOUNT_DISABLED',
        );
        return { kind: 'disabled' };
      }
      if (current.used_at || current.revoked_at) {
        await this.revokeFamily(transaction, current.token_family_id, session.id, 'REFRESH_REUSE');
        await transaction.securityAlert.create({
          data: {
            id: randomUUID(),
            alert_type: 'REFRESH_TOKEN_REUSE',
            severity: 'HIGH',
            title: 'Refresh token reuse detected',
            description: 'An already rotated or revoked refresh token was presented.',
            detected_user_id: session.user_id,
          },
        });
        return { kind: 'reuse', userId: session.user_id, sessionId: session.id };
      }
      if (
        current.expires_at <= new Date() ||
        session.expires_at <= new Date() ||
        session.status !== 'ACTIVE'
      ) {
        return { kind: 'invalid' };
      }
      const claimed = await transaction.refreshToken.updateMany({
        where: { id: current.id, used_at: null, revoked_at: null },
        data: { used_at: new Date(), revoked_at: new Date(), revocation_reason: 'ROTATED' },
      });
      if (claimed.count !== 1) {
        await this.revokeFamily(transaction, current.token_family_id, session.id, 'REFRESH_REUSE');
        await transaction.securityAlert.create({
          data: {
            id: randomUUID(),
            alert_type: 'REFRESH_TOKEN_REUSE',
            severity: 'HIGH',
            title: 'Concurrent refresh token reuse detected',
            description: 'A refresh token lost an atomic rotation race.',
            detected_user_id: session.user_id,
          },
        });
        return { kind: 'reuse', userId: session.user_id, sessionId: session.id };
      }
      await transaction.refreshToken.create({
        data: {
          id: replacement.id,
          auth_session_id: session.id,
          token_family_id: current.token_family_id,
          token_hash: replacement.hash,
          parent_token_id: current.id,
          expires_at: replacement.expiresAt,
        },
      });
      await transaction.authSession.update({
        where: { id: session.id },
        data: { last_seen_at: new Date() },
      });
      const user = await this.findUserById(session.user_id);
      return user
        ? {
            kind: 'rotated',
            user,
            sessionId: session.id,
            mfa: session.mfa_verified_at !== null,
          }
        : { kind: 'invalid' };
    });
  }

  async principalForSession(userId: bigint, sessionId: string): Promise<AuthPrincipal | null> {
    const [session, user] = await Promise.all([
      this.database.authSession.findFirst({
        where: { id: sessionId, user_id: userId, status: 'ACTIVE', expires_at: { gt: new Date() } },
      }),
      this.findUserById(userId),
    ]);
    if (!session || !user || user.status !== 'ACTIVE') return null;
    return {
      userId,
      sessionId,
      username: user.username,
      roles: user.roles,
      mfa: session.mfa_verified_at !== null,
    };
  }

  async revokeSession(sessionId: string, userId: bigint, reason: string): Promise<boolean> {
    return this.database.$transaction(async (transaction) => {
      const session = await transaction.authSession.findFirst({
        where: { id: sessionId, user_id: userId, status: 'ACTIVE' },
      });
      if (!session) return false;
      await this.revokeFamily(transaction, session.token_family_id, session.id, reason);
      return true;
    });
  }

  async revokeAllSessions(userId: bigint, reason: string): Promise<number> {
    return this.database.$transaction(async (transaction) => {
      const sessions = await transaction.authSession.findMany({
        where: { user_id: userId, status: 'ACTIVE' },
      });
      for (const session of sessions) {
        await this.revokeFamily(transaction, session.token_family_id, session.id, reason);
      }
      return sessions.length;
    });
  }

  async updatePassword(userId: bigint, passwordHash: string): Promise<void> {
    await this.database.user.update({
      where: { id: userId },
      data: { password_hash: passwordHash },
    });
  }

  async createPasswordReset(
    userId: bigint,
    tokenHash: string,
    expiresAt: Date,
    ip: string,
  ): Promise<void> {
    await this.database.$transaction(async (transaction) => {
      await transaction.passwordResetToken.updateMany({
        where: { user_id: userId, used_at: null },
        data: { used_at: new Date() },
      });
      await transaction.passwordResetToken.create({
        data: {
          id: randomUUID(),
          user_id: userId,
          token_hash: tokenHash,
          expires_at: expiresAt,
          requested_ip: ip,
        },
      });
    });
  }

  async consumePasswordReset(tokenHash: string, passwordHash: string): Promise<bigint | null> {
    return this.database.$transaction(async (transaction) => {
      const token = await transaction.passwordResetToken.findUnique({
        where: { token_hash: tokenHash },
        include: { users: true },
      });
      if (
        !token ||
        token.used_at ||
        token.expires_at <= new Date() ||
        token.users.status === 'DISABLED'
      ) {
        return null;
      }
      const claimed = await transaction.passwordResetToken.updateMany({
        where: { id: token.id, used_at: null, expires_at: { gt: new Date() } },
        data: { used_at: new Date() },
      });
      if (claimed.count !== 1) return null;
      await transaction.user.update({
        where: { id: token.user_id },
        data: { password_hash: passwordHash, failed_login_count: 0, locked_until: null },
      });
      const sessions = await transaction.authSession.findMany({
        where: { user_id: token.user_id, status: 'ACTIVE' },
      });
      for (const session of sessions) {
        await this.revokeFamily(transaction, session.token_family_id, session.id, 'PASSWORD_RESET');
      }
      return token.user_id;
    });
  }

  async createMfaEnrollment(
    userId: bigint,
    encryptedSecret: string,
    label?: string,
  ): Promise<string> {
    const existing = await this.database.mfaMethod.findFirst({
      where: { user_id: userId, disabled_at: null },
    });
    if (existing) {
      await this.database.mfaMethod.update({
        where: { id: existing.id },
        data: {
          secret_encrypted: encryptedSecret,
          label: label ?? null,
          verified_at: null,
          enabled_at: null,
          recovery_code_hashes: [],
        },
      });
      return existing.id;
    }
    const id = randomUUID();
    await this.database.mfaMethod.create({
      data: { id, user_id: userId, secret_encrypted: encryptedSecret, label: label ?? null },
    });
    return id;
  }

  async pendingMfaMethod(userId: bigint): Promise<{ id: string; encryptedSecret: string } | null> {
    const method = await this.database.mfaMethod.findFirst({
      where: { user_id: userId, verified_at: null, disabled_at: null },
    });
    return method ? { id: method.id, encryptedSecret: method.secret_encrypted } : null;
  }

  async enableMfa(methodId: string, userId: bigint, recoveryHashes: string[]): Promise<void> {
    await this.database.mfaMethod.updateMany({
      where: { id: methodId, user_id: userId, verified_at: null, disabled_at: null },
      data: {
        verified_at: new Date(),
        enabled_at: new Date(),
        recovery_code_hashes: recoveryHashes,
      },
    });
  }

  async consumeRecoveryCode(methodId: string, hashes: string[]): Promise<void> {
    await this.database.mfaMethod.update({
      where: { id: methodId },
      data: { recovery_code_hashes: hashes },
    });
  }

  async disableMfa(userId: bigint): Promise<boolean> {
    const result = await this.database.mfaMethod.updateMany({
      where: { user_id: userId, enabled_at: { not: null }, disabled_at: null },
      data: { disabled_at: new Date() },
    });
    return result.count > 0;
  }

  private async revokeFamily(
    transaction: Pick<ReturnType<typeof getDatabaseClient>, 'refreshToken' | 'authSession'>,
    familyId: string,
    sessionId: string,
    reason: string,
  ): Promise<void> {
    const now = new Date();
    await transaction.refreshToken.updateMany({
      where: { token_family_id: familyId, revoked_at: null },
      data: { revoked_at: now, revocation_reason: reason },
    });
    await transaction.authSession.updateMany({
      where: { id: sessionId, status: 'ACTIVE' },
      data: { status: 'REVOKED', revoked_at: now, revocation_reason: reason },
    });
  }

  private toAuthUser(user: {
    id: bigint;
    username: string;
    email: string;
    password_hash: string;
    full_name: string;
    status: 'PENDING' | 'ACTIVE' | 'LOCKED' | 'DISABLED';
    locked_until: Date | null;
    failed_login_count: number;
    user_roles_user_roles_user_idTousers: Array<{ roles: { code: string } }>;
    mfa_methods: Array<{ id: string; secret_encrypted: string; recovery_code_hashes: unknown }>;
  }): AuthUser {
    const method = user.mfa_methods[0];
    const recoveryHashes = Array.isArray(method?.recovery_code_hashes)
      ? method.recovery_code_hashes.filter((value): value is string => typeof value === 'string')
      : [];
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      passwordHash: user.password_hash,
      fullName: user.full_name,
      status: user.status,
      lockedUntil: user.locked_until,
      failedLoginCount: user.failed_login_count,
      roles: user.user_roles_user_roles_user_idTousers.map((assignment) => assignment.roles.code),
      mfaMethod: method
        ? {
            id: method.id,
            encryptedSecret: method.secret_encrypted,
            recoveryCodeHashes: recoveryHashes,
          }
        : null,
    };
  }
}

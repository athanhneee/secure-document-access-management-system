/**
 * @module AuthRepository
 * Algorithm: Threshold Exponential Lockout, Atomic CAS Password Reset & Session/MFA Repository Facade.
 */
import { Injectable } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import type { AuthPrincipal, AuthUser } from './auth.types.js';
import {
  activateMfaAuthSession,
  createAuthSession,
  revokeAllUserSessions,
  revokeSingleSession,
  rotateSessionRefreshToken,
  type RotationResult,
  type SessionTokensInput,
} from './auth-session.repository.js';
import {
  queryActiveUserSessions,
  revokeOtherActiveUserSessions,
  type ActiveAuthSessionItem,
} from './auth-sessions-management.helper.js';
import {
  advanceWebAuthnCounterAtomic,
  consumeMfaRecoveryCode,
  consumeMfaRecoveryCodeAtomic,
  createUserMfaEnrollment,
  disableUserMfaMethods,
  enableUserMfaMethod,
  findPendingMfaMethod,
  insertSecurityAlert,
  listActiveMfaMethods,
  updateUserMfaSecret,
  type ActiveMfaMethodRecord,
} from './auth-mfa.repository.js';
import {
  buildActiveUserInclude,
  consumeUserPasswordReset,
  createUserPasswordReset,
  findPasswordResetTokenOwner,
  mapRecordToAuthUser,
} from './auth-user.repository.js';

export type { RotationResult, SessionTokensInput } from './auth-session.repository.js';

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
      include: buildActiveUserInclude(new Date()),
    });
    return user ? mapRecordToAuthUser(user) : null;
  }

  async findUserById(userId: bigint): Promise<AuthUser | null> {
    const user = await this.database.user.findUnique({
      where: { id: userId },
      include: buildActiveUserInclude(new Date()),
    });
    return user ? mapRecordToAuthUser(user) : null;
  }

  /**
   * Algorithm / Thuật toán: Khóa tài khoản lũy thừa đơn điệu theo ngưỡng thất bại liên tiếp (`GREATEST(existingLockedUntil, candidateLockUntil)`).
   * Cơ chế hoạt động:
   *   - Tính bước phạt tự động `min(900s, 30 * 2^min(failures - 5, 5))` khi `failures >= 5`.
   *   - Đối chiếu với `locked_until` hiện hữu của quản trị viên (cả trên đối tượng `user` lẫn bản ghi DB mới nhất);
   *     chỉ nâng mốc khóa về tương lai xa hơn và tuyệt đối không xóa (`null`) hay rút ngắn thời hạn khóa quản trị (MED-02).
   */
  async recordLoginFailure(user: AuthUser): Promise<void> {
    const failures = user.failedLoginCount + 1;
    const lockSeconds = failures < 5 ? 0 : Math.min(900, 30 * 2 ** Math.min(failures - 5, 5));
    const candidateLockUntil = lockSeconds > 0 ? new Date(Date.now() + lockSeconds * 1_000) : null;
    const latestRow =
      typeof this.database.user.findUnique === 'function'
        ? await this.database.user.findUnique({
            where: { id: user.id },
            select: { locked_until: true },
          })
        : null;
    const existingLock = [
      user.lockedUntil ?? null,
      latestRow?.locked_until ?? null,
    ].reduce<Date | null>((acc, cur) => {
      if (!cur) return acc;
      if (!acc) return cur;
      return cur.getTime() > acc.getTime() ? cur : acc;
    }, null);
    // CONFLICT-RESOLVED: Giữ nguyên mốc khóa quản trị viên dài hạn thay vì ghi đè bằng null hoặc thời hạn khóa tự động ngắn hơn (MED-02).
    const effectiveLockUntil =
      existingLock && (!candidateLockUntil || existingLock.getTime() > candidateLockUntil.getTime())
        ? existingLock
        : candidateLockUntil;

    await this.database.user.update({
      where: { id: user.id },
      data: {
        failed_login_count: { increment: 1 },
        ...(effectiveLockUntil !== null ? { locked_until: effectiveLockUntil } : {}),
      },
    });
  }

  async recordLoginSuccess(userId: bigint): Promise<void> {
    await this.database.user.update({
      where: { id: userId },
      data: { failed_login_count: 0, locked_until: null, last_login_at: new Date() },
    });
  }

  createSession(input: SessionTokensInput): Promise<void> {
    return createAuthSession(this.database, input);
  }

  activateMfaSession(
    sessionId: string,
    userId: bigint,
    refresh: { id: string; hash: string; expiresAt: Date },
  ): Promise<string | null> {
    return activateMfaAuthSession(this.database, sessionId, userId, refresh);
  }

  rotateRefreshToken(
    oldHash: string,
    replacement: { id: string; hash: string; expiresAt: Date },
  ): Promise<RotationResult> {
    return rotateSessionRefreshToken(this.database, oldHash, replacement, (id) =>
      this.findUserById(id),
    );
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

  revokeSession(sessionId: string, userId: bigint, reason: string): Promise<boolean> {
    return revokeSingleSession(this.database, sessionId, userId, reason);
  }

  revokeAllSessions(userId: bigint, reason: string): Promise<number> {
    return revokeAllUserSessions(this.database, userId, reason);
  }

  listActiveSessions(userId: bigint, currentSessionId: string): Promise<ActiveAuthSessionItem[]> {
    return queryActiveUserSessions(this.database, userId, currentSessionId);
  }

  revokeOtherSessions(userId: bigint, currentSessionId: string, reason: string): Promise<number> {
    return revokeOtherActiveUserSessions(this.database, userId, currentSessionId, reason);
  }

  async updatePassword(userId: bigint, passwordHash: string): Promise<void> {
    await this.database.user.update({
      where: { id: userId },
      data: { password_hash: passwordHash },
    });
  }

  createPasswordReset(
    userId: bigint,
    tokenHash: string,
    expiresAt: Date,
    ip: string,
  ): Promise<void> {
    return createUserPasswordReset(this.database, userId, tokenHash, expiresAt, ip);
  }

  findPasswordResetOwner(
    tokenHash: string,
  ): Promise<{ userId: bigint; username: string; email: string } | null> {
    return findPasswordResetTokenOwner(this.database, tokenHash);
  }

  consumePasswordReset(tokenHash: string, passwordHash: string): Promise<bigint | null> {
    return consumeUserPasswordReset(this.database, tokenHash, passwordHash);
  }

  createMfaEnrollment(
    userId: bigint,
    encryptedSecret: string,
    label?: string,
    methodType: 'TOTP' | 'WEBAUTHN' = 'TOTP',
  ): Promise<string> {
    return createUserMfaEnrollment(this.database, userId, encryptedSecret, label, methodType);
  }

  pendingMfaMethod(userId: bigint): Promise<{ id: string; encryptedSecret: string } | null> {
    return findPendingMfaMethod(this.database, userId);
  }

  enableMfa(methodId: string, userId: bigint, recoveryHashes: string[]): Promise<void> {
    return enableUserMfaMethod(this.database, methodId, userId, recoveryHashes);
  }

  consumeRecoveryCode(methodId: string, hashes: string[]): Promise<void> {
    return consumeMfaRecoveryCode(this.database, methodId, hashes);
  }

  consumeRecoveryCodeAtomic(
    userId: bigint,
    candidateCode: string,
    consumeFn: (hashes: string[], candidate: string) => string[] | null,
  ): Promise<boolean> {
    return consumeMfaRecoveryCodeAtomic(this.database, userId, candidateCode, consumeFn);
  }

  advanceWebAuthnCounter<TCred extends { counter: number }>(
    methodId: string,
    userId: bigint,
    newCounter: number,
    parseFn: (encryptedSecret: string) => TCred | null,
    encryptFn: (updated: TCred) => string,
  ): Promise<'updated' | 'clone_detected' | 'not_found'> {
    return advanceWebAuthnCounterAtomic(
      this.database,
      methodId,
      userId,
      newCounter,
      parseFn,
      encryptFn,
    );
  }

  updateMfaSecret(methodId: string, encryptedSecret: string): Promise<void> {
    return updateUserMfaSecret(this.database, methodId, encryptedSecret);
  }

  getActiveMfaMethods(userId: bigint): Promise<ActiveMfaMethodRecord[]> {
    return listActiveMfaMethods(this.database, userId);
  }

  recordSecurityAlert(data: {
    alertType: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    title: string;
    description: string;
    detectedUserId?: bigint;
  }): Promise<void> {
    return insertSecurityAlert(this.database, data);
  }

  disableMfa(userId: bigint): Promise<boolean> {
    return disableUserMfaMethods(this.database, userId);
  }
}

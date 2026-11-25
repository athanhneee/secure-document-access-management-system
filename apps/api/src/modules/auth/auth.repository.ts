/**
 * @module AuthRepository
 * Thuật toán: Mặt tiền kho dữ liệu xác thực, xoay vòng phiên/Refresh Token, MFA và vô hiệu hóa bộ đệm phiên phân tán theo Epoch.
 */
import { Injectable, Optional } from '@nestjs/common';
import { getDatabaseClient, type Prisma } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import { DistributedStateService } from '../concurrency/distributed-state.service.js';
import {
  MFA_REQUIRED_ROLES,
  type AuthPrincipal,
  type AuthUser,
  type RequestContext,
} from './auth.types.js';
import {
  activateMfaAuthSession,
  completeAuthLoginSession,
  createAuthSession,
  revokeAllUserSessions,
  revokeSingleSession,
  rotateSessionRefreshToken,
  type RotationResult,
  type SessionTokensInput,
} from './auth-session.repository.js';
import {
  DEFAULT_AUTH_SESSION_IDLE_TTL_SECONDS,
  DEFAULT_MAX_CONCURRENT_SESSIONS,
  MAX_LISTED_ACTIVE_SESSIONS,
  expireAuthSessionFamily,
  queryActiveUserSessions,
  revokeOtherActiveUserSessions,
  touchAuthSessionActivity,
  type ActiveAuthSessionItem,
} from './auth-sessions-management.helper.js';
import {
  advanceWebAuthnCounterAtomic,
  consumeMfaRecoveryCode,
  consumeMfaRecoveryCodeAtomic,
  createUserMfaEnrollment,
  disableSingleUserMfaMethod,
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
  recordUserLoginFailure,
} from './auth-user.repository.js';

export type { RotationResult, SessionTokensInput } from './auth-session.repository.js';

@Injectable()
export class AuthRepository {
  private readonly database = getDatabaseClient();
  private readonly stateStore: DistributedStateService;
  private readonly idleTtlSeconds: number;
  private readonly maxConcurrentSessions: number;

  constructor(
    @Optional() config?: AppConfigService,
    @Optional() stateStore?: DistributedStateService,
  ) {
    this.stateStore = stateStore ?? new DistributedStateService(config);
    const configuredIdle = config?.get('AUTH_SESSION_IDLE_TTL_SECONDS');
    this.idleTtlSeconds =
      typeof configuredIdle === 'number' && configuredIdle > 0
        ? configuredIdle
        : DEFAULT_AUTH_SESSION_IDLE_TTL_SECONDS;
    const configuredMaxSessions = config?.get('AUTH_MAX_CONCURRENT_SESSIONS');
    this.maxConcurrentSessions =
      typeof configuredMaxSessions === 'number' && configuredMaxSessions > 0
        ? configuredMaxSessions
        : DEFAULT_MAX_CONCURRENT_SESSIONS;
  }

  /**
   * Thuật toán: Vô hiệu hóa tức thì bộ đệm phiên `auth-session:${sessionId}` và tăng epoch người dùng `auth-user:${userId}`.
   */
  async invalidateSessionCache(userId: bigint, sessionId?: string): Promise<void> {
    if (sessionId) {
      await this.stateStore.deleteKey('auth-session', sessionId);
    }
    await this.stateStore.bumpNamespaceEpoch(`auth-user:${userId.toString()}`);
  }

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

  recordLoginFailure(user: AuthUser): Promise<void> {
    return recordUserLoginFailure(this.database, user);
  }

  async recordLoginSuccess(userId: bigint): Promise<void> {
    await this.database.user.update({
      where: { id: userId },
      data: { failed_login_count: 0, locked_until: null, last_login_at: new Date() },
    });
  }

  async createSession(input: SessionTokensInput): Promise<void> {
    const evictedIds = await createAuthSession(this.database, {
      ...input,
      maxConcurrentSessions: input.maxConcurrentSessions ?? this.maxConcurrentSessions,
    });
    if (evictedIds.length > 0) {
      await Promise.all(
        evictedIds.map((evictedId) => this.stateStore.deleteKey('auth-session', evictedId)),
      );
    }
  }

  /**
   * Thuật toán: Gộp cập nhật `last_login_at`, khởi tạo phiên và ghi kiểm toán `AUTH` trong cùng 1 giao dịch DB,
   * sau đó xóa song song đệm phiên cũ bị thu hồi (nếu vượt trần phiên đồng thời).
   */
  async completeLoginSession(
    input: SessionTokensInput,
    recordAuditInTx: (transaction: Prisma.TransactionClient) => Promise<void>,
  ): Promise<void> {
    const evictedIds = await completeAuthLoginSession(
      this.database,
      {
        ...input,
        maxConcurrentSessions: input.maxConcurrentSessions ?? this.maxConcurrentSessions,
      },
      recordAuditInTx,
    );
    if (evictedIds.length > 0) {
      await Promise.all(
        evictedIds.map((evictedId) => this.stateStore.deleteKey('auth-session', evictedId)),
      );
    }
  }

  async activateMfaSession(
    sessionId: string,
    userId: bigint,
    refresh: { id: string; hash: string; expiresAt: Date },
  ): Promise<string | null> {
    const newSessionId = await activateMfaAuthSession(this.database, sessionId, userId, refresh);
    if (newSessionId) await this.invalidateSessionCache(userId, sessionId);
    return newSessionId;
  }

  async rotateRefreshToken(
    oldHash: string,
    replacement: { id: string; hash: string; expiresAt: Date },
    context?: Pick<RequestContext, 'ip' | 'userAgent'>,
  ): Promise<RotationResult> {
    const result = await rotateSessionRefreshToken(
      this.database,
      oldHash,
      replacement,
      (id) => this.findUserById(id),
      {
        idleTtlSeconds: this.idleTtlSeconds,
        ipAddress: context?.ip,
        userAgent: context?.userAgent,
      },
    );
    if (result.kind === 'reuse') {
      await this.invalidateSessionCache(result.userId, result.sessionId);
    }
    return result;
  }

  /**
   * Thuật toán: Phân giải danh tính phiên hoạt động kèm cưỡng chế hết hạn nhàn rỗi (`idleTtlSeconds`), kiểm tra tài khoản khóa/vô hiệu hóa và xác định trạng thái `mfaPending`.
   */
  async principalForSession(userId: bigint, sessionId: string): Promise<AuthPrincipal | null> {
    const now = new Date();
    const [session, user] = await Promise.all([
      this.database.authSession.findFirst({
        where: { id: sessionId, user_id: userId, status: 'ACTIVE', expires_at: { gt: now } },
      }),
      this.findUserById(userId),
    ]);
    if (
      !session ||
      !user ||
      user.status !== 'ACTIVE' ||
      (user.lockedUntil !== null && user.lockedUntil !== undefined && user.lockedUntil > now)
    ) {
      return null;
    }
    if (
      this.idleTtlSeconds > 0 &&
      session.last_seen_at instanceof Date &&
      now.getTime() - session.last_seen_at.getTime() >= this.idleTtlSeconds * 1_000
    ) {
      const expireOp = async (
        tx: Partial<Pick<typeof this.database, 'authSession' | 'refreshToken'>>,
      ) =>
        expireAuthSessionFamily(
          tx,
          session.token_family_id,
          session.id,
          'IDLE_SESSION_EXPIRED',
          now,
        );
      if (typeof this.database.$transaction === 'function') {
        await this.database.$transaction((tx) => expireOp(tx));
      } else {
        await expireOp(this.database);
      }
      await this.stateStore.deleteKey('auth-session', session.id);
      return null;
    }
    const mfa = session.mfa_verified_at !== null;
    const mfaRequiredForUser =
      Boolean(user.requiresMfa) ||
      Boolean(user.mfaMethod) ||
      user.roles.some((role) => MFA_REQUIRED_ROLES.has(role));
    return {
      userId,
      sessionId,
      username: user.username,
      roles: user.roles,
      mfa,
      mfaPending: !mfa && mfaRequiredForUser,
    };
  }

  touchSessionActivity(userId: bigint, sessionId: string, ipAddress?: string): Promise<void> {
    return touchAuthSessionActivity(this.database, sessionId, userId, new Date(), ipAddress);
  }

  async revokeSession(sessionId: string, userId: bigint, reason: string): Promise<boolean> {
    const revoked = await revokeSingleSession(this.database, sessionId, userId, reason);
    await this.invalidateSessionCache(userId, sessionId);
    return revoked;
  }

  async revokeAllSessions(userId: bigint, reason: string): Promise<number> {
    const count = await revokeAllUserSessions(this.database, userId, reason);
    await this.invalidateSessionCache(userId);
    return count;
  }

  listActiveSessions(userId: bigint, currentSessionId: string): Promise<ActiveAuthSessionItem[]> {
    return queryActiveUserSessions(this.database, userId, currentSessionId, {
      limit: MAX_LISTED_ACTIVE_SESSIONS,
      idleTtlSeconds: this.idleTtlSeconds,
    });
  }

  async revokeOtherSessions(
    userId: bigint,
    currentSessionId: string,
    reason: string,
  ): Promise<number> {
    const count = await revokeOtherActiveUserSessions(
      this.database,
      userId,
      currentSessionId,
      reason,
    );
    if (count > 0) await this.invalidateSessionCache(userId);
    return count;
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

  async consumePasswordReset(tokenHash: string, passwordHash: string): Promise<bigint | null> {
    const userId = await consumeUserPasswordReset(this.database, tokenHash, passwordHash);
    if (userId !== null) await this.invalidateSessionCache(userId);
    return userId;
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

  async disableMfa(userId: bigint): Promise<boolean> {
    const disabled = await disableUserMfaMethods(this.database, userId);
    await this.invalidateSessionCache(userId);
    return disabled;
  }

  async disableSingleMfaMethod(userId: bigint, methodId: string): Promise<boolean> {
    const disabled = await disableSingleUserMfaMethod(this.database, userId, methodId);
    if (disabled) await this.invalidateSessionCache(userId);
    return disabled;
  }
}

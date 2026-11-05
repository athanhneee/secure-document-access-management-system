/**
 * @module AuthSessionRepository
 * Algorithm: RFC 9700 Refresh Token Family Rotation, Replay Theft Detection & Cascade Revocation.
 */
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import type { AuthUser, RequestContext } from './auth.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface SessionTokensInput {
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
  | { kind: 'invalid' | 'disabled' | 'locked' };

/**
 * Algorithm / Thuật toán: Thu hồi lan truyền toàn bộ cây họ Refresh Token và phiên xác thực cha (Cascade Token-Family Revocation).
 */
export async function revokeTokenFamily(
  transaction: Pick<PrismaClient, 'refreshToken' | 'authSession'>,
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

/**
 * Algorithm / Thuật toán: Khởi tạo nguyên tử phiên xác thực và Refresh Token gốc của họ token.
 */
export async function createAuthSession(
  database: PrismaClient,
  input: SessionTokensInput,
): Promise<void> {
  await database.$transaction(async (transaction) => {
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

/**
 * Algorithm / Thuật toán: Xoay mới định danh phiên (`sessionId`) và họ token (`token_family_id`) khi thăng cấp MFA.
 * Mục đích: Chống Session Fixation giữa giai đoạn tiền-MFA và hậu-MFA, đồng thời thu hồi triệt để mọi Refresh Token cũ cùng họ.
 */
export async function activateMfaAuthSession(
  database: PrismaClient,
  sessionId: string,
  userId: bigint,
  refresh: { id: string; hash: string; expiresAt: Date },
): Promise<string | null> {
  return database.$transaction(async (transaction) => {
    const now = new Date();
    const session = await transaction.authSession.findFirst({
      where: { id: sessionId, user_id: userId, status: 'ACTIVE', expires_at: { gt: now } },
    });
    if (!session) return null;

    const claimed = await transaction.authSession.updateMany({
      where: { id: sessionId, user_id: userId, status: 'ACTIVE', expires_at: { gt: now } },
      data: {
        status: 'REVOKED',
        revoked_at: now,
        revocation_reason: 'MFA_SESSION_ROTATED',
      },
    });
    if (claimed.count !== 1) return null;

    await transaction.refreshToken.updateMany({
      where: { token_family_id: session.token_family_id, revoked_at: null },
      data: {
        revoked_at: now,
        revocation_reason: 'MFA_SESSION_ROTATED',
      },
    });

    const newSessionId = randomUUID();
    const newFamilyId = randomUUID();

    await transaction.authSession.create({
      data: {
        id: newSessionId,
        user_id: userId,
        token_family_id: newFamilyId,
        ip_address: session.ip_address,
        user_agent: session.user_agent,
        mfa_verified_at: now,
        last_seen_at: now,
        expires_at: refresh.expiresAt,
      },
    });

    await transaction.refreshToken.create({
      data: {
        id: refresh.id,
        auth_session_id: newSessionId,
        token_family_id: newFamilyId,
        token_hash: refresh.hash,
        expires_at: refresh.expiresAt,
      },
    });

    return newSessionId;
  });
}

/**
 * Algorithm / Thuật toán: Xoay vòng họ Refresh Token và phát hiện đánh cắp/phát lại chuẩn OAuth 2.0 Security BCP (RFC 9700).
 */
export async function rotateSessionRefreshToken(
  database: PrismaClient,
  oldHash: string,
  replacement: { id: string; hash: string; expiresAt: Date },
  findUserById: (userId: bigint) => Promise<AuthUser | null>,
): Promise<RotationResult> {
  return database.$transaction(async (transaction) => {
    const current = await transaction.refreshToken.findUnique({
      where: { token_hash: oldHash },
      include: { auth_sessions: { include: { users: true } } },
    });
    if (!current) return { kind: 'invalid' };
    const now = new Date();
    const session = current.auth_sessions;
    if (session.users.status === 'DISABLED') {
      await revokeTokenFamily(transaction, current.token_family_id, session.id, 'ACCOUNT_DISABLED');
      return { kind: 'disabled' };
    }
    // CONFLICT-RESOLVED: Chặn cấp mới Refresh Token khi tài khoản đang LOCKED, chưa kích hoạt hoặc còn trong thời hạn locked_until, đồng thời thu hồi họ token ngay lập tức (MED-01).
    if (
      session.users.status !== 'ACTIVE' ||
      (session.users.locked_until !== null &&
        session.users.locked_until !== undefined &&
        session.users.locked_until > now)
    ) {
      await revokeTokenFamily(transaction, current.token_family_id, session.id, 'ACCOUNT_LOCKED');
      return { kind: 'locked' };
    }
    if (current.used_at || current.revoked_at) {
      await revokeTokenFamily(transaction, current.token_family_id, session.id, 'REFRESH_REUSE');
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
    if (current.expires_at <= now || session.expires_at <= now || session.status !== 'ACTIVE') {
      return { kind: 'invalid' };
    }
    const claimed = await transaction.refreshToken.updateMany({
      where: { id: current.id, used_at: null, revoked_at: null },
      data: { used_at: now, revoked_at: now, revocation_reason: 'ROTATED' },
    });
    if (claimed.count !== 1) {
      await revokeTokenFamily(transaction, current.token_family_id, session.id, 'REFRESH_REUSE');
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
      data: { last_seen_at: now },
    });
    const user = await findUserById(session.user_id);
    if (!user || user.status !== 'ACTIVE' || (user.lockedUntil && user.lockedUntil > now)) {
      await revokeTokenFamily(transaction, current.token_family_id, session.id, 'ACCOUNT_LOCKED');
      return { kind: 'locked' };
    }
    return { kind: 'rotated', user, sessionId: session.id, mfa: session.mfa_verified_at !== null };
  });
}

/**
 * Algorithm / Thuật toán: Thu hồi phiên đơn lẻ hoặc toàn bộ phiên hoạt động của người dùng.
 */
export async function revokeSingleSession(
  database: PrismaClient,
  sessionId: string,
  userId: bigint,
  reason: string,
): Promise<boolean> {
  return database.$transaction(async (transaction) => {
    const session = await transaction.authSession.findFirst({
      where: { id: sessionId, user_id: userId, status: 'ACTIVE' },
    });
    if (!session) return false;
    await revokeTokenFamily(transaction, session.token_family_id, session.id, reason);
    return true;
  });
}

/**
 * Algorithm / Thuật toán: Thu hồi dây chuyền toàn bộ phiên và họ Refresh Token của một người dùng.
 */
export async function revokeAllUserSessions(
  database: PrismaClient,
  userId: bigint,
  reason: string,
): Promise<number> {
  return database.$transaction(async (transaction) => {
    const sessions = await transaction.authSession.findMany({
      where: { user_id: userId, status: 'ACTIVE' },
    });
    for (const session of sessions) {
      await revokeTokenFamily(transaction, session.token_family_id, session.id, reason);
    }
    return sessions.length;
  });
}

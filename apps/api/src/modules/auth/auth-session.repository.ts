/**
 * @module AuthSessionRepository
 * Algorithm: RFC 9700 Refresh Token Family Rotation, Replay Theft Detection & Cascade Revocation.
 */
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient, Prisma } from '@sda/database';
import {
  enforceConcurrentSessionLimit,
  expireAuthSessionFamily,
  normalizeValidInetAddress,
  revokeTokenFamily,
} from './auth-sessions-management.helper.js';
import { MFA_REQUIRED_ROLES, type AuthUser, type RequestContext } from './auth.types.js';

export { normalizeValidInetAddress, revokeTokenFamily };

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
  maxConcurrentSessions?: number | undefined;
  context: RequestContext;
}

export interface RotateRefreshOptions {
  idleTtlSeconds?: number | undefined;
  ipAddress?: string | undefined;
  userAgent?: string | undefined;
}

export type RotationResult =
  | { kind: 'rotated'; user: AuthUser; sessionId: string; mfa: boolean }
  | { kind: 'reuse'; userId: bigint; sessionId: string; alertId?: string | undefined }
  | {
      kind: 'invalid' | 'disabled' | 'locked';
      userId?: bigint | undefined;
      sessionId?: string | undefined;
    };

/**
 * Algorithm / Thuật toán: Gộp nguyên tử cập nhật đăng nhập thành công (`last_login_at`), cưỡng chế trần phiên,
 * tạo phiên/Refresh Token và ghi chuỗi băm kiểm toán `AUTH` vào đúng 1 giao dịch PostgreSQL duy nhất.
 */
export async function completeAuthLoginSession(
  database: PrismaClient,
  input: SessionTokensInput,
  recordAuditInTx: (transaction: Prisma.TransactionClient) => Promise<void>,
): Promise<string[]> {
  return database.$transaction(async (transaction) => {
    const now = new Date();
    const [, evictedIds] = await Promise.all([
      transaction.user.update({
        where: { id: input.userId },
        data: { failed_login_count: 0, locked_until: null, last_login_at: now },
      }),
      typeof input.maxConcurrentSessions === 'number' && input.maxConcurrentSessions > 0
        ? enforceConcurrentSessionLimit(transaction, input.userId, input.maxConcurrentSessions, now)
        : Promise.resolve([] as string[]),
    ]);
    const validIp = normalizeValidInetAddress(input.context.ip);
    const initialUserAgent = input.context.userAgent ?? null;
    await transaction.authSession.create({
      data: {
        id: input.sessionId,
        user_id: input.userId,
        token_family_id: input.familyId,
        ip_address: validIp ?? null,
        user_agent: initialUserAgent,
        login_ip_address: validIp ?? null,
        login_user_agent: initialUserAgent,
        mfa_verified_at: input.mfaVerified ? now : null,
        expires_at: input.sessionExpiresAt,
      },
    });
    const postSessionOps: Promise<unknown>[] = [recordAuditInTx(transaction)];
    if (input.refreshTokenId && input.refreshTokenHash && input.refreshExpiresAt) {
      postSessionOps.push(
        transaction.refreshToken.create({
          data: {
            id: input.refreshTokenId,
            auth_session_id: input.sessionId,
            token_family_id: input.familyId,
            token_hash: input.refreshTokenHash,
            expires_at: input.refreshExpiresAt,
          },
        }),
      );
    }
    await Promise.all(postSessionOps);
    return evictedIds;
  });
}

/**
 * Algorithm / Thuật toán: Khởi tạo nguyên tử phiên xác thực, cưỡng chế trần phiên đồng thời và lưu Refresh Token gốc của họ token.
 */
export async function createAuthSession(
  database: PrismaClient,
  input: SessionTokensInput,
): Promise<string[]> {
  return database.$transaction(async (transaction) => {
    const now = new Date();
    const evictedIds =
      typeof input.maxConcurrentSessions === 'number' && input.maxConcurrentSessions > 0
        ? await enforceConcurrentSessionLimit(
            transaction,
            input.userId,
            input.maxConcurrentSessions,
            now,
          )
        : [];
    const validIp = normalizeValidInetAddress(input.context.ip);
    const initialUserAgent = input.context.userAgent ?? null;
    await transaction.authSession.create({
      data: {
        id: input.sessionId,
        user_id: input.userId,
        token_family_id: input.familyId,
        ip_address: validIp ?? null,
        user_agent: initialUserAgent,
        login_ip_address: validIp ?? null,
        login_user_agent: initialUserAgent,
        mfa_verified_at: input.mfaVerified ? now : null,
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
    return evictedIds;
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
    const sessionWithLoginBaseline = session as typeof session & {
      login_ip_address?: string | null;
      login_user_agent?: string | null;
    };

    await transaction.authSession.create({
      data: {
        id: newSessionId,
        user_id: userId,
        token_family_id: newFamilyId,
        ip_address: session.ip_address,
        user_agent: session.user_agent,
        login_ip_address: sessionWithLoginBaseline.login_ip_address ?? session.ip_address ?? null,
        login_user_agent: sessionWithLoginBaseline.login_user_agent ?? session.user_agent ?? null,
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
 * Algorithm / Thuật toán: Xoay vòng họ Refresh Token, cưỡng chế hết hạn nhàn rỗi (`idleTtlSeconds`), chặn gia hạn phiên thiếu MFA khi tài khoản đã bật/bắt buộc MFA, cập nhật IP/UA hoạt động gần nhất và phân tách chính xác tấn công tái sử dụng (`ROTATED` / `REFRESH_REUSE`) khỏi thu hồi phiên hợp lệ theo chuẩn RFC 9700.
 */
export async function rotateSessionRefreshToken(
  database: PrismaClient,
  oldHash: string,
  replacement: { id: string; hash: string; expiresAt: Date },
  findUserById: (
    userId: bigint,
    transaction?: Prisma.TransactionClient,
  ) => Promise<AuthUser | null>,
  options?: RotateRefreshOptions,
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
      return { kind: 'disabled', userId: session.user_id, sessionId: session.id };
    }
    // CONFLICT-RESOLVED: Chặn cấp mới Refresh Token khi tài khoản đang LOCKED, chưa kích hoạt hoặc còn trong thời hạn locked_until, đồng thời thu hồi họ token ngay lập tức (MED-01).
    if (
      session.users.status !== 'ACTIVE' ||
      (session.users.locked_until !== null &&
        session.users.locked_until !== undefined &&
        session.users.locked_until > now)
    ) {
      await revokeTokenFamily(transaction, current.token_family_id, session.id, 'ACCOUNT_LOCKED');
      return { kind: 'locked', userId: session.user_id, sessionId: session.id };
    }
    const recordRefreshReuseAlert = async (title: string, description: string): Promise<string> => {
      // CONFLICT-RESOLVED: Việt hóa cảnh báo tái sử dụng Refresh Token và áp dụng chống trùng lặp theo cooldownMinutes & severity từ detection_rule_configs (N06 / MED-10).
      const ruleCfg =
        typeof transaction.detectionRuleConfig?.findUnique === 'function'
          ? await transaction.detectionRuleConfig
              .findUnique({ where: { rule_code: 'REFRESH_TOKEN_REUSE' } })
              .catch(() => null)
          : null;
      const cooldownStart = new Date(now.getTime() - (ruleCfg?.cooldown_minutes ?? 15) * 60_000);
      const existingReuseAlert =
        typeof transaction.securityAlert?.findFirst === 'function'
          ? await transaction.securityAlert.findFirst({
              where: {
                alert_type: 'REFRESH_TOKEN_REUSE',
                detected_user_id: session.user_id,
                status: { in: ['OPEN', 'INVESTIGATING'] },
                detected_at: { gte: cooldownStart },
              },
              select: { id: true },
            })
          : null;
      if (existingReuseAlert?.id) {
        return existingReuseAlert.id;
      }
      const alertId = randomUUID();
      await transaction.securityAlert.create({
        data: {
          id: alertId,
          alert_type: 'REFRESH_TOKEN_REUSE',
          severity: ruleCfg?.severity ?? 'HIGH',
          title,
          description,
          detected_user_id: session.user_id,
        },
      });
      return alertId;
    };

    // BUG-044: Chỉ coi là tấn công phát lại khi token đã tiêu thụ xoay vòng (`used_at != null`, `ROTATED`) hoặc họ token đã bị đánh dấu `REFRESH_REUSE`; các lý do thu hồi hợp lệ khác (hết hạn nhàn rỗi, đăng xuất, đổi mật khẩu, vượt trần phiên...) chỉ trả `invalid` không bắn cảnh báo SOC giả.
    const isTokenReuse =
      (current.used_at !== null && current.used_at !== undefined) ||
      current.revocation_reason === 'ROTATED' ||
      current.revocation_reason === 'REFRESH_REUSE';
    if (isTokenReuse) {
      await revokeTokenFamily(transaction, current.token_family_id, session.id, 'REFRESH_REUSE');
      const alertId = await recordRefreshReuseAlert(
        'Cảnh báo: Tái sử dụng Refresh Token đã thu hồi',
        'Phát hiện nỗ lực sử dụng lại Refresh Token đã xoay vòng hoặc thu hồi. Toàn bộ họ phiên đăng nhập đã bị thu hồi tức thì.',
      );
      return { kind: 'reuse', userId: session.user_id, sessionId: session.id, alertId };
    }
    if (current.revoked_at !== null && current.revoked_at !== undefined) {
      return { kind: 'invalid', userId: session.user_id, sessionId: session.id };
    }
    if (current.expires_at <= now || session.expires_at <= now || session.status !== 'ACTIVE') {
      if (session.status === 'ACTIVE' && session.expires_at <= now) {
        await expireAuthSessionFamily(
          transaction,
          current.token_family_id,
          session.id,
          'SESSION_EXPIRED',
          now,
        );
      }
      return { kind: 'invalid', userId: session.user_id, sessionId: session.id };
    }
    if (
      typeof options?.idleTtlSeconds === 'number' &&
      options.idleTtlSeconds > 0 &&
      session.last_seen_at instanceof Date &&
      now.getTime() - session.last_seen_at.getTime() >= options.idleTtlSeconds * 1_000
    ) {
      await expireAuthSessionFamily(
        transaction,
        current.token_family_id,
        session.id,
        'IDLE_SESSION_EXPIRED',
        now,
      );
      return { kind: 'invalid', userId: session.user_id, sessionId: session.id };
    }
    const user = await findUserById(session.user_id, transaction);
    if (!user || user.status === 'DISABLED') {
      await revokeTokenFamily(transaction, current.token_family_id, session.id, 'ACCOUNT_DISABLED');
      return { kind: 'disabled', userId: session.user_id, sessionId: session.id };
    }
    if (user.status !== 'ACTIVE' || (user.lockedUntil && user.lockedUntil > now)) {
      await revokeTokenFamily(transaction, current.token_family_id, session.id, 'ACCOUNT_LOCKED');
      return { kind: 'locked', userId: session.user_id, sessionId: session.id };
    }
    // BUG-046: Chặn gia hạn Refresh Token đối với phiên chưa xác thực MFA (`mfa_verified_at === null`) khi tài khoản đã kích hoạt MFA hoặc giữ vai trò bắt buộc MFA.
    const hasMfaRole =
      Boolean(user.hasMandatoryMfaRole) ||
      (user.roles ?? []).some((role) => MFA_REQUIRED_ROLES.has(role));
    const userRequiresMfa = Boolean(user.requiresMfa) || Boolean(user.mfaMethod) || hasMfaRole;
    if (
      userRequiresMfa &&
      (session.mfa_verified_at === null || session.mfa_verified_at === undefined)
    ) {
      await revokeTokenFamily(
        transaction,
        current.token_family_id,
        session.id,
        'MFA_REQUIRED_UNVERIFIED_SESSION',
      );
      return { kind: 'invalid', userId: session.user_id, sessionId: session.id };
    }
    const claimed = await transaction.refreshToken.updateMany({
      where: { id: current.id, used_at: null, revoked_at: null },
      data: { used_at: now, revoked_at: now, revocation_reason: 'ROTATED' },
    });
    if (claimed.count !== 1) {
      // MED-10: Đọc lại bản ghi token mới nhất sau khi CAS thất bại để phân biệt tranh chấp xoay vòng thật (`ROTATED`/`used_at`) với thu hồi hợp lệ song song (`LOGOUT`/khóa tài khoản).
      const latest =
        typeof transaction.refreshToken?.findUnique === 'function'
          ? await transaction.refreshToken
              .findUnique({
                where: { id: current.id },
                select: { used_at: true, revoked_at: true, revocation_reason: true },
              })
              .catch(() => null)
          : null;
      const confirmedReuse =
        !latest ||
        latest.used_at !== null ||
        latest.revocation_reason === 'ROTATED' ||
        latest.revocation_reason === 'REFRESH_REUSE';
      if (!confirmedReuse) {
        return { kind: 'invalid', userId: session.user_id, sessionId: session.id };
      }
      await revokeTokenFamily(transaction, current.token_family_id, session.id, 'REFRESH_REUSE');
      const alertId = await recordRefreshReuseAlert(
        'Cảnh báo: Tranh chấp xoay vòng Refresh Token đồng thời',
        'Refresh Token không vượt qua kiểm tra xoay vòng nguyên tử (phát hiện gửi đồng thời hoặc phát lại). Toàn bộ họ phiên đã bị thu hồi.',
      );
      return { kind: 'reuse', userId: session.user_id, sessionId: session.id, alertId };
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
    const validIp = normalizeValidInetAddress(options?.ipAddress);
    const trimmedUserAgent = options?.userAgent?.trim();
    await transaction.authSession.update({
      where: { id: session.id },
      data: {
        last_seen_at: now,
        ...(validIp ? { ip_address: validIp } : {}),
        ...(trimmedUserAgent ? { user_agent: trimmedUserAgent } : {}),
      },
    });
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

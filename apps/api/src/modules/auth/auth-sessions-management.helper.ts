/**
 * @module AuthSessionsManagementHelper
 * Thuật toán: Liệt kê phiên thiết bị đang hoạt động có chặn trần (`take`) kèm lọc hết hạn nhàn rỗi (`idleTtlSeconds`),
 * giới hạn số phiên đồng thời tối đa theo tài khoản, làm mới `last_seen_at`/`ip_address` có kiểm định `INET`,
 * thu hồi chọn lọc các phiên song song khác và chấm dứt phiên chỉ định có kiểm định UUID.
 */
import { isIP } from 'node:net';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthAuditService } from './auth-audit.service.js';
import type { AuthPrincipal, RequestContext } from './auth.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;
type SessionTx = Pick<PrismaClient, 'refreshToken' | 'authSession'>;

/**
 * Algorithm / Thuật toán: Thu hồi lan truyền toàn bộ cây họ Refresh Token và phiên xác thực cha (Cascade Token-Family Revocation).
 */
export async function revokeTokenFamily(
  transaction: SessionTx,
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

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const MAX_LISTED_ACTIVE_SESSIONS = 50;
export const DEFAULT_AUTH_SESSION_IDLE_TTL_SECONDS = 28_800;
export const DEFAULT_MAX_CONCURRENT_SESSIONS = 10;

export interface ActiveAuthSessionItem {
  id: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  isCurrent: boolean;
  mfaVerified: boolean;
}

export interface QueryActiveSessionsOptions {
  limit?: number | undefined;
  idleTtlSeconds?: number | undefined;
  now?: Date | undefined;
}

/**
 * Thuật toán: Chuẩn hóa chuỗi IP hợp lệ (IPv4 / IPv6) trước khi ghi vào cột PostgreSQL `INET`.
 */
export function normalizeValidInetAddress(rawIp?: string | null): string | undefined {
  if (!rawIp) return undefined;
  const trimmed = rawIp.trim();
  return trimmed.length > 0 && isIP(trimmed) !== 0 ? trimmed : undefined;
}

/**
 * Thuật toán: Liệt kê các phiên đăng nhập đang hoạt động chưa hết hạn (tuyệt đối & nhàn rỗi) của người dùng có chặn trần `take`.
 */
export async function queryActiveUserSessions(
  database: PrismaClient,
  userId: bigint,
  currentSessionId: string,
  options?: QueryActiveSessionsOptions,
): Promise<ActiveAuthSessionItem[]> {
  const now = options?.now ?? new Date();
  const limit = Math.min(
    Math.max(Math.floor(options?.limit ?? MAX_LISTED_ACTIVE_SESSIONS), 1),
    100,
  );
  const idleTtlSeconds = options?.idleTtlSeconds;
  const idleCutoff =
    typeof idleTtlSeconds === 'number' && idleTtlSeconds > 0
      ? new Date(now.getTime() - idleTtlSeconds * 1_000)
      : undefined;

  const rows = await database.authSession.findMany({
    where: {
      user_id: userId,
      status: 'ACTIVE',
      expires_at: { gt: now },
      ...(idleCutoff ? { last_seen_at: { gt: idleCutoff } } : {}),
    },
    orderBy: [{ last_seen_at: 'desc' }, { created_at: 'desc' }],
    take: limit,
  });
  return rows.map((row) => ({
    id: row.id,
    ipAddress: row.ip_address ?? null,
    userAgent: row.user_agent ?? null,
    createdAt: row.created_at.toISOString(),
    lastSeenAt: row.last_seen_at.toISOString(),
    expiresAt: row.expires_at.toISOString(),
    isCurrent: row.id === currentSessionId,
    mfaVerified: Boolean((row as { mfa_verified_at?: Date | null }).mfa_verified_at),
  }));
}

/**
 * Thuật toán: Cưỡng chế giới hạn số phiên đăng nhập đồng thời tối đa trên mỗi tài khoản (`LRU Session Eviction`).
 * Mục đích: Trước khi tạo 1 phiên mới, giữ lại tối đa `maxConcurrentSessions - 1` phiên hoạt động gần nhất
 * và thu hồi nguyên tử mọi phiên dư cũ nhất kèm cây họ Refresh Token tương ứng.
 */
export async function enforceConcurrentSessionLimit(
  transaction: SessionTx,
  userId: bigint,
  maxConcurrentSessions: number,
  now: Date = new Date(),
): Promise<string[]> {
  if (
    !Number.isFinite(maxConcurrentSessions) ||
    maxConcurrentSessions < 1 ||
    typeof transaction.authSession?.findMany !== 'function'
  ) {
    return [];
  }
  const keepCount = Math.max(0, Math.floor(maxConcurrentSessions) - 1);
  const activeSessions = await transaction.authSession.findMany({
    where: {
      user_id: userId,
      status: 'ACTIVE',
      expires_at: { gt: now },
    },
    orderBy: [{ last_seen_at: 'desc' }, { created_at: 'desc' }],
  });
  if (activeSessions.length <= keepCount) {
    return [];
  }
  const toEvict = activeSessions.slice(keepCount);
  const evictedIds: string[] = [];
  for (const session of toEvict) {
    await revokeTokenFamily(
      transaction,
      session.token_family_id,
      session.id,
      'MAX_CONCURRENT_SESSIONS_EXCEEDED',
    );
    evictedIds.push(session.id);
  }
  return evictedIds;
}

/**
 * Thuật toán: Chuyển trạng thái phiên xác thực sang `EXPIRED` và thu hồi toàn bộ họ Refresh Token liên kết khi vượt ngưỡng nhàn rỗi (`IDLE_SESSION_EXPIRED`).
 */
export async function expireAuthSessionFamily(
  transaction: Partial<SessionTx>,
  familyId: string,
  sessionId: string,
  reason: string,
  now: Date = new Date(),
): Promise<void> {
  if (typeof transaction.refreshToken?.updateMany === 'function') {
    await transaction.refreshToken.updateMany({
      where: { token_family_id: familyId, revoked_at: null },
      data: { revoked_at: now, revocation_reason: reason },
    });
  }
  if (typeof transaction.authSession?.updateMany === 'function') {
    await transaction.authSession.updateMany({
      where: { id: sessionId, status: 'ACTIVE' },
      data: { status: 'EXPIRED', revoked_at: now, revocation_reason: reason },
    });
  }
}

/**
 * Thuật toán: Cập nhật dấu vết hoạt động (`last_seen_at`) và địa chỉ IP hợp lệ mới nhất của phiên đang hoạt động.
 */
export async function touchAuthSessionActivity(
  database: Partial<Pick<PrismaClient, 'authSession'>>,
  sessionId: string,
  userId: bigint,
  now: Date = new Date(),
  ipAddress?: string | null,
): Promise<void> {
  if (typeof database.authSession?.updateMany !== 'function') {
    return;
  }
  const validIp = normalizeValidInetAddress(ipAddress);
  await database.authSession.updateMany({
    where: {
      id: sessionId,
      user_id: userId,
      status: 'ACTIVE',
      expires_at: { gt: now },
    },
    data: {
      last_seen_at: now,
      ...(validIp ? { ip_address: validIp } : {}),
    },
  });
}

/**
 * Thuật toán: Thu hồi nguyên tử mọi phiên `ACTIVE` khác của người dùng (`id !== currentSessionId`) kèm cây họ Refresh Token mà không làm đứt phiên hiện hành.
 */
export async function revokeOtherActiveUserSessions(
  database: PrismaClient,
  userId: bigint,
  currentSessionId: string,
  reason: string,
): Promise<number> {
  return database.$transaction(async (transaction) => {
    const otherSessions = await transaction.authSession.findMany({
      where: {
        user_id: userId,
        status: 'ACTIVE',
        id: { not: currentSessionId },
      },
    });
    for (const session of otherSessions) {
      await revokeTokenFamily(transaction, session.token_family_id, session.id, reason);
    }
    return otherSessions.length;
  });
}

export interface RevokeOtherUnverifiedMfaSessionsResult {
  revokedCount: number;
  revokedSessionIds: string[];
  preservedSessionIds: string[];
}

/**
 * Thuật toán: Khi người dùng kích hoạt nhân tố MFA mới, thu hồi nguyên tử toàn bộ các phiên `ACTIVE` khác đang ở trạng thái chưa xác thực MFA (`mfa_verified_at IS NULL`),
 * tuyệt đối loại trừ `excludeSessionId` (phiên vừa xoay nâng cấp MFA) và giữ nguyên các phiên khác đã xác thực MFA để không đá văng chính tab đang hiển thị mã khôi phục (`BUG-046`).
 */
export async function revokeOtherUnverifiedMfaUserSessions(
  database: PrismaClient,
  userId: bigint,
  excludeSessionId: string,
  reason: string,
): Promise<RevokeOtherUnverifiedMfaSessionsResult> {
  return database.$transaction(async (transaction) => {
    const otherSessions = await transaction.authSession.findMany({
      where: {
        user_id: userId,
        status: 'ACTIVE',
        id: { not: excludeSessionId },
      },
    });
    const revokedSessionIds: string[] = [];
    const preservedSessionIds: string[] = [];
    for (const session of otherSessions) {
      if (session.mfa_verified_at === null || session.mfa_verified_at === undefined) {
        await revokeTokenFamily(transaction, session.token_family_id, session.id, reason);
        revokedSessionIds.push(session.id);
      } else {
        preservedSessionIds.push(session.id);
      }
    }
    return {
      revokedCount: revokedSessionIds.length,
      revokedSessionIds,
      preservedSessionIds,
    };
  });
}

/**
 * Thuật toán: Điều phối dịch vụ quản lý phiên (liệt kê phiên, đăng xuất thiết bị khác, thu hồi phiên chỉ định có kiểm tra UUID).
 */
export async function executeRevokeTargetSession(params: {
  repository: {
    revokeSession: (sessionId: string, userId: bigint, reason: string) => Promise<boolean>;
  };
  audit: AuthAuditService;
  principal: AuthPrincipal;
  targetSessionId: string;
  context: RequestContext;
}): Promise<{ clearedCurrentCookies: boolean }> {
  const { repository, audit, principal, targetSessionId, context } = params;
  if (!UUID_REGEX.test(targetSessionId)) {
    throw new BadRequestException('sessionId must be a valid UUID.');
  }
  const revoked = await repository.revokeSession(
    targetSessionId,
    principal.userId,
    'USER_SESSION_REVOKED',
  );
  if (!revoked) {
    throw new NotFoundException({
      errorCode: AppErrorCode.RESOURCE_NOT_FOUND,
      message: 'Active session was not found.',
    });
  }
  await audit.record(
    {
      action: 'SESSION_REVOKED',
      outcome: 'SUCCESS',
      actorUserId: principal.userId,
      actorUsername: principal.username,
      objectId: targetSessionId,
    },
    context,
  );
  return { clearedCurrentCookies: targetSessionId === principal.sessionId };
}

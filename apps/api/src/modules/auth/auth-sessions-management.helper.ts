/**
 * @module AuthSessionsManagementHelper
 * Algorithm: Active Device Session Enumeration, Selective Peer-Session Revocation & Targeted Session Termination.
 */
import { BadRequestException, NotFoundException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthAuditService } from './auth-audit.service.js';
import { revokeTokenFamily } from './auth-session.repository.js';
import type { AuthPrincipal, RequestContext } from './auth.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface ActiveAuthSessionItem {
  id: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  isCurrent: boolean;
}

/**
 * Thuật toán: Liệt kê các phiên đăng nhập đang hoạt động chưa hết hạn của người dùng và đánh dấu phiên hiện tại (`isCurrent`).
 */
export async function queryActiveUserSessions(
  database: PrismaClient,
  userId: bigint,
  currentSessionId: string,
): Promise<ActiveAuthSessionItem[]> {
  const now = new Date();
  const rows = await database.authSession.findMany({
    where: {
      user_id: userId,
      status: 'ACTIVE',
      expires_at: { gt: now },
    },
    orderBy: [{ last_seen_at: 'desc' }, { created_at: 'desc' }],
  });
  return rows.map((row) => ({
    id: row.id,
    ipAddress: row.ip_address ?? null,
    userAgent: row.user_agent ?? null,
    createdAt: row.created_at.toISOString(),
    lastSeenAt: row.last_seen_at.toISOString(),
    expiresAt: row.expires_at.toISOString(),
    isCurrent: row.id === currentSessionId,
  }));
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

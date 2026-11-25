import { getDatabaseClient } from '@sda/database';
import { recordWorkerJobRun } from './worker-metrics.js';

/**
 * Thuật toán / Tổng quan module:
 * Tác vụ nền quản trị vòng đời phiên đăng nhập (`auth_sessions`) và chuỗi xoay vòng `refresh_tokens`:
 * - Pha 1 (`expireIdleAndElapsedAuthSessions`): Tự động chuyển sang `EXPIRED` các phiên `ACTIVE` đã quá hạn
 *   tuyệt đối (`expires_at <= now`) hoặc vượt ngưỡng nhàn rỗi (`last_seen_at <= now - AUTH_SESSION_IDLE_TTL_SECONDS`),
 *   đồng thời thu hồi mọi `refresh_tokens` còn mở thuộc phiên không còn hoạt động.
 * - Pha 2 (`purgeExpiredAuthSessionsAndTokens`): Xóa theo lô có trần (`batchSize`) các phiên `REVOKED`/`EXPIRED`
 *   quá hạn lưu trữ (`AUTH_SESSION_RETENTION_DAYS`, mặc định 30 ngày), chủ động gỡ khóa tự tham chiếu `parent_token_id`
 *   (`ON DELETE RESTRICT`) trước khi xóa `refresh_tokens` và `auth_sessions` để chống phình bảng và chống lỗi ràng buộc FK.
 */

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export const DEFAULT_AUTH_SESSION_IDLE_TTL_SECONDS = 28_800;
export const DEFAULT_AUTH_SESSION_RETENTION_DAYS = 30;
export const DEFAULT_AUTH_SESSION_PURGE_BATCH_SIZE = 500;

export interface AuthSessionExpirationResult {
  expiredAbsoluteCount: number;
  expiredIdleCount: number;
  revokedOrphanTokens: number;
}

export interface AuthSessionPurgeResult {
  purgedSessions: number;
  purgedRefreshTokens: number;
}

export interface AuthSessionCleanupCycleResult
  extends AuthSessionExpirationResult, AuthSessionPurgeResult {
  timestamp: string;
}

function resolveBoundedInt(
  explicitValue: number | undefined,
  envKey: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const raw = explicitValue ?? Number(process.env[envKey] ?? fallback);
  if (!Number.isFinite(raw)) return fallback;
  return Math.min(Math.max(Math.floor(raw), min), max);
}

/**
 * Thuật toán: Quét hết hạn tuyệt đối & hết hạn nhàn rỗi trên `auth_sessions` kèm thu hồi `refresh_tokens` mồ côi.
 */
export async function expireIdleAndElapsedAuthSessions(options?: {
  databaseClient?: PrismaClient;
  idleTtlSeconds?: number;
  now?: Date;
}): Promise<AuthSessionExpirationResult> {
  if (!options?.databaseClient && !process.env['DATABASE_URL']?.trim()) {
    return { expiredAbsoluteCount: 0, expiredIdleCount: 0, revokedOrphanTokens: 0 };
  }
  const database = options?.databaseClient ?? getDatabaseClient();
  if (typeof database.authSession?.updateMany !== 'function') {
    return { expiredAbsoluteCount: 0, expiredIdleCount: 0, revokedOrphanTokens: 0 };
  }

  const now = options?.now ?? new Date();
  const idleTtlSeconds = resolveBoundedInt(
    options?.idleTtlSeconds,
    'AUTH_SESSION_IDLE_TTL_SECONDS',
    DEFAULT_AUTH_SESSION_IDLE_TTL_SECONDS,
    300,
    604_800,
  );
  const idleCutoff = new Date(now.getTime() - idleTtlSeconds * 1_000);

  const absoluteExpired = await database.authSession.updateMany({
    where: {
      status: 'ACTIVE',
      expires_at: { lte: now },
    },
    data: {
      status: 'EXPIRED',
      revoked_at: now,
      revocation_reason: 'SESSION_EXPIRED',
    },
  });

  const idleExpired = await database.authSession.updateMany({
    where: {
      status: 'ACTIVE',
      expires_at: { gt: now },
      last_seen_at: { lte: idleCutoff },
    },
    data: {
      status: 'EXPIRED',
      revoked_at: now,
      revocation_reason: 'IDLE_SESSION_EXPIRED',
    },
  });

  let revokedOrphanTokens = 0;
  if (typeof database.refreshToken?.updateMany === 'function') {
    const revokedTokens = await database.refreshToken.updateMany({
      where: {
        revoked_at: null,
        auth_sessions: { status: { not: 'ACTIVE' } },
      },
      data: {
        revoked_at: now,
        revocation_reason: 'SESSION_EXPIRED',
      },
    });
    revokedOrphanTokens = revokedTokens.count;
  }

  return {
    expiredAbsoluteCount: absoluteExpired.count,
    expiredIdleCount: idleExpired.count,
    revokedOrphanTokens,
  };
}

/**
 * Thuật toán: Xóa theo lô an toàn khóa ngoại (`Break Self-FK RESTRICT -> Delete RefreshTokens -> Delete AuthSessions`)
 * các bản ghi phiên đăng nhập đã hết hạn hoặc bị thu hồi quá ngưỡng lưu trữ `AUTH_SESSION_RETENTION_DAYS`.
 */
export async function purgeExpiredAuthSessionsAndTokens(options?: {
  databaseClient?: PrismaClient;
  retentionDays?: number;
  batchSize?: number;
  now?: Date;
}): Promise<AuthSessionPurgeResult> {
  if (!options?.databaseClient && !process.env['DATABASE_URL']?.trim()) {
    return { purgedSessions: 0, purgedRefreshTokens: 0 };
  }
  const database = options?.databaseClient ?? getDatabaseClient();
  if (
    typeof database.authSession?.findMany !== 'function' ||
    typeof database.authSession?.deleteMany !== 'function'
  ) {
    return { purgedSessions: 0, purgedRefreshTokens: 0 };
  }

  const now = options?.now ?? new Date();
  const retentionDays = resolveBoundedInt(
    options?.retentionDays,
    'AUTH_SESSION_RETENTION_DAYS',
    DEFAULT_AUTH_SESSION_RETENTION_DAYS,
    1,
    365,
  );
  const batchSize = resolveBoundedInt(
    options?.batchSize,
    'AUTH_SESSION_PURGE_BATCH_SIZE',
    DEFAULT_AUTH_SESSION_PURGE_BATCH_SIZE,
    1,
    2_000,
  );
  const retentionCutoff = new Date(now.getTime() - retentionDays * 86_400_000);

  const executePurge = async (
    tx: Pick<PrismaClient, 'authSession' | 'refreshToken'>,
  ): Promise<AuthSessionPurgeResult> => {
    const candidates = await tx.authSession.findMany({
      where: {
        status: { in: ['REVOKED', 'EXPIRED'] },
        OR: [{ revoked_at: { lt: retentionCutoff } }, { expires_at: { lt: retentionCutoff } }],
      },
      select: { id: true },
      orderBy: { expires_at: 'asc' },
      take: batchSize,
    });
    if (candidates.length === 0) {
      return { purgedSessions: 0, purgedRefreshTokens: 0 };
    }
    const sessionIds = candidates.map((row) => row.id);
    let purgedRefreshTokens = 0;

    if (typeof tx.refreshToken?.updateMany === 'function') {
      await tx.refreshToken.updateMany({
        where: {
          auth_session_id: { in: sessionIds },
          parent_token_id: { not: null },
        },
        data: { parent_token_id: null },
      });
    }
    if (typeof tx.refreshToken?.deleteMany === 'function') {
      const deletedTokens = await tx.refreshToken.deleteMany({
        where: { auth_session_id: { in: sessionIds } },
      });
      purgedRefreshTokens = deletedTokens.count;
    }

    const deletedSessions = await tx.authSession.deleteMany({
      where: { id: { in: sessionIds } },
    });

    return {
      purgedSessions: deletedSessions.count,
      purgedRefreshTokens,
    };
  };

  return typeof database.$transaction === 'function'
    ? database.$transaction((tx) => executePurge(tx))
    : executePurge(database);
}

/**
 * Thuật toán: Thực thi trọn vẹn 1 chu kỳ hết hạn nhàn rỗi và thu dọn rác bảng `auth_sessions` / `refresh_tokens`.
 */
export async function runAuthSessionCleanupCycle(options?: {
  databaseClient?: PrismaClient;
  idleTtlSeconds?: number;
  retentionDays?: number;
  batchSize?: number;
  now?: Date;
}): Promise<AuthSessionCleanupCycleResult> {
  const now = options?.now ?? new Date();
  const expiration = await expireIdleAndElapsedAuthSessions({
    ...(options?.databaseClient ? { databaseClient: options.databaseClient } : {}),
    ...(options?.idleTtlSeconds !== undefined ? { idleTtlSeconds: options.idleTtlSeconds } : {}),
    now,
  });
  const purge = await purgeExpiredAuthSessionsAndTokens({
    ...(options?.databaseClient ? { databaseClient: options.databaseClient } : {}),
    ...(options?.retentionDays !== undefined ? { retentionDays: options.retentionDays } : {}),
    ...(options?.batchSize !== undefined ? { batchSize: options.batchSize } : {}),
    now,
  });
  return {
    ...expiration,
    ...purge,
    timestamp: now.toISOString(),
  };
}

/**
 * Thuật toán: Bộ lập lịch định kỳ chống chồng lấn chu kỳ (Non-Overlapping Interval Scheduler) cho `AuthSessionCleanupJob`.
 */
export function startAuthSessionCleanupJob(intervalMs: number, signal: AbortSignal): void {
  if (signal.aborted) return;

  let isRunning = false;
  const timer = setInterval(async () => {
    if (signal.aborted) {
      clearInterval(timer);
      return;
    }
    if (isRunning) return;
    isRunning = true;

    try {
      const res = await runAuthSessionCleanupCycle();
      recordWorkerJobRun('auth_session_cleanup', 'success');
      if (
        res.expiredAbsoluteCount > 0 ||
        res.expiredIdleCount > 0 ||
        res.purgedSessions > 0 ||
        res.revokedOrphanTokens > 0
      ) {
        console.info(
          `Auth session cleanup expired ${res.expiredAbsoluteCount} elapsed + ${res.expiredIdleCount} idle session(s), revoked ${res.revokedOrphanTokens} orphan token(s), and purged ${res.purgedSessions} archived session(s) / ${res.purgedRefreshTokens} token(s).`,
        );
      }
    } catch (err) {
      recordWorkerJobRun('auth_session_cleanup', 'error');
      console.error(`Auth session cleanup cycle failed: ${err}`);
    } finally {
      isRunning = false;
    }
  }, intervalMs);

  signal.addEventListener(
    'abort',
    () => {
      clearInterval(timer);
      console.info('Auth session cleanup worker stopped cleanly.');
    },
    { once: true },
  );

  console.info(`Auth session cleanup worker started (interval: ${intervalMs}ms).`);
}

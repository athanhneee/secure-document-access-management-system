import { getDatabaseClient, type session_status } from '@sda/database';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { recordWorkerJobRun } from './worker-metrics.js';

/**
 * Thuật toán / Tổng quan module:
 * Cơ chế thu dọn định kỳ tệp tạm giải mã/dẫn xuất trên danh sách thư mục cấu hình `DERIVATIVE_TMP_DIRS`
 * kết hợp tự động hết hạn các phiên đọc tài liệu (`access_sessions`) ở trạng thái `ACTIVE` bị treo nhàn rỗi
 * vượt quá ngưỡng `MAX_IDLE_SESSION_MINUTES` (mặc định 60 phút) trong PostgreSQL.
 */

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface CleanupResult {
  cleanedTempFiles: number;
  expiredSessions: number;
  timestamp: string;
}

/**
 * Thuật toán: Phân tách và khử trùng lặp danh sách thư mục tạm từ `DERIVATIVE_TMP_DIRS` (hỗ trợ dấu phẩy hoặc `path.delimiter`).
 */
export function resolveDerivativeTmpDirs(customDirs?: readonly string[] | string): string[] {
  const rawList = Array.isArray(customDirs)
    ? customDirs
    : typeof customDirs === 'string' && customDirs.trim().length > 0
      ? customDirs.split(new RegExp(`[,${path.delimiter === ';' ? ';' : ':'}]`, 'u'))
      : process.env['DERIVATIVE_TMP_DIRS']?.trim()
        ? process.env['DERIVATIVE_TMP_DIRS'].split(',')
        : [os.tmpdir()];

  const resolvedSet = new Set<string>();
  for (const entry of rawList) {
    const trimmed = entry.trim();
    if (trimmed.length > 0) {
      resolvedSet.add(path.resolve(trimmed));
    }
  }
  if (resolvedSet.size === 0) {
    resolvedSet.add(path.resolve(os.tmpdir()));
  }
  return [...resolvedSet];
}

/**
 * Thuật toán: Quét và xóa an toàn tệp/thư mục tạm tiền tố `'sda-'` hết hạn TTL chống tấn công Symlink & Path Traversal.
 */
export async function cleanStaleTempFiles(
  maxAgeMinutes: number = 15,
  targetDir: string = os.tmpdir(),
): Promise<number> {
  let cleaned = 0;
  const maxAgeMs = maxAgeMinutes * 60 * 1000;
  const now = Date.now();

  try {
    const resolvedBase = path.resolve(targetDir);
    const files = await fsp.readdir(resolvedBase).catch(() => []);

    for (const file of files) {
      if (!file.startsWith('sda-')) continue;
      const fullPath = path.resolve(resolvedBase, file);
      if (!fullPath.startsWith(`${resolvedBase}${path.sep}`)) continue;
      try {
        const stat = await fsp.lstat(fullPath);
        if (now - stat.mtimeMs > maxAgeMs) {
          if (stat.isSymbolicLink() || stat.isFile()) {
            await fsp.unlink(fullPath).catch(() => {});
          } else if (stat.isDirectory()) {
            await fsp.rm(fullPath, { recursive: true, force: true }).catch(() => {});
          }
          cleaned++;
        }
      } catch {
        // File might have already been cleaned up concurrently
      }
    }
  } catch (err) {
    console.warn(`Temp directory cleanup error: ${err}`);
  }

  return cleaned;
}

/**
 * Thuật toán: Đánh dấu hết hạn (`EXPIRED`) các phiên `access_sessions` đang `ACTIVE` nhưng không có hoạt động
 * kể từ trước `now - maxIdleSessionMinutes` (tự động quay lui sang `ENDED` nếu enum PostgreSQL cũ chưa có `EXPIRED`).
 */
export async function expireIdleAccessSessions(options?: {
  databaseClient?: PrismaClient;
  maxIdleSessionMinutes?: number;
  now?: Date;
}): Promise<number> {
  if (!options?.databaseClient && !process.env['DATABASE_URL']?.trim()) {
    return 0;
  }
  const database = options?.databaseClient ?? getDatabaseClient();
  if (typeof database.accessSession?.updateMany !== 'function') {
    return 0;
  }

  const configuredIdle =
    options?.maxIdleSessionMinutes ?? Number(process.env['MAX_IDLE_SESSION_MINUTES'] ?? '60');
  const idleMinutes = Number.isFinite(configuredIdle) && configuredIdle > 0 ? configuredIdle : 60;
  const now = options?.now ?? new Date();
  const idleCutoff = new Date(now.getTime() - idleMinutes * 60_000);

  try {
    const updated = await database.accessSession.updateMany({
      where: {
        status: 'ACTIVE',
        last_activity_at: { lt: idleCutoff },
      },
      data: {
        status: 'EXPIRED' as unknown as session_status,
        ended_at: now,
        terminated_reason: 'IDLE_SESSION_EXPIRED',
      },
    });
    return updated.count;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('invalid input value for enum') || msg.includes('22P02')) {
      const fallback = await database.accessSession.updateMany({
        where: {
          status: 'ACTIVE',
          last_activity_at: { lt: idleCutoff },
        },
        data: {
          status: 'ENDED',
          ended_at: now,
          terminated_reason: 'IDLE_SESSION_EXPIRED',
        },
      });
      return fallback.count;
    }
    throw err;
  }
}

/**
 * Thuật toán: Chạy trọn vẹn một chu kỳ dọn tệp dẫn xuất trên mọi thư mục `DERIVATIVE_TMP_DIRS` kèm thu hồi phiên nhàn rỗi.
 */
export async function runDerivativeCleanupCycle(options?: {
  ttlMinutes?: number;
  maxIdleSessionMinutes?: number;
  tmpDirs?: readonly string[] | string;
  databaseClient?: PrismaClient;
  now?: Date;
}): Promise<CleanupResult> {
  const ttlMinutes = options?.ttlMinutes ?? 60;
  const dirs = resolveDerivativeTmpDirs(options?.tmpDirs);
  let cleanedTempFiles = 0;
  for (const dir of dirs) {
    cleanedTempFiles += await cleanStaleTempFiles(ttlMinutes, dir);
  }
  const expiredSessions = await expireIdleAccessSessions({
    ...(options?.databaseClient ? { databaseClient: options.databaseClient } : {}),
    ...(options?.maxIdleSessionMinutes !== undefined
      ? { maxIdleSessionMinutes: options.maxIdleSessionMinutes }
      : {}),
    ...(options?.now ? { now: options.now } : {}),
  });
  return {
    cleanedTempFiles,
    expiredSessions,
    timestamp: (options?.now ?? new Date()).toISOString(),
  };
}

/**
 * Thuật toán: Bộ lập lịch định kỳ chống chồng lấn chu kỳ (Non-Overlapping Interval Scheduler) cho `DerivativeCleanupJob`.
 */
export function startDerivativeCleanupJob(
  intervalMs: number,
  ttlMinutes: number,
  signal: AbortSignal,
): void {
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
      const res = await runDerivativeCleanupCycle({ ttlMinutes });
      recordWorkerJobRun('derivative_cleanup', 'success');
      if (res.cleanedTempFiles > 0 || res.expiredSessions > 0) {
        console.info(
          `Derivative cleanup purged ${res.cleanedTempFiles} temp file(s) and expired ${res.expiredSessions} idle session(s).`,
        );
      }
    } catch (err) {
      recordWorkerJobRun('derivative_cleanup', 'error');
      console.error(`Derivative cleanup cycle failed: ${err}`);
    } finally {
      isRunning = false;
    }
  }, intervalMs);

  signal.addEventListener(
    'abort',
    () => {
      clearInterval(timer);
      console.info('Derivative cleanup job stopped cleanly.');
    },
    { once: true },
  );

  console.info(
    `Derivative cleanup worker started (interval: ${intervalMs}ms, TTL: ${ttlMinutes}m).`,
  );
}

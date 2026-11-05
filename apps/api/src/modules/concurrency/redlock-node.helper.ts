/**
 * @module RedlockNodeHelper
 * Algorithm: Single-Node Bounded-Timeout Redis NX/PX Lock Acquisition & Atomic Token-Verified Lua Release/Extend.
 */
import type { Logger } from '@nestjs/common';
import { Redis } from 'ioredis';
import type { AppConfigService } from '../../config/config.service.js';

export interface RedlockHandle {
  readonly resource: string;
  readonly token: string;
  readonly validityTimeMs: number;
  readonly acquiredAt: number;
  release(): Promise<boolean>;
  extend(additionalTtlMs: number): Promise<boolean>;
}

export interface RedlockAcquireOptions {
  retryCount?: number;
  retryDelayMs?: number;
  retryJitterMs?: number;
}

export interface RedlockExecutionOptions extends RedlockAcquireOptions {
  failClosed?: boolean;
}

/**
 * Atomic Lua CAS script for safe unlock: deletes key ONLY when current value matches caller's random token.
 */
export const UNLOCK_LUA_SCRIPT = `
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("del", KEYS[1])
else
  return 0
end
`;

/**
 * Atomic Lua CAS script for safe lock extension / heartbeat: refreshes PEXPIRE ONLY when value matches token.
 */
export const EXTEND_LUA_SCRIPT = `
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("pexpire", KEYS[1], ARGV[2])
else
  return 0
end
`;

/**
 * Algorithm / Thuật toán: Khởi tạo danh sách kết nối Redis độc lập cho cụm đồng thuận Redlock.
 */
export function createRedlockClients(config: AppConfigService, logger: Logger): Redis[] {
  const clusterNodes = config.get('REDLOCK_CLUSTER_NODES');
  const urls: string[] = clusterNodes
    ? clusterNodes
        .split(',')
        .map((u) => u.trim())
        .filter((u) => u.length > 0)
    : [config.get('REDIS_URL')];

  return urls.map((url) => {
    const client = new Redis(url, {
      lazyConnect: true,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
      connectTimeout: 1_000,
    });
    client.on('error', (err) => {
      logger.debug(`Redis node (${url}) error: ${err.message}`);
    });
    return client;
  });
}

/**
 * Algorithm / Thuật toán: Chiếm khóa nguyên tử `SET key token PX ttlMs NX` trên một nút Redis đơn lẻ kèm cắt ngưỡng thời gian chờ (`timeoutMs`).
 */
export function lockRedisInstance(
  client: Redis,
  key: string,
  token: string,
  ttlMs: number,
  timeoutMs: number,
): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        resolve(false);
      }
    }, timeoutMs);

    client
      .set(key, token, 'PX', ttlMs, 'NX')
      .then((res) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          resolve(res === 'OK');
        }
      })
      .catch(() => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          resolve(false);
        }
      });
  });
}

/**
 * Algorithm / Thuật toán: Giải phóng khóa nguyên tử bằng Lua CAS trên toàn bộ các nút và đối chiếu ngưỡng đa số (`>= quorum`).
 */
export async function releaseQuorumLocks(
  clients: Redis[],
  quorum: number,
  key: string,
  token: string,
): Promise<boolean> {
  const results = await Promise.allSettled(
    clients.map(async (client) => {
      try {
        const result = await client.eval(UNLOCK_LUA_SCRIPT, 1, key, token);
        return result === 1;
      } catch {
        return false;
      }
    }),
  );
  const unlockedCount = results.filter((r) => r.status === 'fulfilled' && r.value === true).length;
  return unlockedCount >= quorum;
}

/**
 * Algorithm / Thuật toán: Gia hạn thời gian sống khóa nguyên tử (`PEXPIRE`) bằng Lua CAS trên đa số nút (`>= quorum`).
 */
export async function extendQuorumLocks(
  clients: Redis[],
  quorum: number,
  key: string,
  token: string,
  additionalTtlMs: number,
): Promise<boolean> {
  const results = await Promise.allSettled(
    clients.map(async (client) => {
      try {
        const result = await client.eval(EXTEND_LUA_SCRIPT, 1, key, token, additionalTtlMs);
        return result === 1;
      } catch {
        return false;
      }
    }),
  );
  const extendedCount = results.filter((r) => r.status === 'fulfilled' && r.value === true).length;
  return extendedCount >= quorum;
}

/**
 * Algorithm / Thuật toán: Hoàn tác giải phóng khóa tức thời trên mọi nút khi không đạt đồng thuận Quorum.
 */
export async function unlockAllRedisInstances(
  clients: Redis[],
  key: string,
  token: string,
): Promise<void> {
  await Promise.allSettled(
    clients.map((client) => client.eval(UNLOCK_LUA_SCRIPT, 1, key, token).catch(() => undefined)),
  );
}

/**
 * Algorithm / Thuật toán: Thăm dò sức khỏe nhanh 500ms kiểm tra ít nhất một nút Redis còn phản hồi `PING`.
 */
export async function probeAnyRedisHealthy(clients: Redis[]): Promise<boolean> {
  try {
    const results = await Promise.allSettled(
      clients.map((c) =>
        Promise.race([
          c.ping(),
          new Promise<string>((_, reject) => setTimeout(() => reject(new Error('timeout')), 500)),
        ]),
      ),
    );
    return results.some((r) => r.status === 'fulfilled');
  } catch {
    return false;
  }
}

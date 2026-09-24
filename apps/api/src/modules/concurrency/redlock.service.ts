import {
  Injectable,
  Logger,
  type OnModuleDestroy,
  ConflictException,
  Optional,
} from '@nestjs/common';
import crypto from 'node:crypto';
import { Redis } from 'ioredis';
import { AppConfigService } from '../../config/config.service.js';

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

// Atomic Lua script for safe unlock: only delete if current value matches our unique random token
const UNLOCK_LUA_SCRIPT = `
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("del", KEYS[1])
else
  return 0
end
`;

// Atomic Lua script for safe lock extension / heartbeat: only extend if current value matches token
const EXTEND_LUA_SCRIPT = `
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("pexpire", KEYS[1], ARGV[2])
else
  return 0
end
`;

/**
 * REDLOCK DISTRIBUTED LOCK SERVICE
 * Implements the Redlock algorithm for distributed mutual exclusion across Redis instances/clusters.
 * Complies with Martin Kleppmann & Salvatore Sanfilippo (Antirez) specification:
 * - Multi-node Quorum consensus: N/2 + 1 nodes must agree within validity window
 * - Clock drift calculation: drift = validityTime * 0.01 + 2ms
 * - Atomic release via Lua script (prevents releasing locks that expired and were acquired by another worker)
 * - Atomic extension via Lua script (heartbeat/renewal)
 * - Randomized jitter backoff retry mechanism
 * - Two-tier Hybrid Concurrency Control (Redlock at application layer + SELECT ... FOR UPDATE at database layer)
 */
@Injectable()
export class RedlockService implements OnModuleDestroy {
  private readonly logger = new Logger(RedlockService.name);
  private readonly clients: Redis[];
  private readonly quorum: number;
  private readonly defaultRetryCount: number;
  private readonly defaultRetryDelayMs: number;
  private readonly defaultRetryJitterMs: number;
  private readonly defaultTtlMs: number;
  private readonly defaultFailClosed: boolean;
  private readonly driftFactor = 0.01;

  constructor(config: AppConfigService, @Optional() customClients?: Redis[]) {
    if (customClients && customClients.length > 0) {
      this.clients = customClients;
    } else {
      const clusterNodes = config.get('REDLOCK_CLUSTER_NODES');
      const urls: string[] = clusterNodes
        ? clusterNodes
            .split(',')
            .map((u) => u.trim())
            .filter((u) => u.length > 0)
        : [config.get('REDIS_URL')];

      this.clients = urls.map((url) => {
        const client = new Redis(url, {
          lazyConnect: true,
          enableOfflineQueue: false,
          maxRetriesPerRequest: 1,
          connectTimeout: 1_000,
        });
        client.on('error', (err) => {
          this.logger.debug(`Redis node (${url}) error: ${err.message}`);
        });
        return client;
      });
    }

    this.quorum = Math.floor(this.clients.length / 2) + 1;
    this.defaultRetryCount = config.get('REDLOCK_RETRY_COUNT') ?? 10;
    this.defaultRetryDelayMs = config.get('REDLOCK_RETRY_DELAY_MS') ?? 100;
    this.defaultRetryJitterMs = config.get('REDLOCK_RETRY_JITTER_MS') ?? 50;
    this.defaultTtlMs = config.get('REDLOCK_DEFAULT_TTL_MS') ?? 5000;
    this.defaultFailClosed = config.get('REDLOCK_FAIL_CLOSED') ?? false;

    this.logger.log(
      `RedlockService initialized with ${this.clients.length} node(s) (Quorum: ${this.quorum}/${this.clients.length})`,
    );
  }

  get nodeCount(): number {
    return this.clients.length;
  }

  get quorumCount(): number {
    return this.quorum;
  }

  /**
   * Helper to format Redis lock key
   */
  getLockKey(resource: string): string {
    return `sda:lock:${resource}`;
  }

  /**
   * Acquires a distributed lock on a resource using the Redlock algorithm.
   * Returns a RedlockHandle if successful, or null if quorum cannot be achieved.
   */
  async acquire(
    resource: string,
    ttlMs: number = this.defaultTtlMs,
    options?: RedlockAcquireOptions,
  ): Promise<RedlockHandle | null> {
    const lockKey = this.getLockKey(resource);
    const retryCount = options?.retryCount ?? this.defaultRetryCount;
    const retryDelayMs = options?.retryDelayMs ?? this.defaultRetryDelayMs;
    const retryJitterMs = options?.retryJitterMs ?? this.defaultRetryJitterMs;

    for (let attempt = 0; attempt <= retryCount; attempt++) {
      const token = crypto.randomUUID();
      const startTime = Date.now();

      // Attempt to acquire lock on all instances in parallel
      const nodeTimeoutMs = Math.max(10, Math.min(150, Math.floor(ttlMs / 10)));
      const lockPromises = this.clients.map((client) =>
        this.lockInstance(client, lockKey, token, ttlMs, nodeTimeoutMs),
      );

      const results = await Promise.allSettled(lockPromises);
      const successfulVotes = results.filter(
        (r) => r.status === 'fulfilled' && r.value === true,
      ).length;

      const elapsed = Date.now() - startTime;
      const drift = Math.round(ttlMs * this.driftFactor) + 2;
      const validityTimeMs = ttlMs - elapsed - drift;

      // Quorum achieved and lock is still valid in time window
      if (successfulVotes >= this.quorum && validityTimeMs > 0) {
        return {
          resource,
          token,
          validityTimeMs,
          acquiredAt: startTime,
          release: () => this.releaseLock(lockKey, token),
          extend: (additionalTtlMs: number) => this.extendLock(lockKey, token, additionalTtlMs),
        };
      }

      // Failed to reach quorum or validity expired: unlock all instances immediately
      await this.unlockAllInstances(lockKey, token);

      // If more retries left, wait with randomized jitter
      if (attempt < retryCount) {
        const jitter = Math.floor(Math.random() * retryJitterMs);
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs + jitter));
      }
    }

    return null;
  }

  /**
   * Executes a callback function with distributed mutual exclusion.
   * Automatically acquires the lock, executes the function, and releases the lock in a finally block.
   */
  async withLock<T>(
    resource: string,
    ttlMs: number = this.defaultTtlMs,
    fn: (handle: RedlockHandle) => Promise<T>,
    options?: RedlockExecutionOptions,
  ): Promise<T> {
    const handle = await this.acquire(resource, ttlMs, options);

    if (handle) {
      try {
        return await fn(handle);
      } finally {
        await handle.release().catch((err) => {
          this.logger.warn(`Failed to release lock on resource "${resource}": ${err.message}`);
        });
      }
    }

    // Lock acquisition failed
    const failClosed = options?.failClosed ?? this.defaultFailClosed;
    const isRedisReachable = await this.checkRedisHealth();

    // If Redis is down and failClosed is false, gracefully fallback to DB-level locking
    if (!isRedisReachable && !failClosed) {
      this.logger.warn(
        `[Redlock Degraded Mode] Redis lock unavailable for "${resource}"; proceeding with database-level row lock (SELECT ... FOR UPDATE).`,
      );
      const mockHandle: RedlockHandle = {
        resource,
        token: 'fallback-token',
        validityTimeMs: ttlMs,
        acquiredAt: Date.now(),
        release: async () => true,
        extend: async () => true,
      };
      return await fn(mockHandle);
    }

    throw new ConflictException({
      errorCode: 'DISTRIBUTED_LOCK_TIMEOUT',
      message: `Failed to acquire distributed lock for resource "${resource}". Concurrent operation is in progress.`,
    });
  }

  /**
   * Lock a single Redis instance with PX and NX
   */
  private async lockInstance(
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
   * Releases lock from all Redis instances using atomic Lua script
   */
  private async releaseLock(key: string, token: string): Promise<boolean> {
    const promises = this.clients.map(async (client) => {
      try {
        const result = await client.eval(UNLOCK_LUA_SCRIPT, 1, key, token);
        return result === 1;
      } catch {
        return false;
      }
    });

    const results = await Promise.allSettled(promises);
    const unlockedCount = results.filter(
      (r) => r.status === 'fulfilled' && r.value === true,
    ).length;
    return unlockedCount >= this.quorum;
  }

  /**
   * Extends lock TTL across all Redis instances using atomic Lua script
   */
  private async extendLock(key: string, token: string, additionalTtlMs: number): Promise<boolean> {
    const promises = this.clients.map(async (client) => {
      try {
        const result = await client.eval(EXTEND_LUA_SCRIPT, 1, key, token, additionalTtlMs);
        return result === 1;
      } catch {
        return false;
      }
    });

    const results = await Promise.allSettled(promises);
    const extendedCount = results.filter(
      (r) => r.status === 'fulfilled' && r.value === true,
    ).length;
    return extendedCount >= this.quorum;
  }

  /**
   * Unlock all instances regardless of individual success (used on failure to reach quorum)
   */
  private async unlockAllInstances(key: string, token: string): Promise<void> {
    await Promise.allSettled(
      this.clients.map((client) =>
        client.eval(UNLOCK_LUA_SCRIPT, 1, key, token).catch(() => undefined),
      ),
    );
  }

  /**
   * Quick probe to test if at least one Redis node is alive
   */
  async checkRedisHealth(): Promise<boolean> {
    try {
      const pingPromises = this.clients.map((c) =>
        Promise.race([
          c.ping(),
          new Promise<string>((_, reject) => setTimeout(() => reject(new Error('timeout')), 500)),
        ]),
      );
      const results = await Promise.allSettled(pingPromises);
      return results.some((r) => r.status === 'fulfilled');
    } catch {
      return false;
    }
  }

  onModuleDestroy(): void {
    for (const client of this.clients) {
      try {
        client.disconnect();
      } catch {
        // Ignore disconnect errors during teardown
      }
    }
  }
}

/**
 * @module RedlockService
 * Algorithm: Distributed Mutual Exclusion via Multi-Node Redlock Quorum Consensus & Clock-Drift Compensation.
 * Thuật toán khóa phân tán Redlock (Salvatore Sanfilippo):
 *   - Đồng thuận đa số tối thiểu `quorum = floor(N / 2) + 1` trên `N` nút Redis độc lập.
 *   - Bù trôi đồng hồ vật lý: `drift = round(ttlMs * 0.01) + 2ms`; hiệu lực thực `validityTimeMs = ttlMs - elapsed - drift`.
 *   - Thử lại lùi ngẫu nhiên (Randomized Jitter Backoff) và giải phóng/gia hạn nguyên tử bằng Lua CAS.
 *   - Kiểm soát đồng thời lai hai tầng (Hybrid Concurrency): hỗ trợ chuyển sang khóa bi quan DB (`SELECT ... FOR UPDATE`) khi Redis sự cố.
 */
import {
  ConflictException,
  Injectable,
  Logger,
  Optional,
  type OnModuleDestroy,
} from '@nestjs/common';
import crypto from 'node:crypto';
import type { Redis } from 'ioredis';
import { AppConfigService } from '../../config/config.service.js';
import {
  createRedlockClients,
  extendQuorumLocks,
  lockRedisInstance,
  probeAnyRedisHealthy,
  releaseQuorumLocks,
  unlockAllRedisInstances,
  type RedlockAcquireOptions,
  type RedlockExecutionOptions,
  type RedlockHandle,
} from './redlock-node.helper.js';

export type {
  RedlockAcquireOptions,
  RedlockExecutionOptions,
  RedlockHandle,
} from './redlock-node.helper.js';

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
    this.clients =
      customClients && customClients.length > 0
        ? customClients
        : createRedlockClients(config, this.logger);

    this.quorum = Math.floor(this.clients.length / 2) + 1;
    this.defaultRetryCount = config.get('REDLOCK_RETRY_COUNT') ?? 10;
    this.defaultRetryDelayMs = config.get('REDLOCK_RETRY_DELAY_MS') ?? 100;
    this.defaultRetryJitterMs = config.get('REDLOCK_RETRY_JITTER_MS') ?? 50;
    this.defaultTtlMs = config.get('REDLOCK_DEFAULT_TTL_MS') ?? 5000;
    // CONFLICT-RESOLVED: Chuyển chính sách khóa phân tán mặc định sang Fail-Closed (true) chống vượt rào đồng thời khi cụm Redis sự cố (MED-04).
    this.defaultFailClosed = config.get('REDLOCK_FAIL_CLOSED') ?? true;

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

  getLockKey(resource: string): string {
    return `sda:lock:${resource}`;
  }

  /**
   * Algorithm / Thuật toán: Chiếm khóa phân tán Redlock có bù độ lệch đồng hồ và thử lại ngẫu nhiên (Quorum Lock Acquisition with Clock-Drift Compensation).
   * Cơ chế hoạt động:
   *   1. Sinh định danh ngẫu nhiên `token = UUIDv4`, ghi mốc `startTime` và gửi song song `SET NX PX` tới mọi nút với timeout nhỏ (`ttlMs / 10`).
   *   2. Đếm số phiếu thành công `successfulVotes` và tính thời gian còn hiệu lực `validityTimeMs = ttlMs - elapsed - (round(ttlMs * 0.01) + 2)`.
   *   3. Nếu `successfulVotes >= quorum && validityTimeMs > 0` thì trả về `RedlockHandle`; ngược lại giải phóng ngay trên mọi nút và ngủ `retryDelayMs + jitter`.
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
      const nodeTimeoutMs = Math.max(10, Math.min(150, Math.floor(ttlMs / 10)));

      const results = await Promise.allSettled(
        this.clients.map((client) =>
          lockRedisInstance(client, lockKey, token, ttlMs, nodeTimeoutMs),
        ),
      );
      const successfulVotes = results.filter(
        (r) => r.status === 'fulfilled' && r.value === true,
      ).length;

      const elapsed = Date.now() - startTime;
      const drift = Math.round(ttlMs * this.driftFactor) + 2;
      const validityTimeMs = ttlMs - elapsed - drift;

      if (successfulVotes >= this.quorum && validityTimeMs > 0) {
        return {
          resource,
          token,
          validityTimeMs,
          acquiredAt: startTime,
          release: () => releaseQuorumLocks(this.clients, this.quorum, lockKey, token),
          extend: (additionalTtlMs: number) =>
            extendQuorumLocks(this.clients, this.quorum, lockKey, token, additionalTtlMs),
        };
      }

      await unlockAllRedisInstances(this.clients, lockKey, token);

      if (attempt < retryCount) {
        const jitter = Math.floor(Math.random() * retryJitterMs);
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs + jitter));
      }
    }

    return null;
  }

  /**
   * Algorithm / Thuật toán: Thực thi miền găng phân tán tự động giải phóng khóa và chuyển đổi dự phòng hai tầng (Hybrid Critical-Section Guard).
   *   - Nếu chiếm được khóa: thực thi `fn(handle)` và luôn giải phóng khóa trong khối `finally`.
   *   - Nếu không chiếm được khóa do cụm Redis mất kết nối và `failClosed === false`: hạ cấp an toàn xuống khóa dòng DB (`SELECT ... FOR UPDATE`).
   *   - Nếu đang có tranh chấp thật trên Redis hoặc bật `failClosed`: ném `409 DISTRIBUTED_LOCK_TIMEOUT`.
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
        await handle.release().catch((err: Error) => {
          this.logger.warn(`Failed to release lock on resource "${resource}": ${err.message}`);
        });
      }
    }

    const failClosed = options?.failClosed ?? this.defaultFailClosed;
    const isRedisReachable = await this.checkRedisHealth();

    if (!isRedisReachable && !failClosed) {
      this.logger.warn(
        `[Redlock Degraded Mode] Redis lock unavailable for "${resource}"; proceeding with database-level row lock (SELECT ... FOR UPDATE).`,
      );
      return await fn({
        resource,
        token: 'fallback-token',
        validityTimeMs: ttlMs,
        acquiredAt: Date.now(),
        release: async () => true,
        extend: async () => true,
      });
    }

    throw new ConflictException({
      errorCode: 'DISTRIBUTED_LOCK_TIMEOUT',
      message: `Failed to acquire distributed lock for resource "${resource}". Concurrent operation is in progress.`,
    });
  }

  checkRedisHealth(): Promise<boolean> {
    return probeAnyRedisHealthy(this.clients);
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

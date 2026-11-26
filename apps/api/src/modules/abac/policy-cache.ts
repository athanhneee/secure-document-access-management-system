/**
 * @module PolicyCache
 * Thuật toán: Bộ nhớ đệm chính sách ABAC hai tầng (L1 In-Memory + L2 Redis Fail-Open) định danh kép theo
 * `(abacCacheEpoch, policyVersion)` kết hợp đồng bộ xóa tức thì đa bản sao qua Redis Pub/Sub (`DistributedStateService.onInvalidate`)
 * nhằm triệt tiêu race condition ghi ngược tập luật chưa commit khi `nextval('abac_policy_version_seq')` tăng sớm (`BUG-051`).
 */
import { Injectable, Optional, type OnModuleDestroy } from '@nestjs/common';
import { Redis } from 'ioredis';
import { AppConfigService } from '../../config/config.service.js';
import { DistributedStateService } from '../concurrency/distributed-state.service.js';
import type { CompiledPolicy } from './abac.types.js';

const CURRENT_EPOCH_KEY = 'sda:abac:current_epoch';
const ABAC_EPOCH_REDIS_KEY = 'sda:epoch:abac-policy';
export const ABAC_POLICY_EPOCH_NAMESPACE = 'abac-policy';
const EPOCH_TTL_MS = 2_000;

@Injectable()
export class PolicyCache implements OnModuleDestroy {
  private readonly redis: Redis | null;
  private readonly localPolicies = new Map<string, { policy: CompiledPolicy; expiresAt: number }>();
  private localEpoch: { version: bigint; cacheEpoch: number; expiresAt: number } | null = null;
  private generation = 0;
  private fallbackCacheEpoch = 0;
  private unsubscribeInvalidate: (() => void) | null = null;

  constructor(
    @Optional() config?: AppConfigService,
    @Optional() customRedis?: Redis,
    @Optional() private readonly stateStore?: DistributedStateService,
  ) {
    if (this.stateStore && typeof this.stateStore.onInvalidate === 'function') {
      this.unsubscribeInvalidate = this.stateStore.onInvalidate((event) => {
        if (event.namespace === ABAC_POLICY_EPOCH_NAMESPACE) {
          this.generation += 1;
          this.localEpoch = null;
          this.localPolicies.clear();
        }
      });
    }

    if (customRedis) {
      this.redis = customRedis;
      return;
    }
    const nodeEnv = config?.get('NODE_ENV') ?? process.env['NODE_ENV'] ?? 'development';
    const redisUrl = config?.get('REDIS_URL') ?? process.env['REDIS_URL'];
    const isNodeTestRunner = Boolean(process.env['NODE_TEST_CONTEXT']);
    if (!redisUrl || nodeEnv === 'test' || isNodeTestRunner) {
      this.redis = null;
      return;
    }
    this.redis = new Redis(redisUrl, {
      lazyConnect: false,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
      connectTimeout: 1_000,
      retryStrategy: (times) => Math.min(Math.max(1, times) * 250, 5_000),
    });
    this.redis.on('error', () => undefined);
  }

  currentGeneration(): number {
    return this.generation;
  }

  /**
   * Thuật toán: Đọc số hiệu `abacCacheEpoch` phân tán hiện tại (tăng sau mỗi lần giao dịch sửa luật ABAC COMMIT).
   */
  async getAbacCacheEpoch(): Promise<number> {
    if (this.stateStore && typeof this.stateStore.getNamespaceEpoch === 'function') {
      try {
        return await this.stateStore.getNamespaceEpoch(ABAC_POLICY_EPOCH_NAMESPACE);
      } catch {
        return this.fallbackCacheEpoch;
      }
    }
    if (this.redis && typeof this.redis.get === 'function') {
      try {
        const raw = await this.redis.get(ABAC_EPOCH_REDIS_KEY);
        if (raw !== null && /^\d+$/u.test(raw)) {
          return Number(raw);
        }
      } catch {
        // Fallback safely to in-process epoch counter
      }
    }
    return this.fallbackCacheEpoch;
  }

  /**
   * Thuật toán: Đọc số hiệu phiên bản chính sách hiện hành từ bộ đệm ngắn hạn `2_000ms` có gắn khóa `abacCacheEpoch`.
   */
  async getCachedPolicyEpoch(explicitCacheEpoch?: number): Promise<bigint | null> {
    const now = Date.now();
    const cacheEpoch = explicitCacheEpoch ?? (await this.getAbacCacheEpoch());
    if (
      this.localEpoch &&
      this.localEpoch.expiresAt > now &&
      this.localEpoch.cacheEpoch === cacheEpoch
    ) {
      return this.localEpoch.version;
    }
    this.localEpoch = null;
    if (this.redis) {
      try {
        const raw = await this.redis.get(this.epochVersionKey(cacheEpoch));
        if (raw !== null && /^-?\d+$/u.test(raw)) {
          const parsed = BigInt(raw);
          this.localEpoch = { version: parsed, cacheEpoch, expiresAt: now + EPOCH_TTL_MS };
          return parsed;
        }
      } catch {
        // Degrade gracefully to PostgreSQL sequence read
      }
    }
    return null;
  }

  /**
   * Thuật toán: Lưu số hiệu phiên bản chính sách hiện tại với TTL ngắn `2_000ms` kèm kiểm tra không lệch `generation` / `abacCacheEpoch`.
   */
  async setCachedPolicyEpoch(
    version: bigint,
    ttlMs = EPOCH_TTL_MS,
    expectedCacheEpoch?: number,
    expectedGeneration?: number,
  ): Promise<void> {
    if (expectedGeneration !== undefined && expectedGeneration !== this.generation) {
      return;
    }
    const currentCacheEpoch = await this.getAbacCacheEpoch();
    if (expectedCacheEpoch !== undefined && currentCacheEpoch !== expectedCacheEpoch) {
      return;
    }
    if (expectedGeneration !== undefined && expectedGeneration !== this.generation) {
      return;
    }
    const safeTtlMs = Math.max(250, Math.floor(ttlMs));
    this.localEpoch = {
      version,
      cacheEpoch: currentCacheEpoch,
      expiresAt: Date.now() + safeTtlMs,
    };
    if (this.redis) {
      try {
        await this.redis.set(
          this.epochVersionKey(currentCacheEpoch),
          version.toString(),
          'PX',
          safeTtlMs,
        );
      } catch {
        // Non-authoritative cache
      }
    }
  }

  async get(version: string, explicitCacheEpoch?: number): Promise<CompiledPolicy | null> {
    const now = Date.now();
    const genBefore = this.generation;
    const cacheEpoch = explicitCacheEpoch ?? (await this.getAbacCacheEpoch());
    const localKey = `${cacheEpoch}:${version}`;
    const local = this.localPolicies.get(localKey);
    if (local && local.expiresAt > now && local.policy.version === version) {
      return local.policy;
    }
    this.localPolicies.delete(localKey);
    if (!this.redis) return null;
    try {
      const serialized = await this.redis.get(this.key(version, cacheEpoch));
      if (!serialized) return null;
      const parsed = JSON.parse(serialized) as CompiledPolicy;
      if (parsed.version !== version) return null;
      if (this.generation === genBefore) {
        this.setLocalPolicyBounded(localKey, parsed, now + 3_600_000);
      }
      return parsed;
    } catch {
      return null;
    }
  }

  async put(
    policy: CompiledPolicy,
    expectedCacheEpoch?: number,
    expectedGeneration?: number,
  ): Promise<void> {
    if (expectedGeneration !== undefined && expectedGeneration !== this.generation) {
      return;
    }
    const currentCacheEpoch = await this.getAbacCacheEpoch();
    if (expectedCacheEpoch !== undefined && currentCacheEpoch !== expectedCacheEpoch) {
      return;
    }
    if (expectedGeneration !== undefined && expectedGeneration !== this.generation) {
      return;
    }

    const localKey = `${currentCacheEpoch}:${policy.version}`;
    this.setLocalPolicyBounded(localKey, policy, Date.now() + 3_600_000);
    if (!this.redis) return;
    try {
      await this.redis.set(
        this.key(policy.version, currentCacheEpoch),
        JSON.stringify(policy),
        'EX',
        3600,
      );
      if (expectedGeneration !== undefined && expectedGeneration !== this.generation) {
        this.localPolicies.delete(localKey);
      }
    } catch {
      // Redis is never the policy source of truth. Evaluation can safely compile from PostgreSQL.
    }
  }

  async invalidate(version: string): Promise<void> {
    const prevEpoch = await this.getAbacCacheEpoch();
    this.generation += 1;
    this.localEpoch = null;
    this.localPolicies.delete(`${prevEpoch}:${version}`);
    if (!this.redis) return;
    try {
      await this.redis.del(
        CURRENT_EPOCH_KEY,
        this.epochVersionKey(prevEpoch),
        this.key(version, prevEpoch),
      );
    } catch {
      // Versioned keys prevent stale reuse even when Redis is temporarily unavailable.
    }
  }

  /**
   * Thuật toán: Tăng `abacCacheEpoch` phân tán sau khi giao dịch sửa luật đã COMMIT, phát Pub/Sub xóa tức thì L1 RAM trên mọi pod và dọn khóa phiên bản cũ (`BUG-051`).
   */
  async bumpPolicyEpoch(previousVersion?: string): Promise<void> {
    const prevEpoch = await this.getAbacCacheEpoch();
    this.generation += 1;
    this.fallbackCacheEpoch += 1;
    this.localEpoch = null;
    this.localPolicies.clear();

    if (this.stateStore && typeof this.stateStore.bumpNamespaceEpoch === 'function') {
      try {
        await this.stateStore.bumpNamespaceEpoch(ABAC_POLICY_EPOCH_NAMESPACE);
      } catch {
        // Degrade safely; local generation & fallbackCacheEpoch already advanced
      }
    } else if (this.redis && typeof this.redis.incr === 'function') {
      try {
        await this.redis.incr(ABAC_EPOCH_REDIS_KEY);
      } catch {
        // Safe fail-open invalidation on epoch-prefixed keys
      }
    }

    if (!this.redis) return;
    try {
      const keysToDelete = [CURRENT_EPOCH_KEY, this.epochVersionKey(prevEpoch)];
      if (previousVersion) {
        keysToDelete.push(this.key(previousVersion, prevEpoch));
      }
      await this.redis.del(...keysToDelete);
    } catch {
      // Safe fail-open invalidation on epoch-prefixed keys
    }
  }

  onModuleDestroy(): void {
    if (this.unsubscribeInvalidate) {
      this.unsubscribeInvalidate();
      this.unsubscribeInvalidate = null;
    }
    this.localEpoch = null;
    this.localPolicies.clear();
    if (this.redis) {
      this.redis.disconnect();
    }
  }

  private epochVersionKey(cacheEpoch: number): string {
    return `${CURRENT_EPOCH_KEY}:${cacheEpoch}`;
  }

  private key(version: string, cacheEpoch: number): string {
    return `sda:abac:compiled:${cacheEpoch}:${version}`;
  }

  private setLocalPolicyBounded(cacheKey: string, policy: CompiledPolicy, expiresAt: number): void {
    if (this.localPolicies.size >= 32) {
      const oldest = this.localPolicies.keys().next().value;
      if (oldest !== undefined) this.localPolicies.delete(oldest);
    }
    this.localPolicies.set(cacheKey, { policy, expiresAt });
  }
}

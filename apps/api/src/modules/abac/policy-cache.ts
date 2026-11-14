/**
 * @module PolicyCache
 * Thuật toán: Bộ nhớ đệm chính sách ABAC hai tầng (In-Memory + Redis Fail-Open) định danh theo phiên bản
 * kết hợp bộ đệm ngắn hạn `2_000ms` cho số hiệu Epoch hiện tại (`sda:abac:current_epoch`) được xóa tức thì
 * ngay khi `bumpPolicyEpoch` / `invalidate` thực thi, giúp `AbacService.evaluate` không phải truy vấn SQL sequence trên mỗi HTTP request.
 */
import { Injectable, Optional, type OnModuleDestroy } from '@nestjs/common';
import { Redis } from 'ioredis';
import { AppConfigService } from '../../config/config.service.js';
import type { CompiledPolicy } from './abac.types.js';

const CURRENT_EPOCH_KEY = 'sda:abac:current_epoch';
const EPOCH_TTL_MS = 2_000;

@Injectable()
export class PolicyCache implements OnModuleDestroy {
  private readonly redis: Redis | null;
  private readonly localPolicies = new Map<string, { policy: CompiledPolicy; expiresAt: number }>();
  private localEpoch: { version: bigint; expiresAt: number } | null = null;

  constructor(@Optional() config?: AppConfigService, @Optional() customRedis?: Redis) {
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
      lazyConnect: true,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
      connectTimeout: 1_000,
      retryStrategy: (times) => (times > 3 ? null : Math.min(times * 250, 1_000)),
    });
    this.redis.on('error', () => undefined);
  }

  /**
   * Thuật toán: Đọc số hiệu Epoch chính sách hiện hành từ bộ đệm ngắn hạn `2_000ms` (Local + Redis).
   */
  async getCachedPolicyEpoch(): Promise<bigint | null> {
    const now = Date.now();
    if (this.localEpoch && this.localEpoch.expiresAt > now) {
      return this.localEpoch.version;
    }
    this.localEpoch = null;
    if (this.redis) {
      try {
        const raw = await this.redis.get(CURRENT_EPOCH_KEY);
        if (raw !== null && /^-?\d+$/u.test(raw)) {
          const parsed = BigInt(raw);
          this.localEpoch = { version: parsed, expiresAt: now + EPOCH_TTL_MS };
          return parsed;
        }
      } catch {
        // Degrade gracefully to PostgreSQL sequence read
      }
    }
    return null;
  }

  /**
   * Thuật toán: Lưu số hiệu Epoch chính sách hiện tại với TTL ngắn `2_000ms` trên cả RAM và Redis.
   */
  async setCachedPolicyEpoch(version: bigint, ttlMs = EPOCH_TTL_MS): Promise<void> {
    const safeTtlMs = Math.max(250, Math.floor(ttlMs));
    this.localEpoch = { version, expiresAt: Date.now() + safeTtlMs };
    if (this.redis) {
      try {
        await this.redis.set(CURRENT_EPOCH_KEY, version.toString(), 'PX', safeTtlMs);
      } catch {
        // Non-authoritative cache
      }
    }
  }

  async get(version: string): Promise<CompiledPolicy | null> {
    const now = Date.now();
    const local = this.localPolicies.get(version);
    if (local && local.expiresAt > now && local.policy.version === version) {
      return local.policy;
    }
    this.localPolicies.delete(version);
    if (!this.redis) return null;
    try {
      const serialized = await this.redis.get(this.key(version));
      if (!serialized) return null;
      const parsed = JSON.parse(serialized) as CompiledPolicy;
      if (parsed.version !== version) return null;
      this.setLocalPolicyBounded(version, parsed, now + 3_600_000);
      return parsed;
    } catch {
      return null;
    }
  }

  async put(policy: CompiledPolicy): Promise<void> {
    this.setLocalPolicyBounded(policy.version, policy, Date.now() + 3_600_000);
    if (!this.redis) return;
    try {
      await this.redis.set(this.key(policy.version), JSON.stringify(policy), 'EX', 3600);
    } catch {
      // Redis is never the policy source of truth. Evaluation can safely compile from PostgreSQL.
    }
  }

  async invalidate(version: string): Promise<void> {
    this.localEpoch = null;
    this.localPolicies.delete(version);
    if (!this.redis) return;
    try {
      await this.redis.del(CURRENT_EPOCH_KEY, this.key(version));
    } catch {
      // Versioned keys prevent stale reuse even when Redis is temporarily unavailable.
    }
  }

  /**
   * Thuật toán: Xóa tức thì khóa Epoch hiện hành (`sda:abac:current_epoch`) cùng bản biên dịch phiên bản cũ.
   */
  async bumpPolicyEpoch(previousVersion?: string): Promise<void> {
    this.localEpoch = null;
    if (previousVersion) {
      this.localPolicies.delete(previousVersion);
    }
    if (!this.redis) return;
    try {
      if (previousVersion) {
        await this.redis.del(CURRENT_EPOCH_KEY, this.key(previousVersion));
      } else {
        await this.redis.del(CURRENT_EPOCH_KEY);
      }
    } catch {
      // Safe fail-open invalidation on versioned keys
    }
  }

  onModuleDestroy(): void {
    this.localEpoch = null;
    this.localPolicies.clear();
    if (this.redis) {
      this.redis.disconnect();
    }
  }

  private key(version: string): string {
    return `sda:abac:compiled:${version}`;
  }

  private setLocalPolicyBounded(version: string, policy: CompiledPolicy, expiresAt: number): void {
    if (this.localPolicies.size >= 32) {
      const oldest = this.localPolicies.keys().next().value;
      if (oldest !== undefined) this.localPolicies.delete(oldest);
    }
    this.localPolicies.set(version, { policy, expiresAt });
  }
}

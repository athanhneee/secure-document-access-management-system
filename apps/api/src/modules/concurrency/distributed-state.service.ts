/**
 * @module DistributedStateService
 * Thuật toán: Kho Trạng Thái Bảo Mật Phân Tán Hai Tầng (Redis Command + Pub/Sub + L1 In-Memory Invalidation).
 *   1. Chống phát lại (`claimOnce`): `SET sda:state:<ns>:<id> "1" PX <ttlMs> NX`.
 *   2. Vé dùng một lần (`putEphemeral` / `consumeOnce`): Đọc & xóa nguyên tử bằng Lua (`GET` + `DEL`).
 *   3. Bộ đếm cửa sổ (`incrementWindowCounter`): Tăng nguyên tử `INCR` + `PEXPIRE` qua Lua.
 *   4. Đọc gộp 1-RTT (`mgetBatch`): Gom nhiều khóa Epoch + State vào đúng 1 lệnh `MGET` duy nhất.
 *   5. Vô hiệu hóa 1-RTT (`bumpNamespaceEpoch` / `deleteKey`): Thực thi Lua `INCR/DEL` + `PUBLISH sda:cache:invalidate`
 *      để mọi bản sao API xóa đệm L1 tức thì mà không phải gọi nhiều RTT tuần tự.
 */
import {
  Injectable,
  Logger,
  Optional,
  ServiceUnavailableException,
  type OnModuleDestroy,
} from '@nestjs/common';
import type { Redis } from 'ioredis';
import { AppConfigService } from '../../config/config.service.js';
import {
  BUMP_EPOCH_AND_PUBLISH_LUA,
  CACHE_INVALIDATION_CHANNEL,
  CONSUME_ONCE_LUA,
  createActiveRedisClient,
  createRedisSubscriberClient,
  DEL_AND_PUBLISH_LUA,
  INCR_WINDOW_LUA,
  parseCacheInvalidationPayload,
  type CacheInvalidationEvent,
} from './distributed-state-pubsub.helper.js';

export type { CacheInvalidationEvent };

interface LocalEntry {
  value: string;
  expiresAt: number;
}

export interface StatePolicyOptions {
  failClosedInProd?: boolean;
}

export type BatchLookupItem =
  { kind: 'epoch'; namespace: string } | { kind: 'state'; namespace: string; id: string };

@Injectable()
export class DistributedStateService implements OnModuleDestroy {
  private readonly logger = new Logger(DistributedStateService.name);
  private readonly redis: Redis | null;
  private readonly subscriber: Redis | null;
  private readonly isStrictEnv: boolean;
  private readonly localNamespaces = new Map<string, Map<string, LocalEntry>>();
  private readonly localMaxPerNamespace = 10_000;
  private readonly invalidationListeners = new Set<(event: CacheInvalidationEvent) => void>();
  private readonly channelListeners = new Map<string, Set<(message: string) => void>>();

  constructor(@Optional() config?: AppConfigService, @Optional() customRedis?: Redis) {
    const nodeEnv = config?.get('NODE_ENV') ?? process.env['NODE_ENV'] ?? 'development';
    this.isStrictEnv = nodeEnv === 'production' || nodeEnv === 'staging';

    if (customRedis) {
      this.redis = customRedis;
      this.subscriber = null;
      return;
    }

    const redisUrl = config?.get('REDIS_URL') ?? process.env['REDIS_URL'];
    const isNodeTestRunner = Boolean(process.env['NODE_TEST_CONTEXT']);
    if (!redisUrl || nodeEnv === 'test' || (isNodeTestRunner && !this.isStrictEnv)) {
      this.redis = null;
      this.subscriber = null;
      return;
    }

    this.redis = createActiveRedisClient(redisUrl, this.logger, 'state store');
    this.subscriber = createRedisSubscriberClient(redisUrl, this.logger, (channel, message) => {
      this.handlePubSubMessage(channel, message);
    });
  }

  hasRemoteRedis(): boolean {
    return this.redis !== null;
  }

  /** Thuật toán: Đăng ký bộ lắng nghe sự kiện vô hiệu hóa L1 (Epoch/Key) nhận cả tín hiệu cục bộ lẫn Redis Pub/Sub. */
  onInvalidate(listener: (event: CacheInvalidationEvent) => void): () => void {
    this.invalidationListeners.add(listener);
    return () => {
      this.invalidationListeners.delete(listener);
    };
  }

  /** Thuật toán: Đăng ký nhận thông điệp Pub/Sub theo kênh (phục vụ cầu nối Realtime SSE đa tiến trình API <-> Worker). */
  subscribeChannel(channel: string, listener: (message: string) => void): () => void {
    let set = this.channelListeners.get(channel);
    if (!set) {
      set = new Set();
      this.channelListeners.set(channel, set);
    }
    set.add(listener);
    return () => {
      set?.delete(listener);
    };
  }

  /** Thuật toán: Phát thông điệp lên kênh Redis Pub/Sub (hoặc phát nội bộ tức thì khi chạy đơn tiến trình không có Redis). */
  async publishChannel(channel: string, message: string): Promise<boolean> {
    if (this.redis) {
      try {
        await this.redis.publish(channel, message);
        return true;
      } catch {
        // Fallback to local delivery so single-node SSE clients still receive the event
      }
    }
    this.dispatchChannelLocal(channel, message);
    return false;
  }

  /** Thuật toán: Đọc gộp nhiều khóa Epoch và State trong đúng 1 lệnh `MGET` Redis duy nhất (triệt tiêu chuỗi RTT tuần tự). */
  async mgetBatch(items: readonly BatchLookupItem[]): Promise<Array<string | null>> {
    if (items.length === 0) return [];
    const redisKeys = items.map((item) =>
      item.kind === 'epoch' ? this.epochKey(item.namespace) : this.key(item.namespace, item.id),
    );
    if (this.redis) {
      try {
        if (typeof this.redis.mget === 'function') {
          return await this.redis.mget(...redisKeys);
        }
        return await Promise.all(redisKeys.map((k) => this.redis!.get(k)));
      } catch {
        // Degrade safely to local cache / DB evaluation
      }
    }
    const now = Date.now();
    return items.map((item) => {
      if (item.kind === 'epoch') {
        const entry = this.bucket('__epochs__').get(item.namespace);
        return entry && entry.expiresAt > now ? entry.value : null;
      }
      const bucket = this.bucket(item.namespace);
      const entry = bucket.get(item.id);
      if (!entry) return null;
      if (entry.expiresAt <= now) {
        bucket.delete(item.id);
        return null;
      }
      return entry.value;
    });
  }

  /** Thuật toán: Đánh dấu tiêu thụ nguyên tử một lần (`SET NX PX`) chống tấn công phát lại xuyên bản sao. */
  async claimOnce(
    namespace: string,
    id: string,
    ttlMs: number,
    options?: StatePolicyOptions,
  ): Promise<boolean> {
    const safeTtlMs = Math.max(1_000, Math.floor(ttlMs));
    if (this.redis) {
      try {
        return (await this.redis.set(this.key(namespace, id), '1', 'PX', safeTtlMs, 'NX')) === 'OK';
      } catch (err) {
        this.enforceFallbackPolicy(namespace, err, options?.failClosedInProd ?? true);
      }
    }
    const now = Date.now();
    const existing = this.bucket(namespace).get(id);
    if (existing && existing.expiresAt > now) return false;
    this.setLocalBounded(namespace, id, '1', now + safeTtlMs);
    return true;
  }

  /** Thuật toán: Lưu trữ vé/trạng thái ngắn hạn có TTL tự hủy trên Redis (`SET PX`). */
  async putEphemeral<T>(
    namespace: string,
    id: string,
    value: T,
    ttlMs: number,
    options?: StatePolicyOptions,
  ): Promise<void> {
    const serialized = JSON.stringify(value);
    const safeTtlMs = Math.max(1_000, Math.floor(ttlMs));
    if (this.redis) {
      try {
        await this.redis.set(this.key(namespace, id), serialized, 'PX', safeTtlMs);
        return;
      } catch (err) {
        this.enforceFallbackPolicy(namespace, err, options?.failClosedInProd ?? false);
      }
    }
    this.setLocalBounded(namespace, id, serialized, Date.now() + safeTtlMs);
  }

  /** Thuật toán: Đọc và hủy nguyên tử vé một lần bằng Lua (`GET` + `DEL`). */
  async consumeOnce<T>(
    namespace: string,
    id: string,
    options?: StatePolicyOptions,
  ): Promise<T | null> {
    if (this.redis) {
      try {
        const raw = (await this.redis.eval(CONSUME_ONCE_LUA, 1, this.key(namespace, id))) as
          string | null;
        return raw ? (JSON.parse(raw) as T) : null;
      } catch (err) {
        this.enforceFallbackPolicy(namespace, err, options?.failClosedInProd ?? true);
      }
    }
    const bucket = this.bucket(namespace);
    const entry = bucket.get(id);
    bucket.delete(id);
    return entry && entry.expiresAt > Date.now() ? (JSON.parse(entry.value) as T) : null;
  }

  async getJson<T>(namespace: string, id: string): Promise<T | null> {
    const fullKey = this.key(namespace, id);
    if (this.redis) {
      try {
        const raw = await this.redis.get(fullKey);
        return raw ? (JSON.parse(raw) as T) : null;
      } catch {
        // Non-authoritative caches degrade safely to DB evaluation.
      }
    }
    const bucket = this.bucket(namespace);
    const entry = bucket.get(id);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      bucket.delete(id);
      return null;
    }
    return JSON.parse(entry.value) as T;
  }

  /** Thuật toán: Xóa khóa trạng thái và phát sự kiện vô hiệu hóa L1 trong đúng 1 vòng RTT Lua (`DEL` + `PUBLISH`). */
  async deleteKey(namespace: string, id: string): Promise<void> {
    this.localNamespaces.get(namespace)?.delete(id);
    this.notifyInvalidation({ kind: 'key', namespace, id });
    if (this.redis) {
      try {
        const payload = `key:${namespace}:${id}`;
        if (typeof this.redis.eval === 'function') {
          await this.redis.eval(
            DEL_AND_PUBLISH_LUA,
            1,
            this.key(namespace, id),
            CACHE_INVALIDATION_CHANNEL,
            payload,
          );
        } else {
          await this.redis.del(this.key(namespace, id));
        }
      } catch {
        // Callers pair critical invalidations with epoch bumps.
      }
    }
  }

  /** Thuật toán: Bộ đếm cửa sổ thời gian nguyên tử bằng Lua (`INCR` + `PEXPIRE`). */
  async incrementWindowCounter(
    namespace: string,
    id: string,
    windowMs: number,
    options?: StatePolicyOptions,
  ): Promise<{ count: number; ttlMs: number }> {
    const fullKey = this.key(namespace, id);
    const safeWindowMs = Math.max(1_000, Math.floor(windowMs));

    if (this.redis) {
      try {
        const [count, ttlMs] = (await this.redis.eval(
          INCR_WINDOW_LUA,
          1,
          fullKey,
          String(safeWindowMs),
        )) as [number, number];
        return { count: Number(count), ttlMs: Math.max(0, Number(ttlMs)) };
      } catch (err) {
        this.enforceFallbackPolicy(namespace, err, options?.failClosedInProd ?? false);
      }
    }

    const bucket = this.bucket(namespace);
    const now = Date.now();
    const existing = bucket.get(id);
    if (!existing || existing.expiresAt <= now) {
      this.setLocalBounded(namespace, id, '1', now + safeWindowMs);
      return { count: 1, ttlMs: safeWindowMs };
    }
    const nextCount = Number(existing.value) + 1;
    existing.value = String(nextCount);
    return { count: nextCount, ttlMs: Math.max(0, existing.expiresAt - now) };
  }

  /** Thuật toán: Đọc số hiệu thế hệ (`Epoch Versioning`) từ Redis hoặc kho cục bộ. */
  async getNamespaceEpoch(namespace: string): Promise<number> {
    const fullKey = this.epochKey(namespace);
    if (this.redis) {
      try {
        const raw = await this.redis.get(fullKey);
        return raw ? Number(raw) || 0 : 0;
      } catch {
        // Fall through to local epoch
      }
    }
    const entry = this.bucket('__epochs__').get(namespace);
    return entry && entry.expiresAt > Date.now() ? Number(entry.value) || 0 : 0;
  }

  /**
   * Thuật toán: Tăng Epoch vô hiệu hóa bộ đệm và phát sóng Pub/Sub trong đúng 1 vòng RTT Lua duy nhất (`INCR` + `PEXPIRE` + `PUBLISH`),
   * loại bỏ hoàn toàn 3 vòng RTT tuần tự (`GET` -> `INCR` -> `PEXPIRE`) trước đây.
   */
  async bumpNamespaceEpoch(namespace: string, ttlMs: number = 86_400_000): Promise<number> {
    const fullKey = this.epochKey(namespace);
    const safeTtlMs = Math.max(1_000, Math.floor(ttlMs));
    const localBucket = this.bucket('__epochs__');
    const existingLocal = localBucket.get(namespace);
    const nextLocal =
      (existingLocal && existingLocal.expiresAt > Date.now()
        ? Number(existingLocal.value) || 0
        : 0) + 1;
    this.setLocalBounded('__epochs__', namespace, String(nextLocal), Date.now() + safeTtlMs);
    this.notifyInvalidation({ kind: 'epoch', namespace, epoch: nextLocal });

    if (this.redis) {
      try {
        const val =
          typeof this.redis.eval === 'function'
            ? Number(
                await this.redis.eval(
                  BUMP_EPOCH_AND_PUBLISH_LUA,
                  1,
                  fullKey,
                  String(safeTtlMs),
                  CACHE_INVALIDATION_CHANNEL,
                  namespace,
                ),
              )
            : await this.redis.incr(fullKey);
        if (typeof this.redis.eval !== 'function') {
          await this.redis.pexpire(fullKey, safeTtlMs);
        }
        this.setLocalBounded('__epochs__', namespace, String(val), Date.now() + safeTtlMs);
        this.notifyInvalidation({ kind: 'epoch', namespace, epoch: val });
        return val;
      } catch {
        return nextLocal;
      }
    }
    return nextLocal;
  }

  onModuleDestroy(): void {
    this.localNamespaces.clear();
    this.invalidationListeners.clear();
    this.channelListeners.clear();
    if (this.subscriber) {
      this.subscriber.disconnect();
    }
    if (this.redis) {
      this.redis.disconnect();
    }
  }

  private handlePubSubMessage(channel: string, message: string): void {
    if (channel === CACHE_INVALIDATION_CHANNEL) {
      const event = parseCacheInvalidationPayload(message);
      if (!event) return;
      if (event.kind === 'epoch') {
        this.setLocalBounded(
          '__epochs__',
          event.namespace,
          String(event.epoch),
          Date.now() + 86_400_000,
        );
      } else {
        this.localNamespaces.get(event.namespace)?.delete(event.id);
      }
      this.notifyInvalidation(event);
      return;
    }
    this.dispatchChannelLocal(channel, message);
  }

  private dispatchChannelLocal(channel: string, message: string): void {
    const listeners = this.channelListeners.get(channel);
    if (!listeners || listeners.size === 0) return;
    for (const listener of listeners) {
      try {
        listener(message);
      } catch {
        // Isolate subscriber callback exceptions
      }
    }
  }

  private notifyInvalidation(event: CacheInvalidationEvent): void {
    for (const listener of this.invalidationListeners) {
      try {
        listener(event);
      } catch {
        // Isolate L1 invalidation callback exceptions
      }
    }
  }

  private key(namespace: string, id: string): string {
    return `sda:state:${namespace}:${id}`;
  }

  private epochKey(namespace: string): string {
    return `sda:epoch:${namespace}`;
  }

  private bucket(namespace: string): Map<string, LocalEntry> {
    let map = this.localNamespaces.get(namespace);
    if (!map) {
      map = new Map<string, LocalEntry>();
      this.localNamespaces.set(namespace, map);
    }
    return map;
  }

  private enforceFallbackPolicy(namespace: string, err: unknown, failClosedInProd: boolean): void {
    if (this.isStrictEnv && failClosedInProd) {
      this.logger.error(
        `Strict security state failure in "${namespace}": ${err instanceof Error ? err.message : 'Redis unreachable'}`,
      );
      throw new ServiceUnavailableException({
        errorCode: 'REDIS_STATE_UNAVAILABLE',
        message: 'Distributed security state store is temporarily unavailable.',
      });
    }
  }

  private setLocalBounded(namespace: string, id: string, value: string, expiresAt: number): void {
    const bucket = this.bucket(namespace);
    if (!bucket.has(id) && bucket.size >= this.localMaxPerNamespace) {
      const now = Date.now();
      for (const [k, v] of bucket) {
        if (v.expiresAt <= now) bucket.delete(k);
      }
      if (bucket.size >= this.localMaxPerNamespace) {
        const oldestKey = bucket.keys().next().value;
        if (oldestKey !== undefined) bucket.delete(oldestKey);
      }
    }
    bucket.set(id, { value, expiresAt });
  }
}

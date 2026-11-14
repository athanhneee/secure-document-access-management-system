/**
 * @module DistributedStateService
 * Thuật toán: Quản lý Trạng thái Bảo mật Phân tán Nguyên tử trên Redis kèm Dự phòng Bộ nhớ Theo Phân vùng cho Kiểm thử Đơn vị (`DistributedStateService`).
 *   1. Chống phát lại (`claimOnce`): Thực thi nguyên tử `SET sda:state:<ns>:<id> "1" PX <ttlMs> NX` trên Redis trên toàn cụm đa bản sao.
 *   2. Vé dùng một lần (`putEphemeral` / `consumeOnce`): Đọc và xóa nguyên tử qua kịch bản Lua (`GET` + `DEL`).
 *   3. Bộ đếm cửa sổ (`incrementWindowCounter`): Tăng nguyên tử `INCR` + `PEXPIRE` qua Lua phục vụ giới hạn tốc độ toàn cụm.
 *   4. Đệm phiên bản hóa theo Epoch (`getNamespaceEpoch` / `bumpNamespaceEpoch`): Vô hiệu hóa tức thì bộ đệm quyền/phiên trong `O(1)`.
 *   5. Chính sách Fail-Closed trên `production`/`staging`: Khi bật `failClosedInProd`, mất kết nối Redis trả `503 REDIS_STATE_UNAVAILABLE`; môi trường `test` cô lập dự phòng theo từng `namespace` có trần `10_000` khóa/nhóm (ngăn ngập một nhóm đẩy bật khóa nhóm bảo mật khác).
 */
import {
  Injectable,
  Logger,
  Optional,
  ServiceUnavailableException,
  type OnModuleDestroy,
} from '@nestjs/common';
import { Redis } from 'ioredis';
import { AppConfigService } from '../../config/config.service.js';
import { redactRedisEndpointUrl } from './redlock-node.helper.js';

const CONSUME_ONCE_LUA =
  'local v=redis.call("get",KEYS[1]);if v then redis.call("del",KEYS[1]) end;return v';

const INCR_WINDOW_LUA = [
  'local c=redis.call("incr",KEYS[1])',
  'if c==1 then redis.call("pexpire",KEYS[1],ARGV[1]) end',
  'local t=redis.call("pttl",KEYS[1])',
  'if t<0 then redis.call("pexpire",KEYS[1],ARGV[1]);t=tonumber(ARGV[1]) end',
  'return {c,t}',
].join(';');

interface LocalEntry {
  value: string;
  expiresAt: number;
}
export interface StatePolicyOptions {
  failClosedInProd?: boolean;
}

@Injectable()
export class DistributedStateService implements OnModuleDestroy {
  private readonly logger = new Logger(DistributedStateService.name);
  private readonly redis: Redis | null;
  private readonly isStrictEnv: boolean;
  private readonly localNamespaces = new Map<string, Map<string, LocalEntry>>();
  private readonly localMaxPerNamespace = 10_000;

  constructor(@Optional() config?: AppConfigService, @Optional() customRedis?: Redis) {
    const nodeEnv = config?.get('NODE_ENV') ?? process.env['NODE_ENV'] ?? 'development';
    this.isStrictEnv = nodeEnv === 'production' || nodeEnv === 'staging';

    if (customRedis) {
      this.redis = customRedis;
      return;
    }

    const redisUrl = config?.get('REDIS_URL') ?? process.env['REDIS_URL'];
    const isNodeTestRunner = Boolean(process.env['NODE_TEST_CONTEXT']);
    if (!redisUrl || nodeEnv === 'test' || (isNodeTestRunner && !this.isStrictEnv)) {
      this.redis = null;
      return;
    }

    const safeUrl = redactRedisEndpointUrl(redisUrl);
    this.redis = new Redis(redisUrl, {
      lazyConnect: true,
      enableOfflineQueue: true,
      maxRetriesPerRequest: 1,
      connectTimeout: 3_000,
      commandTimeout: 2_500,
      retryStrategy: (times) => (times > 3 ? null : Math.min(times * 250, 1_000)),
    });
    this.redis.on('error', (err) => {
      this.logger.debug(`Redis state store (${safeUrl}) connection notice: ${err.message}`);
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

  async deleteKey(namespace: string, id: string): Promise<void> {
    this.localNamespaces.get(namespace)?.delete(id);
    if (this.redis) {
      try {
        await this.redis.del(this.key(namespace, id));
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

  /** Thuật toán: Đọc/Tăng số hiệu thế hệ (`Epoch Versioning`) vô hiệu hóa bộ đệm trong `O(1)`. */
  async getNamespaceEpoch(namespace: string): Promise<number> {
    const fullKey = `sda:epoch:${namespace}`;
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

  async bumpNamespaceEpoch(namespace: string, ttlMs: number = 86_400_000): Promise<number> {
    const fullKey = `sda:epoch:${namespace}`;
    const nextLocal = (await this.getNamespaceEpoch(namespace)) + 1;
    this.setLocalBounded('__epochs__', namespace, String(nextLocal), Date.now() + ttlMs);

    if (this.redis) {
      try {
        const val = await this.redis.incr(fullKey);
        await this.redis.pexpire(fullKey, ttlMs);
        return val;
      } catch {
        return nextLocal;
      }
    }
    return nextLocal;
  }

  onModuleDestroy(): void {
    this.localNamespaces.clear();
    if (this.redis) {
      this.redis.disconnect();
    }
  }

  private key(namespace: string, id: string): string {
    return `sda:state:${namespace}:${id}`;
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

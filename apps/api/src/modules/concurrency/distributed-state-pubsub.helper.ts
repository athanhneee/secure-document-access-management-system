/**
 * @module DistributedStatePubSubHelper
 * Thuật toán: Kịch bản Lua nguyên tử 1-RTT (`BUMP_EPOCH_AND_PUBLISH_LUA`, `DEL_AND_PUBLISH_LUA`)
 * và bộ điều phối kênh Redis Pub/Sub (`sda:cache:invalidate`, `sda:realtime:events`) đồng bộ xóa đệm L1 xuyên bản sao.
 */
import type { Logger } from '@nestjs/common';
import { Redis } from 'ioredis';
import { redactRedisEndpointUrl } from './redlock-node.helper.js';

export const CACHE_INVALIDATION_CHANNEL = 'sda:cache:invalidate';
export const REALTIME_EVENTS_CHANNEL = 'sda:realtime:events';

export const CONSUME_ONCE_LUA =
  'local v=redis.call("get",KEYS[1]);if v then redis.call("del",KEYS[1]) end;return v';

export const INCR_WINDOW_LUA = [
  'local c=redis.call("incr",KEYS[1])',
  'if c==1 then redis.call("pexpire",KEYS[1],ARGV[1]) end',
  'local t=redis.call("pttl",KEYS[1])',
  'if t<0 then redis.call("pexpire",KEYS[1],ARGV[1]);t=tonumber(ARGV[1]) end',
  'return {c,t}',
].join(';');

/**
 * Thuật toán: Tăng Epoch, đặt TTL và phát thông điệp Pub/Sub vô hiệu hóa L1 trong đúng 1 vòng RTT Redis nguyên tử.
 */
export const BUMP_EPOCH_AND_PUBLISH_LUA = [
  'local v=redis.call("incr",KEYS[1])',
  'redis.call("pexpire",KEYS[1],ARGV[1])',
  'redis.call("publish",ARGV[2],ARGV[3] .. ":" .. tostring(v))',
  'return v',
].join(';');

/**
 * Thuật toán: Xóa khóa trạng thái và phát tín hiệu xóa đệm L1 xuyên bản sao trong đúng 1 vòng RTT Redis nguyên tử.
 */
export const DEL_AND_PUBLISH_LUA = [
  'local removed=redis.call("del",KEYS[1])',
  'redis.call("publish",ARGV[1],ARGV[2])',
  'return removed',
].join(';');

/**
 * Thuật toán: Ghi có điều kiện Compare-And-Swap theo thế hệ Epoch bằng Lua nguyên tử 1-RTT (`SET_IF_EPOCHS_MATCH_LUA`, `BUG-043`).
 * Chỉ thực thi `SET KEYS[1] ARGV[1] PX ARGV[2]` nếu mọi khóa thế hệ `KEYS[2..N]` trên Redis vẫn bằng đúng tem `ARGV[3..N+1]` đã chụp trước lúc đọc CSDL.
 */
export const SET_IF_EPOCHS_MATCH_LUA = [
  'for i = 2, #KEYS do',
  '  local cur = tonumber(redis.call("get", KEYS[i]) or "0") or 0',
  '  local exp = tonumber(ARGV[i + 1]) or 0',
  '  if cur ~= exp then return 0 end',
  'end',
  'redis.call("set", KEYS[1], ARGV[1], "PX", ARGV[2])',
  'return 1',
].join('\n');

export type CacheInvalidationEvent =
  | { kind: 'epoch'; namespace: string; epoch: number }
  | { kind: 'key'; namespace: string; id: string };

/**
 * Thuật toán: Giải mã bản tin vô hiệu hóa từ kênh `sda:cache:invalidate` sang sự kiện định kiểu an toàn.
 */
export function parseCacheInvalidationPayload(raw: string): CacheInvalidationEvent | null {
  if (raw.startsWith('key:')) {
    const rest = raw.slice(4);
    const sepIdx = rest.indexOf(':');
    if (sepIdx <= 0) return null;
    return {
      kind: 'key',
      namespace: rest.slice(0, sepIdx),
      id: rest.slice(sepIdx + 1),
    };
  }
  const lastColon = raw.lastIndexOf(':');
  if (lastColon <= 0) return null;
  const namespace = raw.slice(0, lastColon);
  const epoch = Number(raw.slice(lastColon + 1));
  if (!namespace || !Number.isFinite(epoch)) return null;
  return { kind: 'epoch', namespace, epoch };
}

/**
 * Thuật toán: Chiến lược thử lại kết nối Redis lệnh với độ trễ tăng dần có trần 5 giây (Capped Indefinite Backoff).
 * Tuyệt đối không trả về `null` để ngăn `ioredis` chuyển sang trạng thái `'end'` vĩnh viễn sau sự cố mạng/failover > 3,75 giây.
 */
export function activeRedisRetryStrategy(times: number): number {
  return Math.min(Math.max(1, times) * 250, 5_000);
}

/**
 * Thuật toán: Khởi tạo cặp kết nối Redis chủ động (Command Client + Pub/Sub Subscriber) có tự nối lại vô hạn với backoff có trần và không chặn khởi động.
 */
export function createActiveRedisClient(redisUrl: string, logger: Logger, label: string): Redis {
  const safeUrl = redactRedisEndpointUrl(redisUrl);
  const client = new Redis(redisUrl, {
    lazyConnect: false,
    enableOfflineQueue: true,
    maxRetriesPerRequest: 1,
    connectTimeout: 3_000,
    commandTimeout: 2_500,
    retryStrategy: activeRedisRetryStrategy,
  });
  client.on('error', (err) => {
    logger.debug(`Redis ${label} (${safeUrl}) connection notice: ${err.message}`);
  });
  return client;
}

/**
 * Thuật toán: Khởi tạo kết nối Redis Subscriber chuyên biệt lắng nghe vô hiệu hóa đệm L1 và sự kiện Realtime SSE.
 */
export function createRedisSubscriberClient(
  redisUrl: string,
  logger: Logger,
  onMessage: (channel: string, message: string) => void,
): Redis {
  const safeUrl = redactRedisEndpointUrl(redisUrl);
  const subscriber = new Redis(redisUrl, {
    lazyConnect: false,
    enableOfflineQueue: true,
    maxRetriesPerRequest: null,
    connectTimeout: 3_000,
    retryStrategy: (times) => Math.min(times * 500, 5_000),
  });
  subscriber.on('error', (err) => {
    logger.debug(`Redis pub/sub subscriber (${safeUrl}) notice: ${err.message}`);
  });
  subscriber.on('message', onMessage);
  void subscriber.subscribe(CACHE_INVALIDATION_CHANNEL, REALTIME_EVENTS_CHANNEL).catch((err) => {
    logger.debug(
      `Redis pub/sub initial subscribe notice: ${err instanceof Error ? err.message : String(err)}`,
    );
  });
  return subscriber;
}

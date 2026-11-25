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
 * Thuật toán: Khởi tạo cặp kết nối Redis chủ động (Command Client + Pub/Sub Subscriber) có tự nối lại và không chặn khởi động.
 */
export function createActiveRedisClient(redisUrl: string, logger: Logger, label: string): Redis {
  const safeUrl = redactRedisEndpointUrl(redisUrl);
  const client = new Redis(redisUrl, {
    lazyConnect: false,
    enableOfflineQueue: true,
    maxRetriesPerRequest: 1,
    connectTimeout: 3_000,
    commandTimeout: 2_500,
    retryStrategy: (times) => (times > 5 ? null : Math.min(times * 250, 1_500)),
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

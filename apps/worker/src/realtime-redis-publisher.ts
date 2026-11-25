/**
 * @module WorkerRealtimeRedisPublisher
 * Thuật toán: Cầu nối phát sự kiện Redis Pub/Sub RESP tối giản không phụ thuộc thư viện ngoài cho tiến trình `@sda/worker`.
 *   - Đóng gói lệnh `AUTH` (nếu có mật khẩu/username) và `PUBLISH sda:realtime:events <json>` theo chuẩn RESP2 trên TCP/TLS (`redis://` | `rediss://`).
 *   - Hoàn toàn không chặn chu kỳ worker (`timeout 1500ms`, nuốt lỗi mạng an toàn, bỏ qua trong môi trường kiểm thử `NODE_ENV=test` / `NODE_TEST_CONTEXT`).
 */
import { randomUUID } from 'node:crypto';
import net from 'node:net';
import tls from 'node:tls';

export const WORKER_REALTIME_CHANNEL = 'sda:realtime:events';

export type WorkerRealtimeEventType =
  'NOTIFICATION_CREATED' | 'EXPORT_JOB_UPDATED' | 'SECURITY_ALERT_UPDATED';

export interface WorkerRealtimePublishInput {
  type: WorkerRealtimeEventType;
  targetUserIds?: readonly string[] | undefined;
  targetRoles?: readonly string[] | undefined;
  payload: Record<string, unknown>;
}

/** Thuật toán: Mã hóa mảng tham số lệnh Redis sang khung giao thức RESP2 (`*N\r\n$len\r\narg\r\n`). */
function encodeRespCommand(args: readonly string[]): string {
  let out = `*${args.length}\r\n`;
  for (const arg of args) {
    out += `$${Buffer.byteLength(arg, 'utf8')}\r\n${arg}\r\n`;
  }
  return out;
}

/**
 * Thuật toán: Phát 1 thông điệp sự kiện thời gian thực từ `@sda/worker` sang kênh `sda:realtime:events` trên Redis
 * để `@sda/api` đẩy tức thì xuống trình duyệt qua SSE.
 */
export async function publishWorkerRealtimeEvent(input: WorkerRealtimePublishInput): Promise<void> {
  const isTest = process.env['NODE_ENV'] === 'test' || Boolean(process.env['NODE_TEST_CONTEXT']);
  const redisUrl = process.env['REDIS_URL']?.trim();
  if (isTest || !redisUrl) return;

  let parsed: URL;
  try {
    parsed = new URL(redisUrl);
  } catch {
    return;
  }

  const host = parsed.hostname;
  const port = Number(parsed.port || 6379);
  const useTls = parsed.protocol === 'rediss:';
  const username = parsed.username ? decodeURIComponent(parsed.username) : '';
  const password = parsed.password ? decodeURIComponent(parsed.password) : '';

  const envelope = {
    id: randomUUID(),
    type: input.type,
    occurredAt: new Date().toISOString(),
    ...(input.targetUserIds && input.targetUserIds.length > 0
      ? { targetUserIds: [...new Set(input.targetUserIds)] }
      : {}),
    ...(input.targetRoles && input.targetRoles.length > 0
      ? { targetRoles: [...new Set(input.targetRoles)] }
      : {}),
    payload: input.payload,
  };

  let wireData = '';
  if (password) {
    wireData += username
      ? encodeRespCommand(['AUTH', username, password])
      : encodeRespCommand(['AUTH', password]);
  }
  wireData += encodeRespCommand(['PUBLISH', WORKER_REALTIME_CHANNEL, JSON.stringify(envelope)]);
  wireData += encodeRespCommand(['QUIT']);

  await new Promise<void>((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolve();
    };

    const socket = useTls
      ? tls.connect({ host, port, servername: host })
      : net.connect({ host, port });

    socket.setTimeout(1_500);
    socket.unref();

    const connectEvent = useTls ? 'secureConnect' : 'connect';
    socket.once(connectEvent, () => {
      socket.write(wireData, 'utf8', () => {
        setTimeout(() => {
          socket.destroy();
          finish();
        }, 120).unref();
      });
    });
    socket.once('end', () => {
      socket.destroy();
      finish();
    });
    socket.once('timeout', () => {
      socket.destroy();
      finish();
    });
    socket.once('error', () => {
      socket.destroy();
      finish();
    });
  });
}

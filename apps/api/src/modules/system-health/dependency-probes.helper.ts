/**
 * Module: DependencyProbesHelper — Các phép đo độ trễ kết nối hạ tầng (PostgreSQL, Redis, S3/MinIO) qua TCP Socket và HTTP Health Endpoint có giới hạn thời gian.
 */
import * as net from 'node:net';
import type { DependencyHealth } from '@sda/contracts';
import type { AppConfigService } from '../../config/config.service.js';
import { tracer } from '../../common/telemetry/tracer.js';

/**
 * Thuật toán: Thăm dò kết nối TCP Socket thô có hẹn giờ & giải phóng tài nguyên tức thì (Bounded-Timeout Raw TCP Reachability Ping)
 * Mục đích: Đo khả năng thiết lập bắt tay TCP 3 bước tới dịch vụ đích trong giới hạn `timeoutMs` mà không gây rò rỉ File Descriptor.
 * Cơ chế hoạt động:
 *   - Mở `net.Socket` với `socket.setTimeout(timeoutMs)`, lắng nghe một lần (`once`) trên 3 sự kiện `connect`, `timeout`, `error` và luôn gọi `socket.destroy()` ngay khi kết thúc.
 *
 * Algorithm: Bounded-Timeout Raw TCP Socket Reachability Ping.
 * Opens a non-TLS TCP socket with an explicit timeout and immediately destroys
 * the socket on connect, timeout, or error to prevent file-descriptor leaks.
 */
export function tcpPing(host: string, port: number, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let hasTimedOut = false;

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      socket.destroy();
      resolve();
    });

    socket.once('timeout', () => {
      hasTimedOut = true;
      socket.destroy();
      reject(new Error('Connection timed out'));
    });

    socket.once('error', (err) => {
      if (!hasTimedOut) {
        socket.destroy();
        reject(err);
      }
    });

    socket.connect(port, host);
  });
}

/**
 * Thuật toán: Thăm dò độ trễ PostgreSQL bảo mật thông tin xác thực (Credential-Safe PostgreSQL Probe)
 * Mục đích: Kiểm tra kết nối tới máy chủ CSDL và đo độ trễ mili-giây mà không bao giờ đưa chuỗi DSN nhạy cảm vào thông báo lỗi.
 * Cơ chế hoạt động:
 *   - Tách `hostname` và `port` (mặc định `5432`) từ `DATABASE_URL` thông qua bộ phân tích `URL`, đo thời gian thực thi `tcpPing` bên trong span truy vết `db.probe`.
 *
 * Algorithm: Credential-Safe PostgreSQL Endpoint Probe.
 * Parses host/port from DATABASE_URL and measures TCP handshake latency without leaking DSN secrets.
 */
export async function probeDatabaseEndpoint(
  configService: AppConfigService,
  timeoutMs: number,
): Promise<DependencyHealth> {
  return tracer.withSpan('db.probe', { 'db.system': 'postgresql' }, async () => {
    const start = Date.now();
    try {
      const url = new URL(configService.get('DATABASE_URL'));
      const port = Number(url.port || 5432);
      await tcpPing(url.hostname, port, timeoutMs);
      return { status: 'up', latencyMs: Math.max(1, Date.now() - start) };
    } catch {
      return {
        status: 'down',
        latencyMs: Date.now() - start,
        message: 'Database service is unreachable or timed out',
      };
    }
  });
}

/**
 * Thuật toán: Thăm dò độ trễ Redis bảo mật thông tin xác thực (Credential-Safe Redis Probe)
 * Mục đích: Xác minh máy chủ Redis phản hồi bắt tay TCP trong giới hạn `timeoutMs` phục vụ khóa phân tán Redlock và bộ nhớ đệm.
 * Cơ chế hoạt động:
 *   - Phân tích `hostname` và `port` (mặc định `6379`) từ `REDIS_URL`, gọi `tcpPing` trong span `redis.probe` và chuẩn hóa thông báo lỗi an toàn khi mất kết nối.
 *
 * Algorithm: Credential-Safe Redis Endpoint Probe.
 * Parses host/port from REDIS_URL and measures TCP handshake latency without leaking Redis credentials.
 */
export async function probeRedisEndpoint(
  configService: AppConfigService,
  timeoutMs: number,
): Promise<DependencyHealth> {
  return tracer.withSpan('redis.probe', { 'db.system': 'redis' }, async () => {
    const start = Date.now();
    try {
      const url = new URL(configService.get('REDIS_URL'));
      const port = Number(url.port || 6379);
      await tcpPing(url.hostname, port, timeoutMs);
      return { status: 'up', latencyMs: Math.max(1, Date.now() - start) };
    } catch {
      return {
        status: 'down',
        latencyMs: Date.now() - start,
        message: 'Redis service is unreachable or timed out',
      };
    }
  });
}

/**
 * Thuật toán: Thăm dò thích ứng kho lưu trữ đối tượng đa môi trường (Adaptive Multi-Backend Object Storage Probe)
 * Mục đích: Kiểm tra tính sẵn sàng của kho lưu trữ tệp mã hóa trên cả chế độ giả lập, đám mây S3 (Supabase/Cloudflare R2) và MinIO tự vận hành.
 * Cơ chế hoạt động:
 *   - Nhánh 1 (`STORAGE_MOCK === 'true'`): trả về tức thì `{ status: 'up', latencyMs: 1 }`.
 *   - Nhánh 2 (Cloud S3 / URL đầy đủ): chuẩn hóa giao thức/cổng (`443` cho HTTPS, `80` cho HTTP) và thực hiện `tcpPing`.
 *   - Nhánh 3 (MinIO nội bộ): gọi HTTP GET `/minio/health/ready` kèm `AbortSignal.timeout(timeoutMs)` và hủy dòng body ngay lập tức (`response.body?.cancel()`) để giải phóng kết nối socket.
 *
 * Algorithm: Adaptive Object Storage Readiness Probe.
 * Supports mock mode, cloud S3 endpoints (Supabase/R2/HTTP URLs via TCP ping),
 * and self-hosted MinIO `/minio/health/ready` HTTP health checks with `AbortSignal.timeout`.
 */
export async function probeStorageEndpoint(
  configService: AppConfigService,
  timeoutMs: number,
): Promise<DependencyHealth> {
  return tracer.withSpan('storage.probe', { 'rpc.system': 's3' }, async () => {
    const start = Date.now();
    try {
      if (process.env['STORAGE_MOCK'] === 'true') {
        return { status: 'up', latencyMs: 1 };
      }
      const rawEndpoint = configService.get('STORAGE_ENDPOINT').trim();
      if (
        rawEndpoint.includes('.supabase.co') ||
        rawEndpoint.includes('.r2.cloudflarestorage.com') ||
        rawEndpoint.startsWith('http://') ||
        rawEndpoint.startsWith('https://')
      ) {
        const parsed = new URL(
          rawEndpoint.startsWith('http') ? rawEndpoint : `https://${rawEndpoint}`,
        );
        const targetPort = parsed.port
          ? Number(parsed.port)
          : parsed.protocol === 'https:'
            ? 443
            : 80;
        await tcpPing(parsed.hostname, targetPort, timeoutMs);
        return { status: 'up', latencyMs: Math.max(1, Date.now() - start) };
      }
      const port = configService.get('STORAGE_PORT');
      const protocol = configService.get('STORAGE_USE_SSL') ? 'https' : 'http';
      const response = await fetch(`${protocol}://${rawEndpoint}:${port}/minio/health/ready`, {
        signal: AbortSignal.timeout(timeoutMs),
      });
      await response.body?.cancel();
      if (!response.ok) throw new Error('Storage readiness endpoint is not healthy');
      return { status: 'up', latencyMs: Math.max(1, Date.now() - start) };
    } catch {
      return {
        status: 'down',
        latencyMs: Date.now() - start,
        message: 'Object storage service is unreachable or timed out',
      };
    }
  });
}

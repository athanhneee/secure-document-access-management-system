import { createHash, timingSafeEqual } from 'node:crypto';
import http from 'node:http';
import type * as net from 'node:net';
import { getDatabaseClient } from '@sda/database';
import {
  getLastWorkerLoopHeartbeatMs,
  getWorkerUptimeSeconds,
  recordWorkerLoopHeartbeat,
  renderWorkerPrometheusMetrics,
  setWorkerUp,
} from './worker-metrics.js';

/**
 * Thuật toán / Tổng quan module:
 * Máy chủ HTTP nội bộ phục vụ kiểm tra sức khỏe thực tế (`GET /health`) và thu thập chỉ số Prometheus (`GET /metrics`)
 * cho tiến trình `@sda/worker`, tích hợp bộ nhớ đệm nhịp tim PostgreSQL có hạn giờ và xác thực Bearer Token hằng thời gian.
 */

export interface WorkerIcapHealthSnapshot {
  enabled: boolean;
  listening: boolean;
  action: 'BLOCK' | 'AUDIT_ONLY';
  customKeywordsCount: number;
  metrics?: unknown;
}

export interface WorkerHealthServerOptions {
  enabled?: boolean | undefined;
  host?: string | undefined;
  port?: number | undefined;
  metricsScrapeToken?: string | undefined;
  maxLoopStaleMs?: number | undefined;
  dbHeartbeatTtlMs?: number | undefined;
  checkDatabase?: (() => Promise<boolean>) | undefined;
  getIcapStatus?: (() => WorkerIcapHealthSnapshot | null) | undefined;
}

export interface WorkerHealthServerHandle {
  readonly server: http.Server | null;
  readonly ready: Promise<{ host: string; port: number; enabled: boolean }>;
  stop: () => Promise<void>;
}

/**
 * Thuật toán: Đối chiếu Bearer Token trong thời gian hằng số qua băm SHA-256 cố định 32 byte
 * nhằm chống rò rỉ độ dài lẫn giá trị `METRICS_SCRAPE_TOKEN` qua kênh kề thời gian.
 */
function verifyBearerToken(authHeader: string | undefined, expectedToken: string): boolean {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
  const provided = authHeader.slice('Bearer '.length).trim();
  if (provided.length === 0) return false;
  const expectedDigest = createHash('sha256').update(expectedToken, 'utf8').digest();
  const providedDigest = createHash('sha256').update(provided, 'utf8').digest();
  return timingSafeEqual(expectedDigest, providedDigest);
}

/**
 * Thuật toán: Thăm dò nhịp tim CSDL có giới hạn thời gian `3000ms` và bộ nhớ đệm ngắn hạn (`dbHeartbeatTtlMs`)
 * để container healthcheck không gây bão kết nối lên PostgreSQL.
 */
function createCachedDbProbe(
  ttlMs: number,
  customCheck?: () => Promise<boolean>,
): () => Promise<boolean> {
  let lastSuccessAtMs = 0;
  return async (): Promise<boolean> => {
    const now = Date.now();
    if (lastSuccessAtMs > 0 && now - lastSuccessAtMs < ttlMs) {
      return true;
    }
    try {
      if (customCheck) {
        const ok = await customCheck();
        if (ok) lastSuccessAtMs = Date.now();
        return ok;
      }
      if (!process.env['DATABASE_URL']?.trim()) {
        return false;
      }
      const db = getDatabaseClient();
      await Promise.race([
        db.$queryRawUnsafe('SELECT 1'),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('DB health probe timed out')), 3_000),
        ),
      ]);
      lastSuccessAtMs = Date.now();
      return true;
    } catch {
      return false;
    }
  };
}

/**
 * Thuật toán: Khởi chạy máy chủ HTTP nội bộ cho `/health` và `/metrics`, tự động tắt khi `WORKER_HEALTH_PORT === '0'`
 * và đóng kết nối sạch khi nhận tín hiệu dừng `AbortSignal`.
 */
export function startWorkerHealthServer(
  options?: WorkerHealthServerOptions,
  signal?: AbortSignal,
): WorkerHealthServerHandle {
  const rawPortEnv = process.env['WORKER_HEALTH_PORT']?.trim();
  const disabledByEnv = options?.port === undefined && rawPortEnv === '0';
  const enabled = options?.enabled ?? !disabledByEnv;
  const host = options?.host ?? (process.env['WORKER_HEALTH_HOST']?.trim() || '0.0.0.0');
  const parsedEnvPort = Number.parseInt(rawPortEnv ?? '9102', 10);
  const port =
    options?.port ??
    (Number.isInteger(parsedEnvPort) && parsedEnvPort >= 0 && parsedEnvPort <= 65535
      ? parsedEnvPort
      : 9102);

  if (!enabled || signal?.aborted) {
    return {
      server: null,
      ready: Promise.resolve({ host, port: 0, enabled: false }),
      stop: async () => undefined,
    };
  }

  const maxLoopStaleMs = options?.maxLoopStaleMs ?? 120_000;
  const dbHeartbeatTtlMs = options?.dbHeartbeatTtlMs ?? 10_000;
  const probeDb = createCachedDbProbe(dbHeartbeatTtlMs, options?.checkDatabase);

  setWorkerUp(true);
  recordWorkerLoopHeartbeat();
  const heartbeatTimer = setInterval(() => {
    recordWorkerLoopHeartbeat();
  }, 10_000);
  heartbeatTimer.unref();

  const server = http.createServer(async (req, res) => {
    const method = req.method ?? 'GET';
    const pathname = new URL(req.url ?? '/', 'http://127.0.0.1').pathname;

    if (method !== 'GET' && method !== 'HEAD') {
      res.writeHead(405, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: 'Method Not Allowed' }));
      return;
    }

    if (pathname === '/health' || pathname === '/healthz') {
      const loopAgeMs = Date.now() - getLastWorkerLoopHeartbeatMs();
      const workerLoopAlive = loopAgeMs <= maxLoopStaleMs;
      const dbHealthy = await probeDb();
      const healthy = workerLoopAlive && dbHealthy;
      const icapStatus = options?.getIcapStatus?.() ?? null;
      const payload = JSON.stringify({
        status: healthy ? 'ok' : 'degraded',
        service: 'sda-worker',
        workerLoopAlive,
        dbHealthy,
        loopHeartbeatAgeMs: loopAgeMs,
        uptimeSeconds: getWorkerUptimeSeconds(),
        ...(icapStatus ? { icap: icapStatus } : {}),
        timestamp: new Date().toISOString(),
      });
      res.writeHead(healthy ? 200 : 503, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
      });
      res.end(method === 'HEAD' ? undefined : payload);
      return;
    }

    if (pathname === '/metrics') {
      const expectedToken =
        options?.metricsScrapeToken ?? process.env['METRICS_SCRAPE_TOKEN']?.trim() ?? '';
      if (expectedToken.length > 0) {
        const authHeader =
          typeof req.headers.authorization === 'string' ? req.headers.authorization : undefined;
        if (!verifyBearerToken(authHeader, expectedToken)) {
          res.writeHead(401, {
            'Content-Type': 'application/json; charset=utf-8',
            'WWW-Authenticate': 'Bearer realm="sda-worker-metrics"',
          });
          res.end(JSON.stringify({ error: 'Unauthorized metrics scrape request' }));
          return;
        }
      }
      const body = renderWorkerPrometheusMetrics();
      res.writeHead(200, {
        'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
        'Cache-Control': 'no-store',
      });
      res.end(method === 'HEAD' ? undefined : body);
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'Not Found' }));
  });

  let stopped = false;
  const stop = async (): Promise<void> => {
    if (stopped) return;
    stopped = true;
    clearInterval(heartbeatTimer);
    setWorkerUp(false);
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  };

  const ready = new Promise<{ host: string; port: number; enabled: boolean }>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const addr = server.address() as net.AddressInfo | null;
      const boundPort = addr?.port ?? port;
      console.info(`[Worker Health] Listening on http://${host}:${boundPort} (/health, /metrics)`);
      resolve({ host, port: boundPort, enabled: true });
    });
  });

  if (signal) {
    signal.addEventListener('abort', () => void stop(), { once: true });
  }

  return { server, ready, stop };
}

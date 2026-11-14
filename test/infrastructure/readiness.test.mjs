/**
 * @module InfrastructureReadinessTest
 * Thuật toán: Kiểm chứng điểm cuối sẵn sàng `/api/v1/health/ready` trên cả hai chế độ hạ tầng:
 *   1. Xác minh máy chủ `@sda/api` kết nối thành công tới PostgreSQL, Redis và S3/R2 (`200 ready`).
 *   2. Khi có container `redis` cục bộ: dừng/khởi động lại container để đo chu kỳ `503 degraded` -> `200 ready`.
 *      Khi chạy trên Cloud (Railway PostgreSQL + Redis + Cloudflare R2): khởi chạy tiến trình thăm dò cô lập với `REDIS_URL` mất kết nối
 *      để xác minh phản hồi `503 degraded` (`checks.redis.status === 'down'`) và khử sạch chuỗi bí mật trong payload.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { after, before, test } from 'node:test';
import {
  dockerCompose,
  isLocalComposeServiceRunning,
  repositoryRoot,
  waitFor,
} from './helpers.mjs';

const port = 3199;
const degradedProbePort = 3198;
const readinessUrl = `http://127.0.0.1:${port}/api/v1/health/ready`;
const useLocalRedisContainer = isLocalComposeServiceRunning('redis');
let api;

async function fetchReadiness(url = readinessUrl) {
  const response = await fetch(url, { signal: AbortSignal.timeout(8_000) });
  const body = await response.json();
  return { response, body };
}

before(async () => {
  api = spawn(process.execPath, ['apps/api/dist/main.js'], {
    cwd: repositoryRoot,
    env: {
      ...process.env,
      HOST: '127.0.0.1',
      API_HOST: '127.0.0.1',
      PORT: String(port),
      API_PORT: String(port),
      NODE_ENV: 'development',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await waitFor(async () => {
    const result = await fetchReadiness();
    return result.response.status === 200 && result.body.status === 'ready';
  }, 45_000);
});

after(() => {
  if (useLocalRedisContainer) {
    dockerCompose(['start', 'redis'], { capture: false });
  }
  api?.kill();
});

test('API readiness reports ready against live dependencies and degraded with redacted output when Redis is unreachable', async () => {
  if (useLocalRedisContainer) {
    dockerCompose(['stop', '--timeout', '10', 'redis'], { capture: false });
    const degraded = await waitFor(async () => {
      const result = await fetchReadiness();
      return result.response.status === 503 ? result : undefined;
    });
    assert.equal(degraded.body.status, 'degraded');
    assert.equal(degraded.body.checks.redis.status, 'down');
    assert.doesNotMatch(JSON.stringify(degraded.body), /password|secret|credential|redis:\/\//i);

    dockerCompose(['start', 'redis'], { capture: false });
    const recovered = await waitFor(async () => {
      const result = await fetchReadiness();
      return result.response.status === 200 ? result : undefined;
    });
    assert.equal(recovered.body.status, 'ready');
    return;
  }

  const healthy = await fetchReadiness();
  assert.equal(healthy.response.status, 200);
  assert.equal(healthy.body.status, 'ready');
  assert.doesNotMatch(
    JSON.stringify(healthy.body),
    /password|secret|credential|postgresql:\/\/|rediss?:\/\//i,
  );

  const degradedApi = spawn(process.execPath, ['apps/api/dist/main.js'], {
    cwd: repositoryRoot,
    env: {
      ...process.env,
      HOST: '127.0.0.1',
      API_HOST: '127.0.0.1',
      PORT: String(degradedProbePort),
      API_PORT: String(degradedProbePort),
      REDIS_URL: 'redis://127.0.0.1:1/0',
      NODE_ENV: 'development',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  try {
    const degradedUrl = `http://127.0.0.1:${degradedProbePort}/api/v1/health/ready`;
    const degraded = await waitFor(async () => {
      const result = await fetchReadiness(degradedUrl);
      return result.response.status === 503 ? result : undefined;
    }, 30_000);
    assert.equal(degraded.body.status, 'degraded');
    assert.equal(degraded.body.checks.redis.status, 'down');
    assert.doesNotMatch(
      JSON.stringify(degraded.body),
      /password|secret|credential|postgresql:\/\/|rediss?:\/\//i,
    );
  } finally {
    degradedApi.kill();
  }
});

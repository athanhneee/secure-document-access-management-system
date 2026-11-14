import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const localDevEnv = path.join(repositoryRoot, '.local', 'dev.env');
const rootEnv = path.join(repositoryRoot, '.env');
const resolvedEnvFile = fs.existsSync(localDevEnv) ? localDevEnv : rootEnv;

export const composeBase = [
  'compose',
  ...(fs.existsSync(resolvedEnvFile) ? ['--env-file', resolvedEnvFile] : []),
  '--file',
  path.join(repositoryRoot, 'infra', 'compose.yaml'),
  '--project-name',
  'secure-document-access-system-local',
];

/**
 * Thuật toán: Kiểm Tra Trạng Thái Sẵn Sàng Của Dịch Vụ Docker Compose Cục Bộ (`isLocalComposeServiceRunning`)
 * Trả về `true` chỉ khi Docker daemon đang bật và container dịch vụ mục tiêu đang ở trạng thái `running`;
 * trả `false` an toàn trên môi trường Cloud (Railway + Cloudflare R2) hoặc máy Windows không bật Docker.
 */
export function isLocalComposeServiceRunning(serviceName) {
  try {
    const probe = spawnSync(
      'docker',
      [...composeBase, 'ps', '--status', 'running', '-q', serviceName],
      {
        cwd: repositoryRoot,
        encoding: 'utf8',
        stdio: 'pipe',
        env: process.env,
        timeout: 4_000,
        shell: false,
      },
    );
    if (probe.error || probe.status !== 0) return false;
    return typeof probe.stdout === 'string' && probe.stdout.trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * Thuật toán: Thực thi Lệnh Docker Compose Không Qua Shell (Shell-Free Subprocess Execution)
 */
export function dockerCompose(args, options = {}) {
  const result = spawnSync('docker', [...composeBase, ...args], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    stdio: options.capture === false ? 'inherit' : 'pipe',
    env: process.env,
    shell: false,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const details = [result.stderr, result.stdout]
      .filter((stream) => typeof stream === 'string' && stream.trim().length > 0)
      .map((stream) => stream.trim())
      .join('\n');
    throw new Error(
      `Docker Compose failed (${args.join(' ')}): ${details || `exit code ${result.status}`}`,
    );
  }
  return result.stdout;
}

/**
 * Thuật toán: Thăm dò Sẵn sàng Có Giới hạn Thời gian (Bounded-Deadline Readiness Polling)
 */
export async function waitFor(predicate, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const result = await predicate();
      if (result) return result;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Condition was not met within ${timeoutMs}ms.`, { cause: lastError });
}

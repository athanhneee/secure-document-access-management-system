import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
export const composeBase = [
  'compose',
  '--env-file',
  path.join(repositoryRoot, '.local', 'dev.env'),
  '--file',
  path.join(repositoryRoot, 'infra', 'compose.yaml'),
  '--project-name',
  'secure-document-access-system-local',
];

/**
 * Thuật toán: Thực thi Lệnh Docker Compose Không Qua Shell (Shell-Free Subprocess Execution)
 * Mục đích: Gọi trực tiếp nhị phân `docker compose` kèm cấu hình môi trường cục bộ và bắt lỗi thoát khác 0.
 * Cơ chế hoạt động:
 *   - Chạy `spawnSync('docker', [...composeBase, ...args], { shell: false })` nhằm ngăn chặn lỗi Command Injection qua ký tự meta-shell.
 *   - Hợp nhất luồng `stderr` và `stdout` để ném ngoại lệ giàu ngữ cảnh khi mã thoát `status !== 0`.
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
 * Mục đích: Lặp kiểm tra điều kiện bất đồng bộ `predicate()` cho tới khi thỏa mãn hoặc chạm ngưỡng `timeoutMs`.
 * Cơ chế hoạt động:
 *   - Tính mốc hạn chót `deadline = Date.now() + timeoutMs` và lặp kiểm tra mỗi chu kỳ nghỉ cố định `250ms`.
 *   - Lưu giữ ngoại lệ gần nhất (`lastError`) và gắn vào trường `Error.cause` nếu hết hạn để phục vụ chẩn đoán lỗi hạ tầng.
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

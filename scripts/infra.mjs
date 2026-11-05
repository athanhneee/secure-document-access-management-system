/**
 * Thuật toán: Điều Phối Vòng Đời Hạ Tầng Container & Chẩn Đoán Sức Khỏe Tiền Triển Khai (Docker Compose Orchestrator & Readiness Doctor)
 * Mục đích: Quản lý thống nhất việc khởi chạy, kiểm tra sẵn sàng (`--wait`), xem log an toàn, chẩn đoán môi trường (`doctor`) và xóa sạch dữ liệu có rào chắn xác nhận (`reset-safe`).
 * Cơ chế hoạt động:
 *   - Thực thi mọi tiến trình con với `shell: false` chống tiêm lệnh (Command Injection), tự động cấp phát `.local/dev.env` nếu thiếu và tối ưu danh sách dịch vụ khởi chạy khi chạy trên môi trường CI.
 */
import { spawnSync } from 'node:child_process';
import { access } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { createInterface } from 'node:readline/promises';
import { fileURLToPath } from 'node:url';
import { defaultOutput, generateDevelopmentSecrets } from './generate-dev-secrets.mjs';

const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));
const composeFile = path.join(repositoryRoot, 'infra', 'compose.yaml');
const projectName = 'secure-document-access-system-local';
const resetTarget = 'secure-document-access-system-local-data';
const composeBase = [
  'compose',
  '--env-file',
  defaultOutput,
  '--file',
  composeFile,
  '--project-name',
  projectName,
];

/**
 * Thuật toán: Thực Thi Tiến Trình Con Không Qua Shell (Shell-Free Synchronous Subprocess Runner)
 * Mục đích: Chạy lệnh hệ thống (`docker`, `node`, `git`) an toàn tuyệt đối trước lỗ hổng tiêm ký tự đặc biệt của shell.
 * Cơ chế hoạt động:
 *   - Gọi `spawnSync` với mảng đối số tách rời và `shell: false`, kiểm tra cả lỗi khởi tạo tiến trình lẫn mã thoát khác 0 trừ khi được bật cờ `allowFailure`.
 */
function run(command, args, { capture = false, allowFailure = false } = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    stdio: capture ? 'pipe' : 'inherit',
    shell: false,
  });
  if (result.error) {
    if (allowFailure) return result;
    throw result.error;
  }
  if (result.status !== 0 && !allowFailure) {
    throw new Error(`${command} exited with status ${result.status ?? 'unknown'}.`);
  }
  return result;
}

async function ensureEnvironment() {
  try {
    await access(defaultOutput);
  } catch {
    await generateDevelopmentSecrets();
    console.log('Generated .local/dev.env with cryptographically secure local-only values.');
  }
}

/**
 * Thuật toán: Rào Chắn Xác Nhận Kép Trước Khi Hủy Volume Dữ Liệu (Two-Mode Destructive Reset Guard)
 * Mục đích: Ngăn chặn thao tác xóa nhầm dữ liệu Docker volumes trong môi trường không tương tác hoặc gõ nhầm lệnh.
 * Cơ chế hoạt động:
 *   - Trong tự động hóa (`NODE_ENV` thuộc `local|test`), bắt buộc biến `INFRA_RESET_TARGET` khớp chính xác chuỗi khóa mục tiêu; trong chế độ dòng lệnh TTY, yêu cầu người vận hành nhập lại chính xác chuỗi định danh dự án.
 */
async function confirmReset() {
  const nonInteractiveAllowed =
    (['local', 'test'].includes(process.env['NODE_ENV'] ?? '') || process.env['CI'] === 'true') &&
    process.env['INFRA_RESET_TARGET'] === resetTarget;
  if (nonInteractiveAllowed) return true;
  if (!process.stdin.isTTY || !process.stdout.isTTY) return false;

  const terminal = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await terminal.question(
      `This permanently removes only Docker volumes for ${projectName}.\nType ${resetTarget} to continue: `,
    );
    return answer === resetTarget;
  } finally {
    terminal.close();
  }
}

/**
 * Thuật toán: Thăm Dò Chẩn Đoán Sẵn Sàng Hạ Tầng Đa Điểm (Multi-Probe Infrastructure Readiness Doctor)
 * Mục đích: Kiểm tra toàn diện chuỗi công cụ (`Node.js`, `Docker CLI`, `Docker Compose`, `Docker daemon`), trạng thái ẩn tệp bí mật trên Git và tính hợp lệ cú pháp `compose.yaml`.
 * Cơ chế hoạt động:
 *   - Chạy tuần tự các phép thử không phá hủy, đối chiếu `git check-ignore` cho `.local/dev.env` và chạy `docker compose config --quiet` trước khi tổng hợp danh sách lỗi.
 */
async function doctor() {
  const failures = [];
  const checks = [
    ['Node.js', 'node', ['--version']],
    ['Docker CLI', 'docker', ['--version']],
    ['Docker Compose', 'docker', ['compose', 'version']],
    ['Docker daemon', 'docker', ['info', '--format', '{{.ServerVersion}}']],
  ];
  for (const [label, command, args] of checks) {
    const result = run(command, args, { capture: true, allowFailure: true });
    if (result.status === 0) console.log(`[ok] ${label}: ${result.stdout.trim()}`);
    else {
      failures.push(label);
      console.error(`[failed] ${label}`);
    }
  }

  try {
    await access(defaultOutput);
    console.log('[ok] Local secrets file exists and is ignored by Git.');
    const ignored = run('git', ['check-ignore', '--quiet', '.local/dev.env'], {
      allowFailure: true,
    });
    if (ignored.status !== 0) failures.push('Git ignore for local secrets');
  } catch {
    failures.push('Local secrets file');
    console.error('[failed] .local/dev.env is missing; run pnpm generate-dev-secrets.');
  }

  if (failures.length === 0) {
    const config = run('docker', [...composeBase, 'config', '--quiet'], { allowFailure: true });
    if (config.status !== 0) failures.push('Compose configuration');
    else console.log('[ok] Compose configuration is valid.');
  }

  if (failures.length > 0) {
    throw new Error(`Infrastructure doctor found ${failures.length} failed check(s).`);
  }
}

async function main() {
  const [action = 'doctor', ...rest] = process.argv.slice(2);
  if (action !== 'doctor') await ensureEnvironment();

  switch (action) {
    case 'up': {
      run('docker', [...composeBase, 'config', '--quiet']);
      const isCi = process.env['CI'] === 'true';
      // In CI environments, start core long-running daemon services and skip heavy ClamAV daemon
      // (which has in-memory mock socket fallback in tests) and monitoring stack.
      const targetServices = isCi ? ['postgres', 'redis', 'minio', 'gotenberg', 'mailpit'] : [];
      run('docker', [
        ...composeBase,
        'up',
        '--detach',
        '--wait',
        '--wait-timeout',
        '360',
        ...targetServices,
      ]);
      if (isCi) {
        run('docker', [...composeBase, 'run', '--rm', '--no-deps', 'minio-bootstrap']);
      }
      run('docker', [...composeBase, 'ps']);
      break;
    }
    case 'down':
      run('docker', [...composeBase, 'down', '--remove-orphans']);
      console.log('Containers stopped; named volumes and local data were preserved.');
      break;
    case 'logs': {
      if (rest.some((name) => !/^[a-z0-9][a-z0-9_-]*$/i.test(name))) {
        throw new Error(
          'Service names may contain only letters, digits, underscores, and hyphens.',
        );
      }
      run('docker', [...composeBase, 'logs', '--follow', '--tail', '200', ...rest]);
      break;
    }
    case 'reset-safe':
      if (!(await confirmReset())) {
        throw new Error(
          `Reset cancelled. Interactive confirmation must exactly match ${resetTarget}; ` +
            'automation also requires NODE_ENV=test|local and the exact INFRA_RESET_TARGET.',
        );
      }
      run('docker', [...composeBase, 'down', '--volumes', '--remove-orphans']);
      console.log('Removed only secure-document-access-system-local containers and named volumes.');
      break;
    case 'doctor':
      await doctor();
      break;
    default:
      throw new Error(`Unknown infrastructure action: ${action}`);
  }
}

await main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

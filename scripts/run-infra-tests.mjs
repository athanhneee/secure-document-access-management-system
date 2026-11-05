/**
 * Thuật toán: Phân Tích Biến Môi Trường Cục Bộ & Điều Phối Kiểm Thử Hạ Tầng Tuần Tự (Sequential Infrastructure Test Runner)
 * Mục đích: Nạp cấu hình bí mật từ `.local/dev.env`, biên dịch gói `@sda/api` và chạy tuần tự (`--test-concurrency=1`) các bài kiểm thử tích hợp Object Storage, ClamAV và Readiness.
 * Cơ chế hoạt động:
 *   - Tách dòng văn bản cấu hình, bỏ qua dòng trống và dòng chú thích `#`, cắt tại vị trí dấu `=` đầu tiên để bảo toàn các giá trị chứa ký tự `=` bên trong chuỗi kết nối URI.
 *   - Gọi tiến trình con `turbo` và `node --test` với `shell: false` cùng cờ `RUN_INFRA_TESTS=1`.
 */
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));
const environmentPath = path.join(repositoryRoot, '.local', 'dev.env');

/**
 * Thuật toán: Bộ Phân Tích Từ Vựng Tệp Cấu Hình Khóa-Giá Trị (First-Delimiter Dotenv Lexer)
 * Mục đích: Chuyển đổi nội dung tệp `.local/dev.env` thành bản đồ khóa-giá trị mà không làm hỏng tham số truy vấn hoặc chuỗi đệm chứa dấu `=`.
 * Cơ chế hoạt động:
 *   - Tách dòng theo biểu thức chính quy `/\r?\n/u`, lọc bỏ dòng trống/chú thích, định vị chỉ số dấu `=` đầu tiên (`indexOf('=') >= 1`) và cắt đôi chuỗi thành cặp `[key, value]`.
 */
function parseEnvironment(source) {
  return Object.fromEntries(
    source
      .split(/\r?\n/u)
      .filter((line) => line && !line.startsWith('#'))
      .map((line) => {
        const separator = line.indexOf('=');
        if (separator < 1) throw new Error('Invalid line in local environment file.');
        return [line.slice(0, separator), line.slice(separator + 1)];
      }),
  );
}

let localEnvironment = {};
try {
  localEnvironment = parseEnvironment(await readFile(environmentPath, 'utf8'));
} catch (error) {
  if (process.env['CI'] !== 'true') {
    throw new Error('Missing .local/dev.env. Run pnpm infra:up before infrastructure tests.', {
      cause: error,
    });
  }
}

const build = spawnSync(
  process.execPath,
  [
    path.join(repositoryRoot, 'node_modules', 'turbo', 'bin', 'turbo'),
    'run',
    'build',
    '--filter=@sda/api',
  ],
  {
    cwd: repositoryRoot,
    env: process.env,
    stdio: 'inherit',
    shell: false,
  },
);
if (build.error) throw build.error;
if (build.status !== 0) process.exit(build.status ?? 1);

const result = spawnSync(
  process.execPath,
  [
    '--test',
    '--test-concurrency=1',
    'test/infrastructure/object-storage.test.mjs',
    'test/infrastructure/clamav.test.mjs',
    'test/infrastructure/readiness.test.mjs',
  ],
  {
    cwd: repositoryRoot,
    env: { ...process.env, ...localEnvironment, RUN_INFRA_TESTS: '1' },
    stdio: 'inherit',
    shell: false,
  },
);

if (result.error) throw result.error;
process.exitCode = result.status ?? 1;

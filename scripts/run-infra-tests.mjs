/**
 * Thuật toán: Phân Tích Biến Môi Trường Cục Bộ & Điều Phối Kiểm Thử Hạ Tầng Tuần Tự (Sequential Infrastructure Test Runner)
 * Mục đích: Nạp cấu hình bí mật từ `.local/dev.env` (không ghi đè biến môi trường tiến trình gọi), biên dịch gói `@sda/api`
 *   và chạy tuần tự (`--test-concurrency=1`) các bài kiểm thử tích hợp Object Storage, ClamAV và Readiness.
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
 *   - Tách dòng theo `/\r?\n/u`, loại bỏ dòng chỉ chứa khoảng trắng và dòng chú thích `#` (kể cả thụt lề).
 *   - Tìm dấu `=` đầu tiên, cắt tỉa khoảng trắng quanh tên khóa (`key.trim()`), từ chối khóa rỗng và giữ nguyên phần giá trị sau dấu `=`.
 */
export function parseEnvironment(source) {
  const entries = [];
  for (const rawLine of source.split(/\r?\n/u)) {
    // CONFLICT-RESOLVED: Bỏ qua dòng chỉ chứa khoảng trắng hoặc chú thích có khoảng trắng đầu dòng để không ném lỗi giả ([MED-14]).
    const trimmedLine = rawLine.trim();
    if (!trimmedLine || trimmedLine.startsWith('#')) {
      continue;
    }
    const separator = rawLine.indexOf('=');
    if (separator < 1) {
      throw new Error('Invalid line in local environment file.');
    }
    const key = rawLine.slice(0, separator).trim();
    if (!key) {
      throw new Error('Invalid empty key in local environment file.');
    }
    entries.push([key, rawLine.slice(separator + 1)]);
  }
  return Object.fromEntries(entries);
}

/**
 * Thuật toán: Nạp Cấu Hình Tách Biệt Lỗi Thiếu Tệp (`ENOENT`) Và Lỗi Cú Pháp, Giữ Ưu Tiên `process.env`
 * Mục đích: Chỉ cho phép bỏ qua `.local/dev.env` khi tệp thực sự vắng mặt trên CI (`ENOENT` + `CI === 'true'`),
 *   ném thẳng mọi lỗi cú pháp, và ghép `{ ...localEnvironment, ...process.env }` để biến môi trường từ caller luôn thắng.
 */
async function runInfraTests() {
  let rawEnvContent = null;
  try {
    rawEnvContent = await readFile(environmentPath, 'utf8');
  } catch (error) {
    // CONFLICT-RESOLVED: Tách biệt lỗi thiếu tệp ENOENT với lỗi phân tích cú pháp để không nuốt lỗi cấu hình hỏng trên CI ([MED-14]).
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
      if (process.env['CI'] !== 'true') {
        throw new Error('Missing .local/dev.env. Run pnpm infra:up before infrastructure tests.', {
          cause: error,
        });
      }
    } else {
      throw error;
    }
  }

  const localEnvironment = rawEnvContent !== null ? parseEnvironment(rawEnvContent) : {};

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
      // CONFLICT-RESOLVED: Đặt process.env sau localEnvironment để biến môi trường của caller không bị ghi đè ([MED-14]).
      env: { ...localEnvironment, ...process.env, RUN_INFRA_TESTS: '1' },
      stdio: 'inherit',
      shell: false,
    },
  );

  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await runInfraTests();
}

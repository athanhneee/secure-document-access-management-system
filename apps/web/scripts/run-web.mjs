/**
 * @module RunWebScript
 * Thuật toán: Khởi chạy `@sda/web` (`dev` hoặc `start` standalone) có đồng bộ `WEB_PORT` và `INTERNAL_API_ORIGIN` từ `.env` gốc
 * (ưu tiên biến môi trường tiến trình gọi `process.env` trước `.env`), ngăn chặn va chạm cổng `:3000` khi chạy song song dự án khác.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(scriptDir, '..');
const repoRoot = path.resolve(webDir, '../..');
const mode = process.argv[2] === 'start' ? 'start' : 'dev';

function loadDotenvFallback(filePath) {
  if (!fs.existsSync(filePath)) return {};
  const map = {};
  for (const rawLine of fs.readFileSync(filePath, 'utf8').split(/\r?\n/u)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = rawLine.indexOf('=');
    if (eqIdx < 1) continue;
    const key = rawLine.slice(0, eqIdx).trim();
    let val = rawLine.slice(eqIdx + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (key) map[key] = val;
  }
  return map;
}

const mergedEnv = {
  ...loadDotenvFallback(path.join(repoRoot, '.local', 'dev.env')),
  ...loadDotenvFallback(path.join(repoRoot, '.env')),
  ...process.env,
};

const resolvedPort = String(process.env['PORT'] || mergedEnv['WEB_PORT'] || '3000').trim();
const resolvedHost = String(mergedEnv['HOSTNAME'] || '127.0.0.1').trim();
mergedEnv['PORT'] = resolvedPort;
mergedEnv['HOSTNAME'] = resolvedHost;

const childArgs =
  mode === 'start'
    ? [path.join(webDir, '.next', 'standalone', 'apps', 'web', 'server.js')]
    : [
        path.join(webDir, 'node_modules', 'next', 'dist', 'bin', 'next'),
        'dev',
        '--hostname',
        resolvedHost,
        '--port',
        resolvedPort,
      ];

const child = spawn(process.execPath, childArgs, {
  cwd: webDir,
  env: mergedEnv,
  stdio: 'inherit',
  shell: false,
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => child.kill(sig));
}
child.on('exit', (code) => process.exit(code ?? 0));

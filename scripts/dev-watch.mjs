/**
 * Thuật toán: Điều Phối Kép Biên Dịch Tăng Lượng TypeScript & Tự Khởi Động Lại Tiến Trình Node (`dev-watch`)
 * Mục đích: Đảm bảo khi chạy `pnpm dev` trong `@sda/api` và `@sda/worker`, mọi thay đổi trên tệp `.ts` đều được `tsc --watch` biên dịch tức thì sang `dist/` trước khi `node --watch` nạp lại mô-đun, và tự thu hồi sạch tiến trình con khi nhận tín hiệu dừng (`SIGINT`/`SIGTERM`).
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const cwd = process.cwd();
const entryPoint = process.argv[2] ?? 'dist/main.js';
const entryPath = path.resolve(cwd, entryPoint);

const tscProcess = spawn(
  process.execPath,
  [
    path.resolve(cwd, '../../node_modules/typescript/bin/tsc'),
    '-p',
    'tsconfig.json',
    '--watch',
    '--preserveWatchOutput',
  ],
  { cwd, stdio: 'inherit' },
);

let nodeProcess = null;

function startNodeWatch() {
  if (nodeProcess) return;
  nodeProcess = spawn(
    process.execPath,
    [
      '--env-file-if-exists=../../.local/dev.env',
      '--env-file-if-exists=../../.env',
      '--watch',
      entryPath,
    ],
    {
      cwd,
      stdio: 'inherit',
    },
  );
  nodeProcess.on('exit', (code) => {
    if (code !== null && code !== 0) {
      process.exitCode = code;
    }
  });
}

if (fs.existsSync(entryPath)) {
  startNodeWatch();
} else {
  const poll = setInterval(() => {
    if (fs.existsSync(entryPath)) {
      clearInterval(poll);
      startNodeWatch();
    }
  }, 250);
  poll.unref();
}

function shutdown(signal) {
  tscProcess.kill(signal);
  if (nodeProcess) {
    nodeProcess.kill(signal);
  }
  process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

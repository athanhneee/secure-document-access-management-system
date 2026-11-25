/**
 * Thuật toán: Đồng Bộ Tệp Worker `pdf.worker.min.mjs` Cùng Nguồn Từ `pdfjs-dist` Vào `apps/web/public` (`copy-pdf-worker`)
 * Mục đích: Đảm bảo trình xem PDF Canvas luôn nạp đúng phiên bản worker cùng nguồn (`worker-src 'self'`) trong cả `dev`, `build` và CI mà không phải commit tệp nén vendor vào kho Git.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '..');
const require = createRequire(import.meta.url);

const workerSource = require.resolve('pdfjs-dist/build/pdf.worker.min.mjs');
const publicDir = path.join(webRoot, 'public');
const workerDest = path.join(publicDir, 'pdf.worker.min.mjs');

fs.mkdirSync(publicDir, { recursive: true });
fs.copyFileSync(workerSource, workerDest);

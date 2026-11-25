/**
 * Thuật toán: Đồng bộ tài nguyên tĩnh (`.next/static` và `public`) vào gói thực thi độc lập `.next/standalone/apps/web`
 * ngay sau `next build` để `node .next/standalone/apps/web/server.js` phục vụ đầy đủ CSS/JS trên mọi môi trường.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const webRoot = fileURLToPath(new URL('../', import.meta.url));
const distDir = process.env['NEXT_DIST_DIR']?.trim() || '.next';
const standaloneWebDir = path.join(webRoot, distDir, 'standalone', 'apps', 'web');

if (fs.existsSync(standaloneWebDir)) {
  const staticSrc = path.join(webRoot, distDir, 'static');
  const staticDest = path.join(standaloneWebDir, distDir, 'static');
  if (fs.existsSync(staticSrc)) {
    fs.cpSync(staticSrc, staticDest, { recursive: true, force: true });
  }

  const publicSrc = path.join(webRoot, 'public');
  const publicDest = path.join(standaloneWebDir, 'public');
  if (fs.existsSync(publicSrc)) {
    fs.cpSync(publicSrc, publicDest, { recursive: true, force: true });
  }
}

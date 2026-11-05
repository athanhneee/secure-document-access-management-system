/**
 * Thuật toán: Phân Tích & So Sánh Thứ Tự Từ Điển Phiên Bản Ngữ Nghĩa SemVer 2.0 (Lexicographical SemVer Tuple Gate)
 * Mục đích: Cưỡng chế môi trường thực thi phải dùng đúng nhánh Node.js 24 LTS đạt ngưỡng tối thiểu và trình quản lý gói `pnpm` đã ghim trong `package.json`.
 * Cơ chế hoạt động:
 *   - Trích xuất bộ ba số nguyên `[major, minor, patch]` từ `engines.node` và `process.versions.node`, kiểm tra bất biến `major === 24` và bất đẳng thức thứ tự từ điển `(minor > minMinor) || (minor === minMinor && patch >= minPatch)`.
 *   - Đối chiếu tiền tố biến môi trường `npm_config_user_agent` để chặn cài đặt sai công cụ bằng `npm` hoặc `yarn`.
 */
import { readFile } from 'node:fs/promises';

const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const expectedNode = /(\d+\.\d+\.\d+)/.exec(manifest.engines?.node ?? '')?.[1] ?? '24.14.0';
const parts = process.versions.node.split('.').map(Number);
const minimum = expectedNode.split('.').map(Number);
if (
  parts[0] !== 24 ||
  parts[1] < minimum[1] ||
  (parts[1] === minimum[1] && parts[2] < minimum[2])
) {
  throw new Error(
    `Node ${expectedNode}+ in the 24 LTS line is required; found ${process.versions.node}.`,
  );
}
const expectedPnpm = manifest.packageManager.replace('@', '/');
if (!process.env['npm_config_user_agent']?.startsWith(`${expectedPnpm} `)) {
  throw new Error(
    `Install with ${manifest.packageManager}; do not use npm or yarn for this workspace.`,
  );
}

import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

/**
 * Thuật toán / Tổng quan module:
 * Cơ chế thu dọn định kỳ tệp tạm giải mã và bản dẫn xuất (derivative/watermarked temp files) vượt quá thời gian sống TTL
 * nhằm đảm bảo không lưu giữ dữ liệu rõ trên đĩa lâu hơn mức cần thiết, kết hợp kiểm tra chống leo thang đường dẫn và symlink.
 */

export interface CleanupResult {
  cleanedTempFiles: number;
  timestamp: string;
}

/**
 * Periodically cleans up temporary decrypted files and derivatives exceeding TTL.
 * Requirement 9: Cleanup derivative and temp file according to TTL; no plaintext on disk longer than necessary.
 *
 * Thuật toán: Quét và xóa an toàn tệp/thư mục tạm hết hạn TTL chống tấn công Symlink & Path Traversal.
 * - Chuẩn hóa đường dẫn gốc `resolvedBase`, lọc các mục bắt đầu bằng tiền tố `'sda-'` và xác minh hậu tố đường dẫn con.
 * - Dùng `fsp.lstat` (không đi theo liên kết tượng trưng symlink sang thư mục ngoài ý muốn), kiểm tra độ tuổi `now - stat.mtimeMs > maxAgeMs`,
 *   sau đó xóa nguyên tử bằng `unlink` (cho tệp/symlink) hoặc `rm -rf` (cho thư mục con).
 */
export async function cleanStaleTempFiles(
  maxAgeMinutes: number = 15,
  targetDir: string = os.tmpdir(),
): Promise<number> {
  let cleaned = 0;
  const tempBaseDir = targetDir;
  const maxAgeMs = maxAgeMinutes * 60 * 1000;
  const now = Date.now();

  try {
    const resolvedBase = path.resolve(tempBaseDir);
    const files = await fsp.readdir(resolvedBase).catch(() => []);

    for (const file of files) {
      if (file.startsWith('sda-')) {
        const fullPath = path.resolve(resolvedBase, file);
        if (!fullPath.startsWith(`${resolvedBase}${path.sep}`)) {
          continue;
        }
        try {
          // Use lstat so symlinks in shared /tmp are NEVER followed into arbitrary directories
          const stat = await fsp.lstat(fullPath);
          if (now - stat.mtimeMs > maxAgeMs) {
            if (stat.isSymbolicLink() || stat.isFile()) {
              await fsp.unlink(fullPath).catch(() => {});
            } else if (stat.isDirectory()) {
              await fsp.rm(fullPath, { recursive: true, force: true }).catch(() => {});
            }
            cleaned++;
          }
        } catch {
          // File might have already been cleaned up
        }
      }
    }
  } catch (err) {
    console.warn(`Temp directory cleanup error: ${err}`);
  }

  return cleaned;
}

/**
 * Start the derivative and temporary file cleanup background loop.
 *
 * Thuật toán: Bộ lập lịch định kỳ chống chồng lấn chu kỳ (Non-Overlapping Interval Scheduler)
 * cho tiến trình dọn tệp tạm dẫn xuất, tự động giải phóng timer khi `AbortSignal` kích hoạt.
 */
export function startDerivativeCleanupJob(
  intervalMs: number,
  ttlMinutes: number,
  signal: AbortSignal,
): void {
  if (signal.aborted) return;

  let isRunning = false;
  const timer = setInterval(async () => {
    if (signal.aborted) {
      clearInterval(timer);
      return;
    }
    if (isRunning) return;
    isRunning = true;

    try {
      const cleaned = await cleanStaleTempFiles(ttlMinutes);
      if (cleaned > 0) {
        console.info(`Derivative cleanup job purged ${cleaned} expired temporary files.`);
      }
    } catch (err) {
      console.error(`Derivative cleanup cycle failed: ${err}`);
    } finally {
      isRunning = false;
    }
  }, intervalMs);

  signal.addEventListener(
    'abort',
    () => {
      clearInterval(timer);
      console.info('Derivative cleanup job stopped cleanly.');
    },
    { once: true },
  );

  console.info(
    `Derivative cleanup worker started (interval: ${intervalMs}ms, TTL: ${ttlMinutes}m).`,
  );
}

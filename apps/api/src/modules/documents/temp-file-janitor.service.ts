/**
 * Module: Stale Temporary File & Directory Janitor Service
 * Thuật toán: Quét Định Kỳ Không Chặn Tiến Trình (`unref` Interval) Dọn Dẹp Tệp Tạm `sda-*` Quá Hạn 15 Phút Trong `os.tmpdir()`.
 *   1. Khi khởi tạo `DocumentsModule`, thiết lập bộ hẹn giờ nền chu kỳ 5 phút được `.unref()` để không cản trở tiến trình Node thoát sạch.
 *   2. Duyệt danh mục `os.tmpdir()`, lọc các mục bắt đầu bằng tiền tố `sda-` (`sda-dec-*`, `sda-ing-*`, `sda-upload-*`, `sda-office-*`, ...)
 *      có thời điểm sửa đổi cuối (`mtimeMs`) cũ hơn ngưỡng 15 phút (`900_000 ms`) và xóa đệ quy an toàn.
 */
import { Injectable, Logger, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export const DEFAULT_TEMP_SWEEP_INTERVAL_MS = 5 * 60_000;
export const DEFAULT_STALE_TEMP_MAX_AGE_MS = 15 * 60_000;
const SDA_TEMP_PREFIX = 'sda-';

@Injectable()
export class TempFileJanitorService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(TempFileJanitorService.name);
  private sweepTimer: ReturnType<typeof setInterval> | null = null;

  /**
   * Thuật toán: Kích hoạt bộ dọn dẹp định kỳ nền `.unref()` khi khởi chạy mô-đun.
   */
  onModuleInit(): void {
    if (this.sweepTimer) return;
    this.sweepTimer = setInterval(() => {
      void this.sweepStaleTempEntries().catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.warn(`Temp file janitor sweep encountered an error: ${msg}`);
      });
    }, DEFAULT_TEMP_SWEEP_INTERVAL_MS);
    this.sweepTimer.unref();
  }

  /**
   * Thuật toán: Hủy bộ hẹn giờ dọn dẹp tệp tạm khi đóng ứng dụng.
   */
  onModuleDestroy(): void {
    if (this.sweepTimer) {
      clearInterval(this.sweepTimer);
      this.sweepTimer = null;
    }
  }

  /**
   * Thuật toán: Duyệt `baseTempDir` (mặc định `os.tmpdir()`) và xóa các tệp/thư mục tạm `sda-*` cũ hơn `maxAgeMs` (mặc định 15 phút).
   */
  async sweepStaleTempEntries(
    maxAgeMs = DEFAULT_STALE_TEMP_MAX_AGE_MS,
    baseTempDir = os.tmpdir(),
    nowMs = Date.now(),
  ): Promise<number> {
    let removedCount = 0;
    const entries = await fsp.readdir(baseTempDir, { withFileTypes: true }).catch(() => []);

    for (const entry of entries) {
      if (!entry.name.startsWith(SDA_TEMP_PREFIX)) continue;
      if (entry.isSymbolicLink()) continue;

      const fullPath = path.join(baseTempDir, entry.name);
      const stat = await fsp.lstat(fullPath).catch(() => null);
      if (!stat || stat.isSymbolicLink()) continue;

      if (nowMs - stat.mtimeMs > maxAgeMs) {
        try {
          await fsp.rm(fullPath, { recursive: true, force: true });
          removedCount += 1;
        } catch {
          // Entry may have been concurrently unlinked by active request cleanup
        }
      }
    }

    if (removedCount > 0) {
      this.logger.log(`Swept ${removedCount} stale temporary sda-* entries from ${baseTempDir}`);
    }
    return removedCount;
  }
}

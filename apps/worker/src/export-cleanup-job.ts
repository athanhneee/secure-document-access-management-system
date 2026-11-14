import { getDatabaseClient } from '@sda/database';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { recordWorkerJobRun } from './worker-metrics.js';

/**
 * Thuật toán / Tổng quan module:
 * Tiến trình thu hồi tệp kết xuất kiểm toán bất đồng bộ (`async_export_jobs`) đã hết hạn thời gian sống (`expires_at < now`),
 * neo thư mục dự phòng chuẩn theo `import.meta.dirname` (`../../../.local/exports` đồng bộ 100% với `@sda/api`)
 * và kiểm tra giam cầm đường dẫn (Path Containment) trước khi `unlink`.
 */

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export const DEFAULT_EXPORT_CLEANUP_DIR = path.resolve(
  import.meta.dirname,
  '../../../.local/exports',
);

export interface ExportCleanupResult {
  expiredJobsCleaned: number;
  filesDeleted: number;
}

/**
 * Thuật toán: Thu dọn công việc xuất dữ liệu hết hạn có kiểm soát biên thư mục (Bounded Path Containment Cleanup).
 * - Neo thư mục gốc mặc định vào `path.resolve(import.meta.dirname, '../../../.local/exports')` thay vì `process.cwd()`.
 * - Dùng `lstat` xác minh là tệp thường nằm bên trong `resolvedBaseDir` trước khi xóa tệp vật lý và bản ghi CSDL.
 */
export async function cleanExpiredExportJobs(options?: {
  databaseClient?: PrismaClient;
  now?: Date;
  exportBaseDir?: string;
}): Promise<ExportCleanupResult> {
  const database = options?.databaseClient ?? getDatabaseClient();
  const now = options?.now ?? new Date();
  const resolvedBaseDir = path.resolve(
    options?.exportBaseDir ??
      (process.env['EXPORT_STORAGE_DIR']?.trim() || DEFAULT_EXPORT_CLEANUP_DIR),
  );

  let expiredJobsCleaned = 0;
  let filesDeleted = 0;

  try {
    const expiredJobs = await database.asyncExportJob.findMany({
      where: {
        expires_at: { lt: now },
      },
      select: {
        id: true,
        file_path: true,
      },
    });

    for (const job of expiredJobs) {
      if (job.file_path) {
        const resolvedTarget = path.resolve(job.file_path);
        const relativePath = path.relative(resolvedBaseDir, resolvedTarget);
        const isInsideBaseDir =
          relativePath.length > 0 &&
          !relativePath.startsWith('..') &&
          !path.isAbsolute(relativePath);

        if (!isInsideBaseDir) {
          console.warn(
            `Export cleanup refused to unlink out-of-bounds file_path for job ${job.id}`,
          );
          continue;
        }

        try {
          const stat = await fsp.lstat(resolvedTarget);
          if (!stat.isFile()) {
            console.warn(
              `Export cleanup refused to unlink non-regular file_path for job ${job.id}`,
            );
            continue;
          }
          await fsp.unlink(resolvedTarget);
          filesDeleted++;
        } catch (fileErr: unknown) {
          const errCode = (fileErr as NodeJS.ErrnoException | null | undefined)?.code;
          if (errCode !== 'ENOENT') {
            console.warn(
              `Export cleanup failed to unlink file for job ${job.id} (${errCode ?? 'UNKNOWN'}): ${fileErr instanceof Error ? fileErr.message : String(fileErr)}`,
            );
            continue;
          }
        }
      }

      await database.asyncExportJob.delete({
        where: { id: job.id },
      });
      expiredJobsCleaned++;
    }
  } catch (err) {
    console.warn(`Export cleanup encountered error: ${err}`);
  }

  return { expiredJobsCleaned, filesDeleted };
}

/**
 * Thuật toán: Bộ lập lịch định kỳ chống chồng lấn chu kỳ (Non-Overlapping Interval Scheduler) cho `ExportCleanupJob`.
 */
export function startExportCleanupJob(intervalMs: number, signal: AbortSignal): void {
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
      const result = await cleanExpiredExportJobs();
      recordWorkerJobRun('export_cleanup', 'success');
      if (result.expiredJobsCleaned > 0) {
        console.info(
          `Export cleanup job purged ${result.expiredJobsCleaned} expired export job(s) and ${result.filesDeleted} file(s).`,
        );
      }
    } catch (err) {
      recordWorkerJobRun('export_cleanup', 'error');
      console.error(`Export cleanup cycle failed: ${err}`);
    } finally {
      isRunning = false;
    }
  }, intervalMs);

  signal.addEventListener(
    'abort',
    () => {
      clearInterval(timer);
      console.info('Export cleanup worker stopped cleanly.');
    },
    { once: true },
  );

  console.info(`Export cleanup worker started (interval: ${intervalMs}ms).`);
}

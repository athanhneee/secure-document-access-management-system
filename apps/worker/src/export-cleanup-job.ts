import { getDatabaseClient } from '@sda/database';
import fsp from 'node:fs/promises';
import path from 'node:path';

/**
 * Thuật toán / Tổng quan module:
 * Tiến trình thu hồi tệp kết xuất kiểm toán bất đồng bộ (`async_export_jobs`) đã hết hạn thời gian sống (`expires_at < now`),
 * đảm bảo xóa cả tệp vật lý trên đĩa (với kiểm tra giam cầm đường dẫn Path Containment) lẫn bản ghi metadata trong CSDL.
 */

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface ExportCleanupResult {
  expiredJobsCleaned: number;
  filesDeleted: number;
}

/**
 * Cleans up expired async export files and jobs whose TTL has elapsed.
 *
 * Thuật toán: Thu dọn công việc xuất dữ liệu hết hạn có kiểm soát biên thư mục (Bounded Path Containment Cleanup).
 * - Truy vấn tất cả bản ghi `async_export_jobs` có `expires_at < now`.
 * - Với mỗi bản ghi có `file_path`, chuẩn hóa đường dẫn tuyệt đối và đối chiếu tiền tố `${resolvedBaseDir}${path.sep}`
 *   để ngăn chặn xóa nhầm tệp ngoài vùng `.local/exports`; dùng `lstat` xác minh là tệp thường trước khi `unlink`, rồi xóa bản ghi CSDL.
 */
export async function cleanExpiredExportJobs(options?: {
  databaseClient?: PrismaClient;
  now?: Date;
  exportBaseDir?: string;
}): Promise<ExportCleanupResult> {
  const database = options?.databaseClient ?? getDatabaseClient();
  const now = options?.now ?? new Date();
  const resolvedBaseDir = path.resolve(
    options?.exportBaseDir ?? path.join(process.cwd(), '.local', 'exports'),
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
        if (resolvedTarget.startsWith(`${resolvedBaseDir}${path.sep}`)) {
          try {
            const stat = await fsp.lstat(resolvedTarget);
            if (stat.isFile()) {
              await fsp.unlink(resolvedTarget);
              filesDeleted++;
            }
          } catch {
            // File might already have been unlinked or not exist
          }
        } else {
          console.warn(
            `Export cleanup refused to unlink out-of-bounds file_path for job ${job.id}`,
          );
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
 * Starts the export cleanup background runner.
 *
 * Thuật toán: Bộ lập lịch định kỳ chống chồng lấn chu kỳ (Non-Overlapping Interval Scheduler)
 * bảo vệ bằng cờ `isRunning` và dừng sạch theo tín hiệu `AbortSignal`.
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
      if (result.expiredJobsCleaned > 0) {
        console.info(
          `Export cleanup job purged ${result.expiredJobsCleaned} expired export job(s) and ${result.filesDeleted} file(s).`,
        );
      }
    } catch (err) {
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

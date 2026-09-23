import { getDatabaseClient } from '@sda/database';
import fsp from 'node:fs/promises';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface ExportCleanupResult {
  expiredJobsCleaned: number;
  filesDeleted: number;
}

/**
 * Cleans up expired async export files and jobs whose TTL has elapsed.
 */
export async function cleanExpiredExportJobs(options?: {
  databaseClient?: PrismaClient;
  now?: Date;
}): Promise<ExportCleanupResult> {
  const database = options?.databaseClient ?? getDatabaseClient();
  const now = options?.now ?? new Date();

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
        try {
          await fsp.unlink(job.file_path);
          filesDeleted++;
        } catch {
          // File might already have been unlinked or not exist
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
 */
export function startExportCleanupJob(intervalMs: number, signal: AbortSignal): void {
  if (signal.aborted) return;

  const timer = setInterval(async () => {
    if (signal.aborted) {
      clearInterval(timer);
      return;
    }

    try {
      const result = await cleanExpiredExportJobs();
      if (result.expiredJobsCleaned > 0) {
        console.info(
          `Export cleanup job purged ${result.expiredJobsCleaned} expired export job(s) and ${result.filesDeleted} file(s).`,
        );
      }
    } catch (err) {
      console.error(`Export cleanup cycle failed: ${err}`);
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

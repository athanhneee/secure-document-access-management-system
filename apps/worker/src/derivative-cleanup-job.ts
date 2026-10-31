import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

export interface CleanupResult {
  cleanedTempFiles: number;
  timestamp: string;
}

/**
 * Periodically cleans up temporary decrypted files and derivatives exceeding TTL.
 * Requirement 9: Cleanup derivative and temp file according to TTL; no plaintext on disk longer than necessary.
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

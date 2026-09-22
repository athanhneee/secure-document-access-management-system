import { Injectable, Logger } from '@nestjs/common';
import fsp from 'node:fs/promises';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { ObjectStorageService } from './object-storage.service.js';

export interface UploadSessionCompensation {
  storageKeysToDelete: Array<{ bucket: string; key: string }>;
  tempFilesToDelete: string[];
}

@Injectable()
export class OrphanCompensationService {
  private readonly logger = new Logger(OrphanCompensationService.name);

  constructor(private readonly storage: ObjectStorageService) {}

  /**
   * Creates a new compensation tracker for an active upload session.
   */
  createSession(): UploadSessionCompensation {
    return {
      storageKeysToDelete: [],
      tempFilesToDelete: [],
    };
  }

  /**
   * Rolls back all tracked storage objects and temp files for a failed upload session.
   */
  async compensate(session: UploadSessionCompensation): Promise<void> {
    // 1. Delete tracked storage objects
    for (const item of session.storageKeysToDelete) {
      try {
        await this.storage.deleteObject(item.bucket, item.key);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.warn(
          `Compensation failed to delete storage object ${item.bucket}/${item.key}: ${msg}`,
        );
      }
    }

    // 2. Delete tracked temporary files
    for (const filePath of session.tempFilesToDelete) {
      try {
        if (fs.existsSync(filePath)) {
          const stat = await fsp.stat(filePath).catch(() => null);
          if (stat?.isDirectory()) {
            await fsp.rm(filePath, { recursive: true, force: true }).catch(() => {});
          } else {
            await fsp.unlink(filePath).catch(() => {});
          }
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.warn(`Compensation failed to delete temp file ${filePath}: ${msg}`);
      }
    }
  }

  /**
   * Cleanup job for temporary files older than maxAgeMs.
   */
  async cleanupStaleTempFiles(maxAgeMs = 3_600_000): Promise<number> {
    let deletedCount = 0;
    try {
      const tempDir = os.tmpdir();
      const entries = await fsp.readdir(tempDir);
      const now = Date.now();

      for (const entry of entries) {
        if (entry.startsWith('sda-') || entry.startsWith('sda_')) {
          const fullPath = path.join(tempDir, entry);
          try {
            const stats = await fsp.stat(fullPath);
            if (now - stats.mtimeMs > maxAgeMs) {
              if (stats.isDirectory()) {
                await fsp.rm(fullPath, { recursive: true, force: true });
              } else {
                await fsp.unlink(fullPath);
              }
              deletedCount++;
            }
          } catch {
            // Ignore if file was already removed
          }
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(`Stale temp file cleanup encountered error: ${msg}`);
    }
    return deletedCount;
  }
}

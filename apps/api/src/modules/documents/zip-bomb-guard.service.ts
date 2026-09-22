import { BadRequestException, Injectable } from '@nestjs/common';
import yauzl, { type ZipFile, type Entry } from 'yauzl';
import { AppErrorCode } from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
import type { AllowedExtension } from './file-validation.service.js';

export interface ZipBombCheckOptions {
  maxEntries?: number;
  maxTotalUncompressedSize?: number;
  maxDepth?: number;
  maxCompressionRatio?: number;
}

@Injectable()
export class ZipBombGuardService {
  private readonly defaultMaxEntries: number;
  private readonly defaultMaxTotalUncompressedSize: number;
  private readonly defaultMaxDepth: number;
  private readonly defaultMaxCompressionRatio: number;

  constructor(config: AppConfigService) {
    this.defaultMaxEntries = config.get('ZIP_MAX_ENTRIES');
    this.defaultMaxTotalUncompressedSize = config.get('ZIP_MAX_TOTAL_UNCOMPRESSED_SIZE');
    this.defaultMaxDepth = config.get('ZIP_MAX_DEPTH');
    this.defaultMaxCompressionRatio = config.get('ZIP_MAX_COMPRESSION_RATIO');
  }

  /**
   * Inspects a zip file (either from buffer or file path) for:
   * 1. Zip bomb indicators (entry count, uncompressed size, depth, compression ratio)
   * 2. Zip entry path traversal (../, absolute paths)
   * 3. Office OpenXML internal structure ([Content_Types].xml, word/, xl/, ppt/)
   */
  async inspectOfficeZip(
    source: Buffer | string,
    extension: AllowedExtension,
    options?: ZipBombCheckOptions,
  ): Promise<void> {
    const maxEntries = options?.maxEntries ?? this.defaultMaxEntries;
    const maxTotalUncompressedSize =
      options?.maxTotalUncompressedSize ?? this.defaultMaxTotalUncompressedSize;
    const maxDepth = options?.maxDepth ?? this.defaultMaxDepth;
    const maxCompressionRatio = options?.maxCompressionRatio ?? this.defaultMaxCompressionRatio;

    const zipFile = await this.openZip(source);

    return new Promise<void>((resolve, reject) => {
      let entryCount = 0;
      let totalUncompressedSize = 0;
      let totalCompressedSize = 0;
      let hasContentTypes = false;
      let hasOfficeSpecificDir = false;

      const requiredDir = extension === '.docx' ? 'word/' : extension === '.xlsx' ? 'xl/' : 'ppt/';

      zipFile.on('entry', (entry: Entry) => {
        entryCount++;

        // 1. Entry count check
        if (entryCount > maxEntries) {
          zipFile.close();
          return reject(
            new BadRequestException({
              errorCode: AppErrorCode.VALIDATION_FAILED,
              message: `Zip archive contains too many entries (exceeds limit of ${maxEntries}).`,
            }),
          );
        }

        const fileName = entry.fileName;

        // 2. Path traversal check in entry name
        if (
          fileName.includes('..') ||
          fileName.startsWith('/') ||
          fileName.startsWith('\\') ||
          /^[a-zA-Z]:/u.test(fileName)
        ) {
          zipFile.close();
          return reject(
            new BadRequestException({
              errorCode: AppErrorCode.INVALID_FILE_TYPE,
              message: 'Zip archive contains dangerous path traversal entry names.',
            }),
          );
        }

        // 3. Depth check (count directory levels)
        const segments = fileName.split(/[/\\]+/u).filter((seg) => seg.length > 0);
        const depth = entry.fileName.endsWith('/')
          ? segments.length
          : Math.max(0, segments.length - 1);
        if (depth > maxDepth) {
          zipFile.close();
          return reject(
            new BadRequestException({
              errorCode: AppErrorCode.VALIDATION_FAILED,
              message: `Zip archive exceeds directory nesting depth limit of ${maxDepth}.`,
            }),
          );
        }

        // 4. Cumulative uncompressed size check
        totalUncompressedSize += entry.uncompressedSize;
        totalCompressedSize += entry.compressedSize;

        if (totalUncompressedSize > maxTotalUncompressedSize) {
          zipFile.close();
          return reject(
            new BadRequestException({
              errorCode: AppErrorCode.VALIDATION_FAILED,
              message: `Zip archive uncompressed size exceeds limit of ${maxTotalUncompressedSize} bytes.`,
            }),
          );
        }

        // 5. Compression ratio check (for entries with non-trivial size)
        if (entry.compressedSize > 64) {
          const entryRatio = entry.uncompressedSize / entry.compressedSize;
          if (entryRatio > maxCompressionRatio) {
            zipFile.close();
            return reject(
              new BadRequestException({
                errorCode: AppErrorCode.VALIDATION_FAILED,
                message: `Zip archive contains suspicious compression ratio (${entryRatio.toFixed(1)} > ${maxCompressionRatio}).`,
              }),
            );
          }
        }

        // 6. Check Office internal package requirements
        const lowerName = fileName.toLowerCase();
        if (lowerName === '[content_types].xml') {
          hasContentTypes = true;
        }
        if (lowerName.startsWith(requiredDir)) {
          hasOfficeSpecificDir = true;
        }

        zipFile.readEntry();
      });

      zipFile.on('end', () => {
        // Overall compression ratio check
        if (totalCompressedSize > 512) {
          const overallRatio = totalUncompressedSize / totalCompressedSize;
          if (overallRatio > maxCompressionRatio) {
            return reject(
              new BadRequestException({
                errorCode: AppErrorCode.VALIDATION_FAILED,
                message: `Zip archive total compression ratio exceeds safe limit of ${maxCompressionRatio}.`,
              }),
            );
          }
        }

        // Validate Office structure
        if (!hasContentTypes) {
          return reject(
            new BadRequestException({
              errorCode: AppErrorCode.INVALID_FILE_TYPE,
              message: `Invalid Office OpenXML file: missing [Content_Types].xml for ${extension}.`,
            }),
          );
        }

        if (!hasOfficeSpecificDir) {
          return reject(
            new BadRequestException({
              errorCode: AppErrorCode.INVALID_FILE_TYPE,
              message: `Invalid Office OpenXML file: missing ${requiredDir} package structure for ${extension}.`,
            }),
          );
        }

        resolve();
      });

      zipFile.on('error', (err) => {
        reject(
          new BadRequestException({
            errorCode: AppErrorCode.INVALID_FILE_TYPE,
            message: `Failed to parse zip archive: ${err.message}`,
          }),
        );
      });

      zipFile.readEntry();
    });
  }

  private openZip(source: Buffer | string): Promise<ZipFile> {
    return new Promise((resolve, reject) => {
      if (typeof source === 'string') {
        yauzl.open(source, { lazyEntries: true, autoClose: false }, (err, zip) => {
          if (err || !zip) return reject(err ?? new Error('Failed to open zip file'));
          resolve(zip);
        });
      } else {
        yauzl.fromBuffer(source, { lazyEntries: true, autoClose: false }, (err, zip) => {
          if (err || !zip) return reject(err ?? new Error('Failed to open zip buffer'));
          resolve(zip);
        });
      }
    });
  }
}

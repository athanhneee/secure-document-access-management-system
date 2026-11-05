/**
 * Module: Zip Bomb & Office OpenXML Structural Guard Service
 * Algorithm: Lazy PKZIP central-directory traversal combined with stream inflation byte counting
 *   to defeat spoofed 32-bit ZIP headers, enforce entry/depth/ratio caps, and block OOXML macros/XXE/SSRF.
 */
import { BadRequestException, Injectable } from '@nestjs/common';
import type { Entry } from 'yauzl';
import { AppErrorCode } from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
import type { AllowedExtension } from './file-validation.service.js';
import {
  inflateAndInspectZipEntry,
  inspectOoxmlEntryPathSecurity,
  openYauzlZip,
} from './zip-xml-security.helper.js';

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
   * Algorithm: Streaming PKZIP Inflation & OOXML Structure Verification
   * Validates entry count, path traversal, directory depth, declared & actual inflated byte limits,
   * compression ratios, prohibited VBA/ActiveX/XXE/SSRF vectors, and required OOXML package roots.
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

    const zipFile = await openYauzlZip(source);

    return new Promise<void>((resolve, reject) => {
      let settled = false;
      const safeClose = (): void => {
        try {
          zipFile.close();
        } catch {
          // Ignore close errors on already-closed handles
        }
      };
      const finishResolve = (): void => {
        if (settled) return;
        settled = true;
        safeClose();
        resolve();
      };
      const finishReject = (err: Error): void => {
        if (settled) return;
        settled = true;
        safeClose();
        reject(err);
      };

      let entryCount = 0;
      let totalDeclaredUncompressedSize = 0;
      let actualTotalUncompressedSize = 0;
      let totalCompressedSize = 0;
      let hasContentTypes = false;
      let hasOfficeSpecificDir = false;
      const requiredDir = extension === '.docx' ? 'word/' : extension === '.xlsx' ? 'xl/' : 'ppt/';

      zipFile.on('entry', (entry: Entry) => {
        if (settled) return;
        entryCount++;
        if (entryCount > maxEntries) {
          return finishReject(
            new BadRequestException({
              errorCode: AppErrorCode.VALIDATION_FAILED,
              message: `Zip archive contains too many entries (exceeds limit of ${maxEntries}).`,
            }),
          );
        }

        const fileName = entry.fileName;
        if (
          fileName.includes('..') ||
          fileName.startsWith('/') ||
          fileName.startsWith('\\') ||
          /^[a-zA-Z]:/u.test(fileName)
        ) {
          return finishReject(
            new BadRequestException({
              errorCode: AppErrorCode.INVALID_FILE_TYPE,
              message: 'Zip archive contains dangerous path traversal entry names.',
            }),
          );
        }

        const segments = fileName.split(/[/\\]+/u).filter((seg) => seg.length > 0);
        const depth = fileName.endsWith('/') ? segments.length : Math.max(0, segments.length - 1);
        if (depth > maxDepth) {
          return finishReject(
            new BadRequestException({
              errorCode: AppErrorCode.VALIDATION_FAILED,
              message: `Zip archive exceeds directory nesting depth limit of ${maxDepth}.`,
            }),
          );
        }

        totalDeclaredUncompressedSize += entry.uncompressedSize;
        totalCompressedSize += entry.compressedSize;
        if (totalDeclaredUncompressedSize > maxTotalUncompressedSize) {
          return finishReject(
            new BadRequestException({
              errorCode: AppErrorCode.VALIDATION_FAILED,
              message: `Zip archive uncompressed size exceeds limit of ${maxTotalUncompressedSize} bytes.`,
            }),
          );
        }

        if (entry.compressedSize > 64) {
          const entryRatio = entry.uncompressedSize / entry.compressedSize;
          if (entryRatio > maxCompressionRatio) {
            return finishReject(
              new BadRequestException({
                errorCode: AppErrorCode.VALIDATION_FAILED,
                message: `Zip archive contains suspicious compression ratio (${entryRatio.toFixed(1)} > ${maxCompressionRatio}).`,
              }),
            );
          }
        }

        const lowerName = fileName.toLowerCase();
        const pathIssue = inspectOoxmlEntryPathSecurity(lowerName);
        if (pathIssue) return finishReject(pathIssue);

        if (lowerName === '[content_types].xml') hasContentTypes = true;
        if (lowerName.startsWith(requiredDir)) hasOfficeSpecificDir = true;
        if (fileName.endsWith('/')) {
          zipFile.readEntry();
          return;
        }

        inflateAndInspectZipEntry({
          zipFile,
          entry,
          lowerName,
          maxTotalUncompressedSize,
          maxCompressionRatio,
          addActualBytes: (delta) => {
            actualTotalUncompressedSize += delta;
            return actualTotalUncompressedSize;
          },
          isSettled: () => settled,
          finishReject,
        });
      });

      zipFile.on('end', () => {
        if (settled) return;
        const effectiveUncompressed = Math.max(
          totalDeclaredUncompressedSize,
          actualTotalUncompressedSize,
        );
        if (
          totalCompressedSize > 512 &&
          effectiveUncompressed / totalCompressedSize > maxCompressionRatio
        ) {
          return finishReject(
            new BadRequestException({
              errorCode: AppErrorCode.VALIDATION_FAILED,
              message: `Zip archive total compression ratio exceeds safe limit of ${maxCompressionRatio}.`,
            }),
          );
        }
        if (!hasContentTypes) {
          return finishReject(
            new BadRequestException({
              errorCode: AppErrorCode.INVALID_FILE_TYPE,
              message: `Invalid Office OpenXML file: missing [Content_Types].xml for ${extension}.`,
            }),
          );
        }
        if (!hasOfficeSpecificDir) {
          return finishReject(
            new BadRequestException({
              errorCode: AppErrorCode.INVALID_FILE_TYPE,
              message: `Invalid Office OpenXML file: missing ${requiredDir} package structure for ${extension}.`,
            }),
          );
        }
        finishResolve();
      });

      zipFile.on('error', (err) => {
        finishReject(
          new BadRequestException({
            errorCode: AppErrorCode.INVALID_FILE_TYPE,
            message: `Failed to parse zip archive: ${err.message}`,
          }),
        );
      });

      zipFile.readEntry();
    });
  }
}

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

        // 1. Entry count check
        if (entryCount > maxEntries) {
          return finishReject(
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
          return finishReject(
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
          return finishReject(
            new BadRequestException({
              errorCode: AppErrorCode.VALIDATION_FAILED,
              message: `Zip archive exceeds directory nesting depth limit of ${maxDepth}.`,
            }),
          );
        }

        // 4. Declared header size & ratio pre-check
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

        // 5. Block prohibited VBA macros / ActiveX / external workbook connections at ingestion
        const lowerName = fileName.toLowerCase();
        if (
          lowerName.includes('vbaproject.bin') ||
          lowerName.includes('vbadirection') ||
          lowerName.includes('vbadata') ||
          (lowerName.endsWith('.bin') && lowerName.includes('vba')) ||
          lowerName.includes('/activex/')
        ) {
          return finishReject(
            new BadRequestException({
              errorCode: AppErrorCode.OFFICE_MACRO_BLOCKED,
              message: 'Office document contains prohibited executable macros or ActiveX controls.',
            }),
          );
        }

        if (lowerName === 'xl/connections.xml' || lowerName.endsWith('/externalallink1.xml')) {
          return finishReject(
            new BadRequestException({
              errorCode: AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
              message: 'Office document contains prohibited external data connections.',
            }),
          );
        }

        // 6. Check Office internal package requirements
        if (lowerName === '[content_types].xml') {
          hasContentTypes = true;
        }
        if (lowerName.startsWith(requiredDir)) {
          hasOfficeSpecificDir = true;
        }

        if (fileName.endsWith('/')) {
          zipFile.readEntry();
          return;
        }

        // 7. Stream-inflate entry to defeat spoofed 32-bit ZIP header sizes & inspect XML/RELS
        const shouldInspectXml = lowerName.endsWith('.xml') || lowerName.endsWith('.rels');
        const maxXmlInspectBytes = 2 * 1024 * 1024;
        const xmlChunks: Buffer[] = [];
        let entryActualBytes = 0;

        zipFile.openReadStream(entry, (streamErr, readStream) => {
          if (settled) return;
          if (streamErr || !readStream) {
            return finishReject(
              new BadRequestException({
                errorCode: AppErrorCode.INVALID_FILE_TYPE,
                message: `Failed to read zip entry ${fileName}: ${streamErr?.message ?? 'corrupt stream'}`,
              }),
            );
          }

          readStream.on('data', (chunk: Buffer) => {
            if (settled) {
              readStream.destroy();
              return;
            }
            entryActualBytes += chunk.length;
            actualTotalUncompressedSize += chunk.length;

            if (actualTotalUncompressedSize > maxTotalUncompressedSize) {
              readStream.destroy();
              return finishReject(
                new BadRequestException({
                  errorCode: AppErrorCode.VALIDATION_FAILED,
                  message: `Zip archive actual inflated size exceeds limit of ${maxTotalUncompressedSize} bytes.`,
                }),
              );
            }

            if (entry.compressedSize > 64) {
              const actualRatio = entryActualBytes / entry.compressedSize;
              if (actualRatio > maxCompressionRatio) {
                readStream.destroy();
                return finishReject(
                  new BadRequestException({
                    errorCode: AppErrorCode.VALIDATION_FAILED,
                    message: `Zip archive actual compression ratio (${actualRatio.toFixed(1)}) exceeds limit of ${maxCompressionRatio}.`,
                  }),
                );
              }
            }

            if (shouldInspectXml && entryActualBytes <= maxXmlInspectBytes) {
              xmlChunks.push(chunk);
            }
          });

          readStream.on('error', (err) => {
            finishReject(
              new BadRequestException({
                errorCode: AppErrorCode.INVALID_FILE_TYPE,
                message: `Corrupt compressed stream in zip archive: ${err.message}`,
              }),
            );
          });

          readStream.on('end', () => {
            if (settled) return;
            if (
              shouldInspectXml &&
              xmlChunks.length > 0 &&
              entryActualBytes <= maxXmlInspectBytes
            ) {
              const xmlText = Buffer.concat(xmlChunks).toString('utf8');
              const xmlIssue = this.detectMaliciousXmlOrRels(xmlText, lowerName.endsWith('.rels'));
              if (xmlIssue) {
                return finishReject(xmlIssue);
              }
            }
            zipFile.readEntry();
          });
        });
      });

      zipFile.on('end', () => {
        if (settled) return;
        const effectiveUncompressed = Math.max(
          totalDeclaredUncompressedSize,
          actualTotalUncompressedSize,
        );
        if (totalCompressedSize > 512) {
          const overallRatio = effectiveUncompressed / totalCompressedSize;
          if (overallRatio > maxCompressionRatio) {
            return finishReject(
              new BadRequestException({
                errorCode: AppErrorCode.VALIDATION_FAILED,
                message: `Zip archive total compression ratio exceeds safe limit of ${maxCompressionRatio}.`,
              }),
            );
          }
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

  private detectMaliciousXmlOrRels(xml: string, isRels: boolean): BadRequestException | null {
    if (/<!doctype\b|<!entity\b/iu.test(xml)) {
      return new BadRequestException({
        errorCode: AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
        message: 'Office XML contains prohibited DOCTYPE or ENTITY declarations (XXE protection).',
      });
    }

    if (!isRels) return null;

    const decoded = xml
      .replace(/&#x([0-9a-f]+);/giu, (_, hex: string) =>
        String.fromCodePoint(Math.min(parseInt(hex, 16), 0x10ffff)),
      )
      .replace(/&#(\d+);/gu, (_, dec: string) =>
        String.fromCodePoint(Math.min(parseInt(dec, 10), 0x10ffff)),
      )
      .replace(/&quot;/giu, '"')
      .replace(/&apos;/giu, "'")
      .replace(/&amp;/giu, '&');

    if (
      /targetmode\s*=\s*["']\s*external\s*["']/iu.test(decoded) ||
      /target\s*=\s*["']\s*(?:https?|ftp|file|gopher|ldap|jar|netdoc|smb|mailto|mhtml):/iu.test(
        decoded,
      ) ||
      /target\s*=\s*["']\s*(?:\\\\|\/\/)/iu.test(decoded)
    ) {
      return new BadRequestException({
        errorCode: AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
        message:
          'Office document contains prohibited external relationships or SSRF/NTLM leak vectors.',
      });
    }

    return null;
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

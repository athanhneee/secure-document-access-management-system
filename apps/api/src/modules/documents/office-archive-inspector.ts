/**
 * Module: OOXML Archive Pre-Conversion Security & Text Extraction Helper
 * Algorithm: Streams all PKZIP entries fail-closed before Gotenberg conversion to block macros, external links,
 *   oversized `.rels` manifests, and XXE/SSRF payloads at any XML entry size, plus extracts fallback plain text.
 */
import { BadRequestException } from '@nestjs/common';
import yauzl from 'yauzl';
import { AppErrorCode } from '@sda/contracts';
import {
  createXmlStreamingSecurityScanner,
  inspectOoxmlEntryPathSecurity,
  normalizeArchiveEntryPath,
} from './zip-xml-security.helper.js';

const MAX_CONVERSION_ENTRIES = 10_000;
const MAX_CONVERSION_UNCOMPRESSED_BYTES = 100 * 1024 * 1024;

/**
 * Algorithm / Thuật toán: Kiểm định An ninh Gói OOXML Chế độ Fail-Closed Trước Chuyển đổi PDF (`inspectOfficeArchiveSecurity`).
 *   - Duyệt tuần tự từng entry bằng `lazyEntries: true`, chặn vượt ngưỡng số lượng entry hoặc tổng dung lượng giải nén thực tế (100 MiB).
 *   - Kiểm tra danh sách đen đường dẫn (`vbaProject.bin`, `/activex/`, `xl/externalLinks/externalLink*.xml`).
 *   - Giải nén luồng 100% các mục `.xml` và `.rels` qua `createXmlStreamingSecurityScanner` (cửa sổ trượt O(1) bộ nhớ cho `.xml` lớn > 5 MiB, giới hạn cứng Fail-Closed 2 MiB cho `.rels`), từ chối ngay lập tức nếu luồng lỗi hoặc phát hiện XXE/SSRF trước khi gọi Gotenberg.
 */
export async function inspectOfficeArchiveSecurity(officeBuffer: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(officeBuffer, { lazyEntries: true, autoClose: false }, (openErr, zipfile) => {
      if (openErr || !zipfile) {
        return reject(
          new BadRequestException({
            errorCode: AppErrorCode.OFFICE_CONVERSION_FAILED,
            message: 'Invalid or corrupt Office OpenXML package.',
          }),
        );
      }

      let settled = false;
      let entryCount = 0;
      let totalInflatedBytes = 0;

      const safeClose = (): void => {
        try {
          zipfile.close();
        } catch {
          // Ignore close errors
        }
      };

      const finishReject = (err: Error): void => {
        if (settled) return;
        settled = true;
        safeClose();
        reject(err);
      };

      const finishResolve = (): void => {
        if (settled) return;
        settled = true;
        safeClose();
        resolve();
      };

      zipfile.on('error', (zipErr) => {
        finishReject(
          new BadRequestException({
            errorCode: AppErrorCode.OFFICE_CONVERSION_FAILED,
            message: `Corrupt zip archive: ${zipErr.message}`,
          }),
        );
      });

      zipfile.on('end', () => finishResolve());

      zipfile.on('entry', (entry) => {
        if (settled) return;
        entryCount += 1;
        if (entryCount > MAX_CONVERSION_ENTRIES) {
          return finishReject(
            new BadRequestException({
              errorCode: AppErrorCode.VALIDATION_FAILED,
              message: `Office archive exceeds maximum entry count (${MAX_CONVERSION_ENTRIES}).`,
            }),
          );
        }

        // CONFLICT-RESOLVED: Chuẩn hóa \ thành / và cưỡng chế kiểm tra Zip-Slip (..) ngay trong inspectOfficeArchiveSecurity trước khi chuyển đổi Gotenberg (CRIT-05).
        const lower = normalizeArchiveEntryPath(entry.fileName);
        const pathIssue = inspectOoxmlEntryPathSecurity(
          entry.fileName,
          'Office document contains prohibited executable VBA macros.',
        );
        if (pathIssue) {
          return finishReject(pathIssue);
        }

        if (lower.endsWith('/')) {
          zipfile.readEntry();
          return;
        }

        const isXmlOrRels = lower.endsWith('.xml') || lower.endsWith('.rels');
        const scanner = isXmlOrRels
          ? createXmlStreamingSecurityScanner(lower.endsWith('.rels'))
          : null;

        zipfile.openReadStream(entry, (streamErr, readStream) => {
          if (settled) return;
          if (streamErr || !readStream) {
            return finishReject(
              new BadRequestException({
                errorCode: AppErrorCode.OFFICE_CONVERSION_FAILED,
                message: `Failed to inspect Office archive entry ${entry.fileName}.`,
              }),
            );
          }

          readStream.on('data', (chunk: Buffer) => {
            if (settled) {
              readStream.destroy();
              return;
            }
            totalInflatedBytes += chunk.length;
            if (totalInflatedBytes > MAX_CONVERSION_UNCOMPRESSED_BYTES) {
              readStream.destroy();
              return finishReject(
                new BadRequestException({
                  errorCode: AppErrorCode.VALIDATION_FAILED,
                  message: 'Office archive decompressed size exceeds conversion safety limit.',
                }),
              );
            }
            if (scanner) {
              const issue = scanner.push(chunk);
              if (issue) {
                readStream.destroy();
                return finishReject(issue);
              }
            }
          });

          readStream.on('error', (err) => {
            finishReject(
              new BadRequestException({
                errorCode: AppErrorCode.OFFICE_CONVERSION_FAILED,
                message: `Corrupt stream in Office archive entry ${entry.fileName}: ${err.message}`,
              }),
            );
          });

          readStream.on('end', () => {
            if (settled) return;
            if (scanner) {
              const finalIssue = scanner.finish();
              if (finalIssue) return finishReject(finalIssue);
            }
            zipfile.readEntry();
          });
        });
      });

      zipfile.readEntry();
    });
  });
}

export { extractOfficeFallbackText } from './office-ooxml-extractor.helper.js';

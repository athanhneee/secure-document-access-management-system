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

        const lower = entry.fileName.toLowerCase();
        const pathIssue = inspectOoxmlEntryPathSecurity(
          lower,
          'Office document contains prohibited executable VBA macros.',
        );
        if (pathIssue) {
          return finishReject(pathIssue);
        }

        if (entry.fileName.endsWith('/')) {
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

/**
 * Algorithm: Format-Aware OOXML Plain-Text Extraction
 * Extracts the primary XML content part per Office format and strips tags/entities into normalized lines.
 */
export async function extractOfficeFallbackText(
  officeBuffer: Buffer,
  filename: string,
): Promise<string> {
  const ext = filename.split('.').pop()?.toLowerCase();
  if (ext === 'docx') {
    const xml = await extractEntryContent(officeBuffer, 'word/document.xml');
    return xml ? sanitizeXmlToText(xml) : 'Document body is empty.';
  }
  if (ext === 'xlsx') {
    const sharedStringsXml = await extractEntryContent(officeBuffer, 'xl/sharedStrings.xml');
    return sharedStringsXml
      ? sanitizeXmlToText(sharedStringsXml)
      : 'Workbook contains no shared strings.';
  }
  if (ext === 'pptx') {
    const slideXml = await extractEntryContent(officeBuffer, 'ppt/slides/slide1.xml');
    return slideXml ? sanitizeXmlToText(slideXml) : 'Presentation slide content.';
  }
  return `Document: ${filename}\nFormat: Office OpenXML`;
}

/**
 * Algorithm: Bounded ZIP Entry UTF-8 Stream Extraction (Fallback Text Preview Only)
 * Inflates a single already-audited target entry up to a 5 MiB cap for fallback PDF text rendering.
 */
function extractEntryContent(buffer: Buffer, entryPath: string): Promise<string | null> {
  const maxExtractBytes = 5 * 1024 * 1024;
  return new Promise((resolve) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true, autoClose: false }, (err, zipfile) => {
      if (err || !zipfile) return resolve(null);

      let settled = false;
      const finish = (val: string | null): void => {
        if (settled) return;
        settled = true;
        try {
          zipfile.close();
        } catch {
          // Ignore close errors
        }
        resolve(val);
      };

      zipfile.readEntry();
      zipfile.on('entry', (entry) => {
        if (settled) return;
        if (entry.fileName === entryPath) {
          zipfile.openReadStream(entry, (streamErr, readStream) => {
            if (streamErr || !readStream) return finish(null);
            const chunks: Buffer[] = [];
            let total = 0;
            readStream.on('data', (c: Buffer) => {
              total += c.length;
              if (total > maxExtractBytes) {
                readStream.destroy();
                finish(null);
                return;
              }
              chunks.push(c);
            });
            readStream.on('end', () => finish(Buffer.concat(chunks).toString('utf-8')));
            readStream.on('error', () => finish(null));
          });
        } else {
          zipfile.readEntry();
        }
      });

      zipfile.on('end', () => finish(null));
      zipfile.on('error', () => finish(null));
    });
  });
}

/**
 * Algorithm: XML Tag Stripping & Whitespace Normalization
 * Replaces Word paragraph/run boundaries, removes XML tags, decodes standard entities, and trims blank lines.
 */
function sanitizeXmlToText(xml: string): string {
  const text = xml
    .replace(/<\/w:p>/g, '\n')
    .replace(/<\/w:r>/g, ' ')
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");

  return text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .join('\n');
}

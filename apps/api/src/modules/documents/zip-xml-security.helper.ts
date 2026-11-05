/**
 * Module: OOXML Archive Entry, Stream Inflation & XML/RELS Security Inspector
 * Algorithm: Blocks VBA/ActiveX binaries, external workbook links, XXE DOCTYPE/ENTITY declarations,
 *   entity-encoded external/SSRF/NTLM `.rels` targets, and spoofed ZIP compression ratios via stream inflation.
 */
import { StringDecoder } from 'node:string_decoder';
import { BadRequestException } from '@nestjs/common';
import yauzl, { type Entry, type ZipFile } from 'yauzl';
import { AppErrorCode } from '@sda/contracts';

export const MAX_RELS_INSPECT_BYTES = 2 * 1024 * 1024;
const XML_SLIDING_WINDOW_OVERLAP = 4096;

/**
 * Algorithm: OOXML Entry Path Blacklist Verification
 * Blocks executable macro streams (`vbaProject.bin`, `/activex/`) and external workbook data links.
 */
export function inspectOoxmlEntryPathSecurity(
  lowerName: string,
  macroMessage = 'Office document contains prohibited executable macros or ActiveX controls.',
): BadRequestException | null {
  if (
    lowerName.includes('vbaproject.bin') ||
    lowerName.includes('vbadirection') ||
    lowerName.includes('vbadata') ||
    (lowerName.endsWith('.bin') && lowerName.includes('vba')) ||
    lowerName.includes('/activex/')
  ) {
    return new BadRequestException({
      errorCode: AppErrorCode.OFFICE_MACRO_BLOCKED,
      message: macroMessage,
    });
  }

  // CONFLICT-RESOLVED: Unified external workbook link checks across root and nested OOXML paths
  // (`xl/externalLinks/externalLink1.xml` canonical + legacy `externalallink` typo variant).
  if (
    lowerName === 'xl/connections.xml' ||
    /(?:^|\/)external(?:al)?link\d*\.xml$/u.test(lowerName)
  ) {
    return new BadRequestException({
      errorCode: AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
      message: 'Office document contains prohibited external data connections.',
    });
  }

  return null;
}

function decodeXmlEntities(text: string): string {
  return text
    .replace(/&#x([0-9a-f]+);/giu, (_, hex: string) =>
      String.fromCodePoint(Math.min(parseInt(hex, 16), 0x10ffff)),
    )
    .replace(/&#(\d+);/gu, (_, dec: string) =>
      String.fromCodePoint(Math.min(parseInt(dec, 10), 0x10ffff)),
    )
    .replace(/&lt;/giu, '<')
    .replace(/&gt;/giu, '>')
    .replace(/&quot;/giu, '"')
    .replace(/&apos;/giu, "'")
    .replace(/&amp;/giu, '&');
}

function hasProhibitedDoctypeOrEntity(xmlFragment: string): boolean {
  if (/<!\s*(?:doctype|entity)\b/iu.test(xmlFragment)) {
    return true;
  }
  if (xmlFragment.includes('&')) {
    return /<!\s*(?:doctype|entity)\b/iu.test(decodeXmlEntities(xmlFragment));
  }
  return false;
}

/**
 * Algorithm: XML Entity Decoding & XXE / SSRF-NTLM Relationship Guard
 * Rejects `<!DOCTYPE`/`<!ENTITY` across all XML parts and decodes numeric/named character entities
 * in `.rels` parts before matching `TargetMode="External"`, network schemes, and UNC paths.
 */
export function detectMaliciousXmlOrRels(xml: string, isRels: boolean): BadRequestException | null {
  if (hasProhibitedDoctypeOrEntity(xml)) {
    return new BadRequestException({
      errorCode: AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
      message: 'Office XML contains prohibited DOCTYPE or ENTITY declarations (XXE protection).',
    });
  }

  if (!isRels) return null;

  const decoded = decodeXmlEntities(xml);
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

/**
 * Algorithm / Thuật toán: Quét luồng cửa sổ trượt O(1) bộ nhớ chống XXE & Giới hạn cứng Fail-Closed cho `.rels`.
 *   - Với `.rels`: từ chối ngay lập tức (Fail-Closed) nếu kích thước giải nén vượt quá 2 MiB; ngược lại giải mã thực thể và kiểm tra SSRF/NTLM toàn cục khi kết thúc luồng.
 *   - Với `.xml` cỡ lớn bất kỳ: dùng `StringDecoder('utf8')` kết hợp phần đuôi chồng lấp 4 KiB (`XML_SLIDING_WINDOW_OVERLAP`) để phát hiện `<!DOCTYPE` / `<!ENTITY` (kể cả chia cắt qua ranh giới chunk hoặc mã hóa thực thể số) mà không bao giờ bỏ qua tệp XML lớn.
 */
export function createXmlStreamingSecurityScanner(isRels: boolean): {
  push: (chunk: Buffer) => BadRequestException | null;
  finish: () => BadRequestException | null;
} {
  if (isRels) {
    const relsChunks: Buffer[] = [];
    let relsBytes = 0;
    return {
      push(chunk: Buffer): BadRequestException | null {
        relsBytes += chunk.length;
        if (relsBytes > MAX_RELS_INSPECT_BYTES) {
          return new BadRequestException({
            errorCode: AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
            message: `Office relationship (.rels) entry exceeds maximum safe inspection size of ${MAX_RELS_INSPECT_BYTES} bytes.`,
          });
        }
        relsChunks.push(chunk);
        return null;
      },
      finish(): BadRequestException | null {
        if (relsChunks.length === 0) return null;
        return detectMaliciousXmlOrRels(Buffer.concat(relsChunks).toString('utf8'), true);
      },
    };
  }

  const decoder = new StringDecoder('utf8');
  let overlapTail = '';
  return {
    push(chunk: Buffer): BadRequestException | null {
      const decodedChunk = decoder.write(chunk);
      if (!decodedChunk) return null;
      const windowSlice = overlapTail + decodedChunk;
      if (hasProhibitedDoctypeOrEntity(windowSlice)) {
        return new BadRequestException({
          errorCode: AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
          message:
            'Office XML contains prohibited DOCTYPE or ENTITY declarations (XXE protection).',
        });
      }
      overlapTail = windowSlice.slice(-XML_SLIDING_WINDOW_OVERLAP);
      return null;
    },
    finish(): BadRequestException | null {
      const remainder = decoder.end();
      if (!remainder) return null;
      if (hasProhibitedDoctypeOrEntity(overlapTail + remainder)) {
        return new BadRequestException({
          errorCode: AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
          message:
            'Office XML contains prohibited DOCTYPE or ENTITY declarations (XXE protection).',
        });
      }
      return null;
    },
  };
}

/**
 * Algorithm: Lazy-Entry PKZIP Handle Initialization
 * Opens a file path or in-memory buffer with `lazyEntries: true, autoClose: false` for O(1) entry cursoring.
 */
export function openYauzlZip(source: Buffer | string): Promise<ZipFile> {
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

/**
 * Algorithm: Fail-Closed Entry Stream Inflation & Sliding-Window XML/RELS Inspection
 * Counts actual decompressed bytes to defeat spoofed 32-bit ZIP headers and inspects 100% of `.xml`/`.rels` streams without size-based bypass.
 */
export function inflateAndInspectZipEntry(params: {
  zipFile: ZipFile;
  entry: Entry;
  lowerName: string;
  maxTotalUncompressedSize: number;
  maxCompressionRatio: number;
  addActualBytes: (delta: number) => number;
  isSettled: () => boolean;
  finishReject: (err: Error) => void;
}): void {
  const {
    zipFile,
    entry,
    lowerName,
    maxTotalUncompressedSize,
    maxCompressionRatio,
    addActualBytes,
    isSettled,
    finishReject,
  } = params;
  const shouldInspectXml = lowerName.endsWith('.xml') || lowerName.endsWith('.rels');
  const xmlScanner = shouldInspectXml
    ? createXmlStreamingSecurityScanner(lowerName.endsWith('.rels'))
    : null;
  let entryActualBytes = 0;

  zipFile.openReadStream(entry, (streamErr, readStream) => {
    if (isSettled()) return;
    if (streamErr || !readStream) {
      return finishReject(
        new BadRequestException({
          errorCode: AppErrorCode.INVALID_FILE_TYPE,
          message: `Failed to read zip entry ${entry.fileName}: ${streamErr?.message ?? 'corrupt stream'}`,
        }),
      );
    }

    readStream.on('data', (chunk: Buffer) => {
      if (isSettled()) {
        readStream.destroy();
        return;
      }
      entryActualBytes += chunk.length;
      const actualTotal = addActualBytes(chunk.length);
      if (actualTotal > maxTotalUncompressedSize) {
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
      if (xmlScanner) {
        const xmlIssue = xmlScanner.push(chunk);
        if (xmlIssue) {
          readStream.destroy();
          return finishReject(xmlIssue);
        }
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
      if (isSettled()) return;
      if (xmlScanner) {
        const finalIssue = xmlScanner.finish();
        if (finalIssue) return finishReject(finalIssue);
      }
      zipFile.readEntry();
    });
  });
}

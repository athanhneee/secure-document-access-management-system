/**
 * Module: OOXML Multi-Encoding Streaming XML & `.rels` Security Scanner Helper
 * Thuật toán: Quét Luồng Cửa Sổ Trượt O(1) Bộ Nhớ Hỗ Trợ UTF-8 / UTF-16LE / UTF-16BE Chống XXE & SSRF/NTLM.
 *   1. Nhận diện bảng mã XML theo chuẩn W3C Appendix F từ 4 byte đầu (từ chối Fail-Closed bảng mã phi chuẩn UCS-4/UTF-32).
 *   2. Giải mã thực thể ký tự số (`&#x...;`, `&#...;`) và loại bỏ byte `\0` xen kẽ để phát hiện khai báo `<!DOCTYPE` / `<!ENTITY` (chống XXE / Billion Laughs).
 *   3. Với mục `.rels`, giới hạn cứng 2 MiB và chặn mọi `TargetMode="External"` hoặc giao thức mạng ngoài / đường dẫn UNC (`\\\\`, `//`).
 */
import { TextDecoder } from 'node:util';
import { BadRequestException } from '@nestjs/common';
import { AppErrorCode } from '@sda/contracts';

export const MAX_RELS_INSPECT_BYTES = 2 * 1024 * 1024;
const XML_SLIDING_WINDOW_OVERLAP = 4096;

/**
 * Thuật toán: Giải mã thực thể ký tự số thập lục phân/thập phân và thực thể định danh chuẩn XML.
 */
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

function matchesDoctypeOrEntity(candidate: string): boolean {
  if (/<!\s*(?:doctype|entity)\b/iu.test(candidate)) {
    return true;
  }
  if (candidate.includes('&')) {
    return /<!\s*(?:doctype|entity)\b/iu.test(decodeXmlEntities(candidate));
  }
  return false;
}

/**
 * Thuật toán: Phát hiện khai báo `<!DOCTYPE` hoặc `<!ENTITY` trực tiếp, ẩn sau thực thể XML hoặc chèn byte `\0`.
 */
export function hasProhibitedDoctypeOrEntity(xmlFragment: string): boolean {
  if (matchesDoctypeOrEntity(xmlFragment)) {
    return true;
  }
  if (xmlFragment.includes('\0')) {
    return matchesDoctypeOrEntity(xmlFragment.replace(/\0+/gu, ''));
  }
  return false;
}

/**
 * Thuật toán: Nhận diện bảng mã XML theo chuẩn W3C XML Appendix F (UTF-8, UTF-16LE, UTF-16BE; từ chối UTF-32/UCS-4).
 */
function detectXmlEncodingFromPrefix(prefix: Buffer): {
  encoding: 'utf-8' | 'utf-16le' | 'utf-16be';
  bomOffset: number;
  unsupportedUcs4: boolean;
} {
  if (prefix.length >= 4) {
    const b0 = prefix[0]!;
    const b1 = prefix[1]!;
    const b2 = prefix[2]!;
    const b3 = prefix[3]!;
    if (
      (b0 === 0xff && b1 === 0xfe && b2 === 0x00 && b3 === 0x00) ||
      (b0 === 0x00 && b1 === 0x00 && b2 === 0xfe && b3 === 0xff) ||
      (b0 !== 0x00 && b1 === 0x00 && b2 === 0x00 && b3 === 0x00) ||
      (b0 === 0x00 && b1 === 0x00 && b2 === 0x00 && b3 !== 0x00)
    ) {
      return { encoding: 'utf-8', bomOffset: 0, unsupportedUcs4: true };
    }
  }
  if (prefix.length >= 3 && prefix[0] === 0xef && prefix[1] === 0xbb && prefix[2] === 0xbf) {
    return { encoding: 'utf-8', bomOffset: 3, unsupportedUcs4: false };
  }
  if (prefix.length >= 2) {
    if (prefix[0] === 0xff && prefix[1] === 0xfe) {
      return { encoding: 'utf-16le', bomOffset: 2, unsupportedUcs4: false };
    }
    if (prefix[0] === 0xfe && prefix[1] === 0xff) {
      return { encoding: 'utf-16be', bomOffset: 2, unsupportedUcs4: false };
    }
    if (prefix[0] !== 0x00 && prefix[1] === 0x00) {
      return { encoding: 'utf-16le', bomOffset: 0, unsupportedUcs4: false };
    }
    if (prefix[0] === 0x00 && prefix[1] !== 0x00) {
      return { encoding: 'utf-16be', bomOffset: 0, unsupportedUcs4: false };
    }
  }
  return { encoding: 'utf-8', bomOffset: 0, unsupportedUcs4: false };
}

function decodeXmlBufferAware(rawBuffer: Buffer): { text: string; unsupportedUcs4: boolean } {
  const detected = detectXmlEncodingFromPrefix(rawBuffer);
  if (detected.unsupportedUcs4) {
    return { text: '', unsupportedUcs4: true };
  }
  const decoder = new TextDecoder(detected.encoding, { fatal: false });
  return {
    text: decoder.decode(rawBuffer.subarray(detected.bomOffset)),
    unsupportedUcs4: false,
  };
}

/**
 * Thuật toán: Chốt chặn XXE và liên kết quan hệ ngoài SSRF/NTLM trên nội dung XML/`.rels` của OOXML.
 */
export function detectMaliciousXmlOrRels(xml: string, isRels: boolean): BadRequestException | null {
  if (hasProhibitedDoctypeOrEntity(xml)) {
    return new BadRequestException({
      errorCode: AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
      message: 'Office XML contains prohibited DOCTYPE or ENTITY declarations (XXE protection).',
    });
  }

  if (!isRels) return null;

  const candidates = xml.includes('\0') ? [xml, xml.replace(/\0+/gu, '')] : [xml];
  for (const candidate of candidates) {
    const decoded = decodeXmlEntities(candidate);
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
  }

  return null;
}

/**
 * Thuật toán: Quét luồng cửa sổ trượt 4 KiB O(1) bộ nhớ hỗ trợ đa bảng mã chống XXE & Giới hạn cứng 2 MiB cho `.rels`.
 */
export function createXmlStreamingSecurityScanner(isRels: boolean): {
  push: (chunk: Buffer) => BadRequestException | null;
  finish: () => BadRequestException | null;
} {
  const unsupportedEncodingError = () =>
    new BadRequestException({
      errorCode: AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
      message: 'Office XML uses prohibited UCS-4/UTF-32 encoding.',
    });

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
        const decoded = decodeXmlBufferAware(Buffer.concat(relsChunks));
        if (decoded.unsupportedUcs4) return unsupportedEncodingError();
        return detectMaliciousXmlOrRels(decoded.text, true);
      },
    };
  }

  let decoder: TextDecoder | null = null;
  let prefixBuffer: Buffer = Buffer.alloc(0);
  let overlapTail = '';
  const inspectDecodedSlice = (decodedChunk: string): BadRequestException | null => {
    if (!decodedChunk) return null;
    const windowSlice = overlapTail + decodedChunk;
    if (hasProhibitedDoctypeOrEntity(windowSlice)) {
      return new BadRequestException({
        errorCode: AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
        message: 'Office XML contains prohibited DOCTYPE or ENTITY declarations (XXE protection).',
      });
    }
    overlapTail = windowSlice.slice(-XML_SLIDING_WINDOW_OVERLAP);
    return null;
  };
  return {
    push(chunk: Buffer): BadRequestException | null {
      let toDecode = chunk;
      if (!decoder) {
        prefixBuffer = prefixBuffer.length > 0 ? Buffer.concat([prefixBuffer, chunk]) : chunk;
        if (prefixBuffer.length < 4) return null;
        const detected = detectXmlEncodingFromPrefix(prefixBuffer);
        if (detected.unsupportedUcs4) return unsupportedEncodingError();
        decoder = new TextDecoder(detected.encoding, { fatal: false });
        toDecode = prefixBuffer.subarray(detected.bomOffset);
        prefixBuffer = Buffer.alloc(0);
      }
      return inspectDecodedSlice(decoder.decode(toDecode, { stream: true }));
    },
    finish(): BadRequestException | null {
      if (!decoder) {
        if (prefixBuffer.length === 0) return null;
        const decoded = decodeXmlBufferAware(prefixBuffer);
        if (decoded.unsupportedUcs4) return unsupportedEncodingError();
        return inspectDecodedSlice(decoded.text);
      }
      return inspectDecodedSlice(decoder.decode());
    },
  };
}

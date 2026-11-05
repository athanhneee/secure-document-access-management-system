/**
 * Module: OOXML Archive Entry & XML/RELS Security Inspector
 * Thuật toán: Chặn thực thi macro VBA/ActiveX, liên kết sổ tính ngoài, khai báo thực thể XXE (`<!DOCTYPE`/`<!ENTITY`)
 *   và đích `.rels` mã hóa thực thể gây SSRF/NTLM thông qua bộ quét luồng cửa sổ trượt O(1) bộ nhớ.
 */
import { TextDecoder } from 'node:util';
import { BadRequestException } from '@nestjs/common';
import { AppErrorCode } from '@sda/contracts';

export { inflateAndInspectZipEntry, openYauzlZip } from './zip-entry-inflation.helper.js';

export const MAX_RELS_INSPECT_BYTES = 2 * 1024 * 1024;
const XML_SLIDING_WINDOW_OVERLAP = 4096;

/**
 * Thuật toán: Chuẩn hóa đường dẫn mục ZIP sang dấu gạch chéo xuôi `/` chữ thường thống nhất.
 * Chặn kỹ thuật dùng dấu gạch chéo ngược `\` kiểu Windows (`word\activeX\...`, `xl\connections.xml`) để lách bộ lọc đường dẫn (CRIT-05).
 */
export function normalizeArchiveEntryPath(fileName: string): string {
  return fileName.replace(/\\+/gu, '/').toLowerCase();
}

/**
 * Thuật toán: Kiểm định chống leo thang thư mục Zip-Slip (`..`, đường dẫn tuyệt đối, ổ đĩa Windows, byte rỗng `\0`).
 */
export function inspectArchiveEntryPathTraversal(fileName: string): BadRequestException | null {
  if (
    fileName.includes('\0') ||
    fileName.startsWith('/') ||
    fileName.startsWith('\\') ||
    /^[a-zA-Z]:/u.test(fileName)
  ) {
    return new BadRequestException({
      errorCode: AppErrorCode.INVALID_FILE_TYPE,
      message: 'Zip archive contains dangerous path traversal entry names.',
    });
  }

  const segments = fileName.split(/[/\\]+/u).filter((seg) => seg.length > 0);
  if (segments.includes('..')) {
    return new BadRequestException({
      errorCode: AppErrorCode.INVALID_FILE_TYPE,
      message: 'Zip archive contains dangerous path traversal entry names.',
    });
  }

  return null;
}

/**
 * Thuật toán: Kiểm tra danh sách đen đường dẫn thành phần gói OOXML sau khi chuẩn hóa `\` thành `/`.
 * Chặn tệp nhị phân macro thực thi (`vbaProject.bin`, `/activex/`) và cấu hình kết nối dữ liệu ngoài (`xl/connections.xml`, `externalLink*.xml`).
 */
export function inspectOoxmlEntryPathSecurity(
  rawOrLowerName: string,
  macroMessage = 'Office document contains prohibited executable macros or ActiveX controls.',
): BadRequestException | null {
  const traversalIssue = inspectArchiveEntryPathTraversal(rawOrLowerName);
  if (traversalIssue) return traversalIssue;

  // CONFLICT-RESOLVED: Chuẩn hóa mọi dấu gạch chéo ngược \ sang / trước khi đối chiếu danh sách đen OOXML (CRIT-05).
  const lowerName = normalizeArchiveEntryPath(rawOrLowerName);
  if (
    lowerName.includes('vbaproject.bin') ||
    lowerName.includes('vbadirection') ||
    lowerName.includes('vbadata') ||
    (lowerName.endsWith('.bin') && lowerName.includes('vba')) ||
    lowerName.includes('/activex/') ||
    lowerName.startsWith('activex/')
  ) {
    return new BadRequestException({
      errorCode: AppErrorCode.OFFICE_MACRO_BLOCKED,
      message: macroMessage,
    });
  }

  // CONFLICT-RESOLVED: Hợp nhất kiểm tra đường dẫn liên kết ngoài OOXML ở cả gốc và thư mục lồng nhau.
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

/**
 * Thuật toán: Giải mã thực thể ký tự số thập lục phân/thập phân và thực thể định danh chuẩn XML.
 * Chặn kỹ thuật ẩn dấu khai báo DTD/XXE hoặc giao thức mạng bên trong thuộc tính `Target` bằng mã hóa `&#x...;` / `&#...;`.
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
 * Thuật toán: Phát hiện khai báo `<!DOCTYPE` hoặc `<!ENTITY` trực tiếp, ẩn sau thực thể XML hoặc chèn byte `\0` chống tấn công XXE / Billion Laughs.
 */
function hasProhibitedDoctypeOrEntity(xmlFragment: string): boolean {
  if (matchesDoctypeOrEntity(xmlFragment)) {
    return true;
  }
  if (xmlFragment.includes('\0')) {
    return matchesDoctypeOrEntity(xmlFragment.replace(/\0+/gu, ''));
  }
  return false;
}

/**
 * Thuật toán: Nhận diện bảng mã XML theo chuẩn W3C XML Appendix F (UTF-8, UTF-16LE, UTF-16BE có hoặc không có BOM; từ chối UTF-32 phi chuẩn OOXML).
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
 * Thuật toán: Chốt chặn XXE và liên kết quan hệ ngoài SSRF/NTLM trên nội dung XML/`.rels` của OOXML (kể cả khi chứa byte `\0` xen kẽ).
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
 * Thuật toán: Quét luồng cửa sổ trượt O(1) bộ nhớ hỗ trợ đa bảng mã UTF-8/UTF-16LE/UTF-16BE chống XXE & Giới hạn cứng Fail-Closed cho `.rels`.
 *   - Với `.rels`: từ chối ngay lập tức (Fail-Closed) nếu kích thước giải nén vượt quá 2 MiB; tự động phát hiện UTF-8/UTF-16LE/UTF-16BE (có/không BOM) để chặn SSRF/NTLM.
 *   - Với `.xml` cỡ lớn bất kỳ: lấy mẫu 4 byte đầu nhận diện UTF-8/UTF-16LE/UTF-16BE (từ chối UCS-4/UTF-32), giải mã luồng `TextDecoder(..., { stream: true })` kết hợp cửa sổ trượt 4 KiB.
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
        // CONFLICT-RESOLVED: Giải mã nhận diện UTF-16LE/BE bên cạnh UTF-8 cho tệp .rels để chặn bypass SSRF/XXE qua byte \x00 (CRIT-05).
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

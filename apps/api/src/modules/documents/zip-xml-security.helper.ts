/**
 * Module: OOXML Archive Entry & XML/RELS Security Inspector
 * Thuật toán: Chặn thực thi macro VBA/ActiveX, liên kết sổ tính ngoài, khai báo thực thể XXE (`<!DOCTYPE`/`<!ENTITY`)
 *   và đích `.rels` mã hóa thực thể gây SSRF/NTLM thông qua bộ quét luồng cửa sổ trượt O(1) bộ nhớ.
 */
import { StringDecoder } from 'node:string_decoder';
import { BadRequestException } from '@nestjs/common';
import { AppErrorCode } from '@sda/contracts';

export { inflateAndInspectZipEntry, openYauzlZip } from './zip-entry-inflation.helper.js';

export const MAX_RELS_INSPECT_BYTES = 2 * 1024 * 1024;
const XML_SLIDING_WINDOW_OVERLAP = 4096;

/**
 * Thuật toán: Kiểm tra danh sách đen đường dẫn thành phần gói OOXML.
 * Chặn tệp nhị phân macro thực thi (`vbaProject.bin`, `/activex/`) và cấu hình kết nối dữ liệu ngoài (`xl/connections.xml`, `externalLink*.xml`).
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

/**
 * Thuật toán: Phát hiện khai báo `<!DOCTYPE` hoặc `<!ENTITY` trực tiếp hoặc ẩn sau thực thể XML chống tấn công XXE / Billion Laughs.
 */
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
 * Thuật toán: Quét luồng cửa sổ trượt O(1) bộ nhớ chống XXE & Giới hạn cứng Fail-Closed cho `.rels`.
 *   - Với `.rels`: từ chối ngay lập tức (Fail-Closed) nếu kích thước giải nén vượt quá 2 MiB; ngược lại giải mã thực thể và kiểm tra SSRF/NTLM toàn cục khi kết thúc luồng.
 *   - Với `.xml` cỡ lớn bất kỳ: dùng `StringDecoder('utf8')` kết hợp phần đuôi chồng lấp 4 KiB (`XML_SLIDING_WINDOW_OVERLAP`) để phát hiện `<!DOCTYPE` / `<!ENTITY` chia cắt qua ranh giới chunk.
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

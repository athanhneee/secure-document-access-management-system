/**
 * Module: OOXML Archive Entry Path & Blacklist Security Inspector
 * Thuật toán: Chuẩn Hóa Đường Dẫn PKZIP Chống Zip-Slip & Danh Sách Đen Macro/ActiveX/Liên Kết Ngoài OOXML.
 *   1. Chuẩn hóa mọi dấu gạch chéo ngược `\` kiểu Windows sang `/` chữ thường để chặn lách bộ lọc đường dẫn.
 *   2. Kiểm tra leo thang thư mục (`..`, đường dẫn gốc `/`, ổ đĩa Windows, ký tự rỗng `\0`).
 *   3. Chặn tệp thực thi macro VBA (`vbaProject.bin`, `/activex/`) và tệp kết nối dữ liệu ngoài (`xl/connections.xml`, `externalLink*.xml`).
 */
import { BadRequestException } from '@nestjs/common';
import { AppErrorCode } from '@sda/contracts';

export { inflateAndInspectZipEntry, openYauzlZip } from './zip-entry-inflation.helper.js';
export {
  MAX_RELS_INSPECT_BYTES,
  createXmlStreamingSecurityScanner,
  detectMaliciousXmlOrRels,
  hasProhibitedDoctypeOrEntity,
} from './zip-xml-stream-scanner.helper.js';

/**
 * Thuật toán: Chuẩn hóa đường dẫn mục ZIP sang dấu gạch chéo xuôi `/` chữ thường thống nhất.
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
 */
export function inspectOoxmlEntryPathSecurity(
  rawOrLowerName: string,
  macroMessage = 'Office document contains prohibited executable macros or ActiveX controls.',
): BadRequestException | null {
  const traversalIssue = inspectArchiveEntryPathTraversal(rawOrLowerName);
  if (traversalIssue) return traversalIssue;

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

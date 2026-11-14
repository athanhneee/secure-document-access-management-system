import { deflateRawSync } from 'node:zlib';

/**
 * Thuật toán / Tổng quan module:
 * Bộ đóng gói sổ tính OpenXML SpreadsheetML (`.xlsx` chuẩn ECMA-376 / ISO/IEC 29500) không phụ thuộc thư viện ngoài:
 * - Tính mã kiểm tra dư vòng IEEE 802.3 `CRC-32` (`0xEDB88320`) bằng bảng tra cứu 256 phần tử tiền tính toán `O(N)`.
 * - Nén từng thành phần XML (`[Content_Types].xml`, `_rels/.rels`, `xl/workbook.xml`, `xl/_rels/workbook.xml.rels`,
 *   `xl/worksheets/sheet1.xml`) bằng `zlib.deflateRawSync` và dựng khung lưu trữ ZIP (Local File Header + Central Directory + EOCD).
 * - Ghi toàn bộ ô dữ liệu dưới dạng chuỗi nội tuyến `<c r="..." t="inlineStr"><is><t xml:space="preserve">...</t></is></c>`
 *   kết hợp khử độc công thức bảng tính (Formula Injection Defense).
 */

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let crc = i;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 1) !== 0 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
    }
    table[i] = crc >>> 0;
  }
  return table;
})();

/**
 * Thuật toán: Tính mã kiểm tra `CRC-32` chuẩn PKZIP/IEEE 802.3 trên bộ đệm nhị phân với độ phức tạp `O(N)`.
 */
function computeCrc32(buffer: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buffer.length; i += 1) {
    const byte = buffer[i]!;
    crc = CRC32_TABLE[(crc ^ byte) & 0xff]! ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function stripIllegalXmlChars(input: string): string {
  let out = '';
  for (let i = 0; i < input.length; i += 1) {
    const code = input.charCodeAt(i);
    if (code >= 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) {
      out += input[i];
    }
  }
  return out;
}

function escapeXml(input: string): string {
  return stripIllegalXmlChars(input)
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/"/gu, '&quot;')
    .replace(/'/gu, '&apos;');
}

/**
 * Thuật toán: Chuyển đổi chỉ số cột 0-based sang ký hiệu cột bảng tính hệ 26 bijective (`0 -> A`, `25 -> Z`, `26 -> AA`).
 */
function toSpreadsheetColumnRef(colIndex: number): string {
  let current = colIndex + 1;
  let ref = '';
  while (current > 0) {
    const remainder = (current - 1) % 26;
    ref = String.fromCharCode(65 + remainder) + ref;
    current = Math.floor((current - 1) / 26);
  }
  return ref;
}

function sanitizeSheetName(rawName: string): string {
  const cleaned = stripIllegalXmlChars(rawName)
    .replace(/[:\\/?*[\]]/gu, '_')
    .trim()
    .slice(0, 31);
  return cleaned.length > 0 ? cleaned : 'Export';
}

interface ZipArchiveEntry {
  path: string;
  content: Buffer;
}

/**
 * Thuật toán: Dựng gói lưu trữ PKZIP 2.0 tối giản dùng phương thức nén Deflate (`method = 8`) từ danh sách tệp trong bộ nhớ.
 */
function buildDeflatedZipArchive(entries: ZipArchiveEntry[]): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let localOffset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.path, 'utf8');
    const uncompressed = entry.content;
    const compressed = deflateRawSync(uncompressed);
    const crc = computeCrc32(uncompressed);

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(8, 8);
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0x0021, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compressed.byteLength, 18);
    localHeader.writeUInt32LE(uncompressed.byteLength, 22);
    localHeader.writeUInt16LE(nameBuf.byteLength, 26);
    localHeader.writeUInt16LE(0, 28);

    localParts.push(localHeader, nameBuf, compressed);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0, 8);
    centralHeader.writeUInt16LE(8, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0x0021, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(compressed.byteLength, 20);
    centralHeader.writeUInt32LE(uncompressed.byteLength, 24);
    centralHeader.writeUInt16LE(nameBuf.byteLength, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(localOffset, 42);

    centralParts.push(centralHeader, nameBuf);
    localOffset += localHeader.byteLength + nameBuf.byteLength + compressed.byteLength;
  }

  const centralDirBuffer = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirBuffer.byteLength, 12);
  eocd.writeUInt32LE(localOffset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralDirBuffer, eocd]);
}

/**
 * Thuật toán: Tạo bộ đệm tệp `.xlsx` chuẩn OOXML gồm 5 thành phần XML tối giản với ô `inlineStr` đã khử công thức độc hại.
 */
export function buildOoxmlXlsxBuffer(
  sheetTitle: string,
  columns: string[],
  rows: Record<string, unknown>[],
  sanitizeCell: (value: unknown) => string,
): Buffer {
  const colRefs = columns.map((_, idx) => toSpreadsheetColumnRef(idx));
  const sheetRowsXml: string[] = [];

  const headerCellsXml = columns
    .map(
      (col, idx) =>
        `<c r="${colRefs[idx]!}1" t="inlineStr"><is><t xml:space="preserve">${escapeXml(sanitizeCell(col))}</t></is></c>`,
    )
    .join('');
  sheetRowsXml.push(`<row r="1">${headerCellsXml}</row>`);

  for (let rowIdx = 0; rowIdx < rows.length; rowIdx += 1) {
    const row = rows[rowIdx]!;
    const excelRowNum = rowIdx + 2;
    const cellsXml = columns
      .map(
        (col, colIdx) =>
          `<c r="${colRefs[colIdx]!}${excelRowNum}" t="inlineStr"><is><t xml:space="preserve">${escapeXml(sanitizeCell(row[col]))}</t></is></c>`,
      )
      .join('');
    sheetRowsXml.push(`<row r="${excelRowNum}">${cellsXml}</row>`);
  }

  const contentTypesXml = [
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
    '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
    '  <Default Extension="xml" ContentType="application/xml"/>',
    '  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
    '  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>',
    '</Types>',
  ].join('');

  const rootRelsXml = [
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">',
    '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>',
    '</Relationships>',
  ].join('');

  const workbookXml = [
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
    '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">',
    '  <sheets>',
    `    <sheet name="${escapeXml(sanitizeSheetName(sheetTitle))}" sheetId="1" r:id="rId1"/>`,
    '  </sheets>',
    '</workbook>',
  ].join('');

  const workbookRelsXml = [
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">',
    '  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>',
    '</Relationships>',
  ].join('');

  const sheetXml = [
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
    `  <sheetData>${sheetRowsXml.join('')}</sheetData>`,
    '</worksheet>',
  ].join('');

  return buildDeflatedZipArchive([
    { path: '[Content_Types].xml', content: Buffer.from(contentTypesXml, 'utf8') },
    { path: '_rels/.rels', content: Buffer.from(rootRelsXml, 'utf8') },
    { path: 'xl/workbook.xml', content: Buffer.from(workbookXml, 'utf8') },
    { path: 'xl/_rels/workbook.xml.rels', content: Buffer.from(workbookRelsXml, 'utf8') },
    { path: 'xl/worksheets/sheet1.xml', content: Buffer.from(sheetXml, 'utf8') },
  ]);
}

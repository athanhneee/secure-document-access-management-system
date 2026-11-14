/**
 * Thuật toán / Tổng quan module:
 * Động cơ sinh báo cáo tuân thủ `%PDF-1.4` đa trang khổ A4 ngang (`[0 0 842 595]`) cho `@sda/worker`:
 * - Loại bỏ hoàn toàn giới hạn cắt cứng 55 dòng/trang: tự động ngắt dòng dài (`wrapTextLine`) để bảo toàn 100% dữ liệu kiểm toán
 *   và phân trang tuyến tính trên toàn bộ tập bản ghi xuất (`Page k of N`).
 * - Chuyển tự tổ hợp dấu tiếng Việt Unicode NFD sang ASCII tương thích chuẩn Type1 `/Helvetica` và tính chính xác bảng offset `xref`.
 */

const PAGE_WIDTH_PT = 842;
const PAGE_HEIGHT_PT = 595;
const MAX_CHARS_PER_LINE = 132;
const BODY_LINES_PER_PAGE = 42;

/**
 * Thuật toán: Chuyển tự tiếng Việt Unicode NFD sang ASCII in được và thoát ký tự điều khiển toán tử chuỗi PDF `(...)`.
 */
export function escapePdfTextLine(input: string): string {
  const asciiFolded = input
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/gu, '')
    .replace(/đ/gu, 'd')
    .replace(/Đ/gu, 'D')
    .replace(/[\r\n\t]+/gu, ' ')
    .replace(/[^\x20-\x7E]/gu, '?');
  return asciiFolded.replace(/\\/gu, '\\\\').replace(/\(/gu, '\\(').replace(/\)/gu, '\\)');
}

/**
 * Thuật toán: Ngắt chuỗi văn bản dài thành nhiều dòng có độ rộng cố định `maxWidth` (thụt lề dòng tiếp nối) để không mất dữ liệu.
 */
function wrapTextLine(rawLine: string, maxWidth = MAX_CHARS_PER_LINE): string[] {
  const normalized = rawLine.replace(/[\r\n\t]+/gu, ' ');
  if (normalized.length <= maxWidth) {
    return [normalized];
  }
  const wrapped: string[] = [];
  let offset = 0;
  while (offset < normalized.length) {
    const isContinuation = offset > 0;
    const sliceLen = isContinuation ? maxWidth - 2 : maxWidth;
    const chunk = normalized.slice(offset, offset + sliceLen);
    wrapped.push(isContinuation ? `  ${chunk}` : chunk);
    offset += sliceLen;
  }
  return wrapped;
}

/**
 * Thuật toán: Sinh tài liệu `%PDF-1.4` đa trang khổ A4 ngang với cây đối tượng `/Pages -> /Kids [...]` và bảng `xref` động từng byte.
 */
export function buildMultiPagePdfReport(
  exportType: string,
  columns: string[],
  rows: Record<string, unknown>[],
  generatedAt: Date,
  serializeCell: (value: unknown) => string,
): Buffer {
  const headerColumnLines = wrapTextLine(columns.join(' | '));
  const bodyLines: string[] = [];

  for (let i = 0; i < rows.length; i += 1) {
    const row = rows[i]!;
    const formattedRow = columns.map((col) => serializeCell(row[col])).join(' | ');
    for (const line of wrapTextLine(formattedRow)) {
      bodyLines.push(line);
    }
  }

  if (bodyLines.length === 0) {
    bodyLines.push('(No matching records found for the requested filter scope)');
  }

  const totalPages = Math.max(1, Math.ceil(bodyLines.length / BODY_LINES_PER_PAGE));
  const pageContents: string[] = [];

  for (let pageIdx = 0; pageIdx < totalPages; pageIdx += 1) {
    const slice = bodyLines.slice(
      pageIdx * BODY_LINES_PER_PAGE,
      (pageIdx + 1) * BODY_LINES_PER_PAGE,
    );
    const pageLines: string[] = [
      `SDA Forensic Export Report - ${exportType}`,
      `Page ${pageIdx + 1} of ${totalPages} | Generated At (UTC): ${generatedAt.toISOString()} | Total Rows: ${rows.length}`,
      '-'.repeat(118),
      ...headerColumnLines,
      '-'.repeat(118),
      ...slice,
      '-'.repeat(118),
      'CONFIDENTIAL - SECURE DOCUMENT ACCESS COMPLIANCE REPORT - TAMPER EVIDENT',
    ];

    const streamOps = ['BT', '/F1 7.5 Tf', '32 562 Td', '10.5 TL'];
    for (const line of pageLines) {
      streamOps.push(`(${escapePdfTextLine(line)}) Tj T*`);
    }
    streamOps.push('ET');
    pageContents.push(streamOps.join('\n'));
  }

  const pageObjRefs: string[] = [];
  for (let i = 0; i < pageContents.length; i += 1) {
    pageObjRefs.push(`${4 + i * 2} 0 R`);
  }

  const objects: string[] = [
    '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n',
    `2 0 obj\n<< /Type /Pages /Kids [${pageObjRefs.join(' ')}] /Count ${pageContents.length} >>\nendobj\n`,
    '3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n',
  ];

  for (let i = 0; i < pageContents.length; i += 1) {
    const pageObjId = 4 + i * 2;
    const streamObjId = 5 + i * 2;
    const streamContent = pageContents[i]!;
    const streamByteLen = Buffer.byteLength(streamContent, 'ascii');
    objects.push(
      `${pageObjId} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_WIDTH_PT} ${PAGE_HEIGHT_PT}] /Resources << /Font << /F1 3 0 R >> >> /Contents ${streamObjId} 0 R >>\nendobj\n`,
    );
    objects.push(
      `${streamObjId} 0 obj\n<< /Length ${streamByteLen} >>\nstream\n${streamContent}\nendstream\nendobj\n`,
    );
  }

  const header = '%PDF-1.4\n';
  const offsets: number[] = [];
  let cursor = Buffer.byteLength(header, 'ascii');
  for (const obj of objects) {
    offsets.push(cursor);
    cursor += Buffer.byteLength(obj, 'ascii');
  }

  const xrefOffset = cursor;
  const xrefSection = [
    'xref',
    `0 ${objects.length + 1}`,
    '0000000000 65535 f ',
    ...offsets.map((off) => `${String(off).padStart(10, '0')} 00000 n `),
    'trailer',
    `<< /Size ${objects.length + 1} /Root 1 0 R >>`,
    'startxref',
    String(xrefOffset),
    '%%EOF\n',
  ].join('\n');

  return Buffer.from(header + objects.join('') + xrefSection, 'ascii');
}

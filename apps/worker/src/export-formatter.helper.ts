/**
 * Thuật toán / Tổng quan module:
 * Bộ định dạng dữ liệu kết xuất bất đồng bộ (`CSV`, `JSON`, `EXCEL`, `PDF`) cho `ExportProcessorJob`:
 * - Chống tấn công tiêm công thức bảng tính (CSV/Excel Formula Injection / DDE) bao phủ khoảng trắng đầu dòng và `=`, `+`, `-`, `@`, `|`, `\t`, `\r`, `\n`.
 * - Dựng tài liệu XML SpreadsheetML sạch và tài liệu `%PDF-1.4` chuẩn xác bảng tham chiếu chéo `xref` không phụ thuộc thư viện ngoài.
 */

export type SupportedExportFormat = 'CSV' | 'JSON' | 'EXCEL' | 'PDF';

export interface FormattedExportArtifact {
  buffer: Buffer;
  mimeType: string;
  extension: string;
}

const FORMULA_DANGEROUS_RE = /^(?:[\t\r\n]|\s*[=+\-@|])|[\r\n]\s*[=+\-@|]/u;

function stripIllegalXmlControlChars(input: string): string {
  let out = '';
  for (let i = 0; i < input.length; i += 1) {
    const code = input.charCodeAt(i);
    if (code >= 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) {
      out += input[i];
    }
  }
  return out;
}

function serializeValue(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (value instanceof Date) return value.toISOString();
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'object') {
    return JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
  }
  return String(value);
}

/**
 * Thuật toán: Khử Độc Tiêm Công Thức Bảng Tính (Spreadsheet Formula / DDE Injection Sanitizer).
 * Mọi chuỗi bắt đầu bằng `\t`, `\r`, `\n` hoặc khoảng trắng tùy ý theo sau bởi `=`, `+`, `-`, `@`, `|`
 * đều được tiền tố hóa bằng dấu nháy đơn `'` và phẳng hóa ký tự xuống dòng nội bộ để ngăn thực thi lệnh DDE.
 */
export function sanitizeSpreadsheetCell(value: unknown): string {
  const raw = serializeValue(value);
  if (raw.length === 0) return '';
  const flattened = raw.replace(/[\r\n]+/gu, ' ');
  if (FORMULA_DANGEROUS_RE.test(raw) || FORMULA_DANGEROUS_RE.test(flattened)) {
    return `'${flattened}`;
  }
  return flattened;
}

function escapeCsvCell(value: unknown): string {
  const safe = sanitizeSpreadsheetCell(value);
  if (/[",\t\r\n;|]/u.test(safe) || safe.startsWith(' ') || safe.endsWith(' ')) {
    return `"${safe.replace(/"/gu, '""')}"`;
  }
  return safe;
}

function escapeXml(input: string): string {
  return stripIllegalXmlControlChars(input)
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/"/gu, '&quot;')
    .replace(/'/gu, '&apos;');
}

/**
 * Thuật toán: Chuyển tự ASCII an toàn và thoát ký tự điều khiển toán tử chuỗi PDF `(...)` (`\`, `(`, `)`).
 */
export function escapePdfTextLine(input: string): string {
  const asciiFolded = input
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/gu, '')
    .replace(/đ/gu, 'd')
    .replace(/Đ/gu, 'D')
    .replace(/[^\x20-\x7E]/gu, '?');
  return asciiFolded.replace(/\\/gu, '\\\\').replace(/\(/gu, '\\(').replace(/\)/gu, '\\)');
}

function resolveColumns(exportType: string, rows: Record<string, unknown>[]): string[] {
  const defaultsByType: Record<string, string[]> = {
    AUDIT_LOGS: [
      'id',
      'occurred_at',
      'actor_user_id',
      'actor_username',
      'action',
      'object_type',
      'object_id',
      'document_id',
      'outcome',
      'chain_partition',
      'chain_sequence',
    ],
    SECURITY_ALERTS: [
      'id',
      'detected_at',
      'alert_type',
      'severity',
      'status',
      'title',
      'detected_user_id',
      'document_id',
    ],
    INCIDENT_REPORTS: [
      'id',
      'incident_code',
      'status',
      'title',
      'summary',
      'prepared_by',
      'alert_id',
      'created_at',
    ],
    SYSTEM_REPORT: ['metric', 'value', 'captured_at'],
  };
  const colSet = new Set<string>(defaultsByType[exportType] ?? []);
  for (const row of rows.slice(0, 25)) {
    for (const key of Object.keys(row)) colSet.add(key);
  }
  return colSet.size > 0 ? [...colSet] : ['id'];
}

/**
 * Thuật toán: Sinh tài liệu báo cáo `%PDF-1.4` tối giản hợp lệ với bảng offset `xref` tính động chính xác từng byte.
 */
function buildMinimalPdfReport(
  exportType: string,
  columns: string[],
  rows: Record<string, unknown>[],
  generatedAt: Date,
): Buffer {
  const textLines: string[] = [
    `SDA Forensic Export Report - ${exportType}`,
    `Generated At (UTC): ${generatedAt.toISOString()} | Total Rows: ${rows.length}`,
    '-'.repeat(92),
    columns.join(' | ').slice(0, 110),
    '-'.repeat(92),
  ];

  for (const row of rows.slice(0, 55)) {
    const line = columns
      .map((col) => serializeValue(row[col]))
      .join(' | ')
      .slice(0, 110);
    textLines.push(line);
  }
  if (rows.length > 55) {
    textLines.push(`... (${rows.length - 55} additional row(s) omitted in PDF page view)`);
  }

  const streamOps = ['BT', '/F1 8 Tf', '36 765 Td', '11 TL'];
  for (const line of textLines) {
    streamOps.push(`(${escapePdfTextLine(line)}) Tj T*`);
  }
  streamOps.push('ET');
  const streamContent = streamOps.join('\n');
  const streamByteLen = Buffer.byteLength(streamContent, 'ascii');

  const objects = [
    '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n',
    '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n',
    '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n',
    '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n',
    `5 0 obj\n<< /Length ${streamByteLen} >>\nstream\n${streamContent}\nendstream\nendobj\n`,
  ];

  const header = '%PDF-1.4\n';
  const offsets: number[] = [];
  let cursor = Buffer.byteLength(header, 'ascii');
  for (const obj of objects) {
    offsets.push(cursor);
    cursor += Buffer.byteLength(obj, 'ascii');
  }

  const xrefOffset = cursor;
  const xrefLines = [
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

  return Buffer.from(header + objects.join('') + xrefLines, 'ascii');
}

/**
 * Thuật toán: Điều phối kết xuất bộ đệm nhị phân theo định dạng yêu cầu (`CSV`, `JSON`, `EXCEL`, `PDF`).
 */
export function formatExportPayload(
  exportType: string,
  rawFormat: string,
  rows: Record<string, unknown>[],
  generatedAt: Date = new Date(),
): FormattedExportArtifact {
  const format = rawFormat.trim().toUpperCase() as SupportedExportFormat;
  const columns = resolveColumns(exportType, rows);

  if (format === 'JSON') {
    const body = JSON.stringify(
      {
        exportType,
        generatedAt: generatedAt.toISOString(),
        rowCount: rows.length,
        items: rows,
      },
      (_k, v) => (typeof v === 'bigint' ? v.toString() : v),
      2,
    );
    return {
      buffer: Buffer.from(body, 'utf8'),
      mimeType: 'application/json; charset=utf-8',
      extension: 'json',
    };
  }

  if (format === 'EXCEL') {
    const headerCells = columns
      .map((col) => `<Cell><Data ss:Type="String">${escapeXml(col)}</Data></Cell>`)
      .join('');
    const xmlRows = rows
      .map((row) => {
        const cells = columns
          .map(
            (col) =>
              `<Cell><Data ss:Type="String">${escapeXml(sanitizeSpreadsheetCell(row[col]))}</Data></Cell>`,
          )
          .join('');
        return `<Row>${cells}</Row>`;
      })
      .join('\n');
    const xml = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<?mso-application progid="Excel.Sheet"?>',
      '<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">',
      `  <Worksheet ss:Name="${escapeXml(exportType.slice(0, 31))}">`,
      '    <Table>',
      `      <Row>${headerCells}</Row>`,
      xmlRows,
      '    </Table>',
      '  </Worksheet>',
      '</Workbook>',
    ].join('\n');
    return {
      buffer: Buffer.from(xml, 'utf8'),
      mimeType: 'application/vnd.ms-excel; charset=utf-8',
      extension: 'xls',
    };
  }

  if (format === 'PDF') {
    return {
      buffer: buildMinimalPdfReport(exportType, columns, rows, generatedAt),
      mimeType: 'application/pdf',
      extension: 'pdf',
    };
  }

  // Default: CSV with strict formula injection sanitization
  const csvLines = [
    columns.map((col) => escapeCsvCell(col)).join(','),
    ...rows.map((row) => columns.map((col) => escapeCsvCell(row[col])).join(',')),
  ];
  return {
    buffer: Buffer.from(`${csvLines.join('\n')}\n`, 'utf8'),
    mimeType: 'text/csv; charset=utf-8',
    extension: 'csv',
  };
}

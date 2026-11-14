import { buildMultiPagePdfReport, escapePdfTextLine } from './pdf-builder.js';
import { buildOoxmlXlsxBuffer } from './xlsx-builder.js';

/**
 * Thuật toán / Tổng quan module:
 * Bộ điều phối định dạng dữ liệu kết xuất bất đồng bộ (`CSV`, `JSON`, `EXCEL`, `PDF`) cho `ExportProcessorJob`:
 * - Chống tấn công tiêm công thức bảng tính (CSV/Excel Formula Injection / DDE) bao phủ khoảng trắng đầu dòng và `=`, `+`, `-`, `@`, `|`, `\t`, `\r`, `\n`.
 * - Xuất sổ tính OOXML `.xlsx` chuẩn (`application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`) và tài liệu `%PDF-1.4` đa trang khổ A4.
 */

export { escapePdfTextLine };

export type SupportedExportFormat = 'CSV' | 'JSON' | 'EXCEL' | 'PDF';

export interface FormattedExportArtifact {
  buffer: Buffer;
  mimeType: string;
  extension: string;
}

const FORMULA_DANGEROUS_RE = /^(?:[\t\r\n]|\s*[=+\-@|])|[\r\n]\s*[=+\-@|]/u;

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
  for (const row of rows.slice(0, 50)) {
    for (const key of Object.keys(row)) colSet.add(key);
  }
  return colSet.size > 0 ? [...colSet] : ['id'];
}

/**
 * Thuật toán: Điều phối kết xuất bộ đệm nhị phân theo định dạng yêu cầu (`CSV`, `JSON`, `EXCEL` `.xlsx`, `PDF` đa trang).
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
    // CONFLICT-RESOLVED: Nâng cấp định dạng EXCEL từ XML Spreadsheet 2003 (`.xls`) lên gói ZIP OOXML `.xlsx` chuẩn đồng nhất với `@sda/api`.
    return {
      buffer: buildOoxmlXlsxBuffer(exportType, columns, rows, sanitizeSpreadsheetCell),
      mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      extension: 'xlsx',
    };
  }

  if (format === 'PDF') {
    return {
      buffer: buildMultiPagePdfReport(exportType, columns, rows, generatedAt, serializeValue),
      mimeType: 'application/pdf',
      extension: 'pdf',
    };
  }

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

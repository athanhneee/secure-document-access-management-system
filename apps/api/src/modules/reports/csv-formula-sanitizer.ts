/**
 * CSV Formula Injection (CWE-1236) Defense Utility.
 *
 * Cells starting with =, +, -, @, \t, \r can be interpreted as formulas or commands
 * when opened in spreadsheet software like Microsoft Excel or LibreOffice Calc.
 *
 * To neutralize code/formula execution, dangerous prefix characters are escaped
 * by prepending a single quote (').
 */

const DANGEROUS_PREFIXES = new Set(['=', '+', '-', '@', '\t', '\r']);

export function sanitizeCsvCell(value: unknown): string {
  if (value === null || value === undefined) {
    return '';
  }

  const str = String(value);
  if (str.length > 0 && DANGEROUS_PREFIXES.has(str[0]!)) {
    return `'${str}`;
  }

  return str;
}

export function sanitizeCsvRow(values: unknown[]): string[] {
  return values.map((val) => sanitizeCsvCell(val));
}

export function formatCsvRow(values: unknown[]): string {
  return values
    .map((val) => {
      const sanitized = sanitizeCsvCell(val);
      // Escape if contains comma, quote, or newline
      if (
        sanitized.includes('"') ||
        sanitized.includes(',') ||
        sanitized.includes('\n') ||
        sanitized.includes('\r')
      ) {
        return `"${sanitized.replace(/"/g, '""')}"`;
      }
      return sanitized;
    })
    .join(',');
}

export function generateCsv<T extends Record<string, unknown>>(
  rows: T[],
  columns: Array<{ key: keyof T; header: string }>,
): string {
  const headerLine = formatCsvRow(columns.map((c) => c.header));
  const dataLines = rows.map((row) => formatCsvRow(columns.map((c) => row[c.key])));
  return [headerLine, ...dataLines].join('\r\n');
}

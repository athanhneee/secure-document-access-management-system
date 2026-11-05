/**
 * Module: CsvFormulaSanitizer — Tiện ích chống tấn công chèn công thức bảng tính (OWASP CSV Formula / DDE Injection Defense - CWE-1236) và định dạng CSV chuẩn RFC 4180.
 *
 * CSV Formula Injection (CWE-1236) Defense Utility.
 *
 * Cells starting with =, +, -, @, \t, \r can be interpreted as formulas or commands
 * when opened in spreadsheet software like Microsoft Excel or LibreOffice Calc.
 *
 * To neutralize code/formula execution, dangerous prefix characters are escaped
 * by prepending a single quote (').
 */

const DANGEROUS_PREFIXES = new Set(['=', '+', '-', '@', '|', '\t', '\r', '\n']);
const LEADING_WHITESPACE_FORMULA_RE = /^[\s\u00A0]+[=+\-@|]/u;

/**
 * Thuật toán: Vô hiệu hóa chèn công thức bảng tính OWASP CWE-1236 (Spreadsheet Formula & DDE Prefix Neutralization)
 * Mục đích: Ngăn Microsoft Excel, LibreOffice Calc hoặc Google Sheets thực thi biểu thức/lệnh DDE độc hại khi mở tệp báo cáo CSV xuất từ dữ liệu nhật ký.
 * Cơ chế hoạt động:
 *   - Chuyển giá trị `null`/`undefined` về chuỗi rỗng; ép kiểu mọi giá trị còn lại sang chuỗi.
 *   - Kiểm tra đồng thời hai điều kiện nguy hiểm: (1) ký tự đầu tiên nằm trong tập `DANGEROUS_PREFIXES` (`=`, `+`, `-`, `@`, `|`, `\t`, `\r`, `\n`) tra cứu `O(1)`, hoặc (2) có khoảng trắng/NBSP (`\u00A0`) dẫn đầu theo sau bởi toán tử công thức (`LEADING_WHITESPACE_FORMULA_RE` chống kỹ thuật lách bộ lọc bằng dấu cách đầu dòng).
 *   - Nếu khớp, ghép thêm dấu nháy đơn `'` ở đầu chuỗi để ép phần mềm bảng tính hiểu là văn bản thuần.
 */
export function sanitizeCsvCell(value: unknown): string {
  if (value === null || value === undefined) {
    return '';
  }

  const str = String(value);
  if (
    str.length > 0 &&
    (DANGEROUS_PREFIXES.has(str[0]!) || LEADING_WHITESPACE_FORMULA_RE.test(str))
  ) {
    return `'${str}`;
  }

  return str;
}

/**
 * Thuật toán: Làm sạch toàn bộ mảng giá trị của một dòng CSV (Row-Level Formula Sanitization)
 * Mục đích: Áp dụng `sanitizeCsvCell` đồng nhất lên mọi cột của một bản ghi.
 * Cơ chế hoạt động:
 *   - Ánh xạ tuyến tính `O(C)` từng phần tử trong mảng `values` qua `sanitizeCsvCell`.
 */
export function sanitizeCsvRow(values: unknown[]): string[] {
  return values.map((val) => sanitizeCsvCell(val));
}

/**
 * Thuật toán: Đóng gói dòng CSV chuẩn RFC 4180 kết hợp chống Formula Injection (RFC 4180 Field Quoting & Escaping)
 * Mục đích: Tuần tự hóa mảng giá trị thành một dòng CSV hợp lệ ngay cả khi dữ liệu chứa dấu phẩy, dấu ngoặc kép hoặc ký tự xuống dòng.
 * Cơ chế hoạt động:
 *   - Khử công thức độc hại trên từng ô bằng `sanitizeCsvCell`.
 *   - Nếu chuỗi sau làm sạch chứa `"`, `,`, `\n` hoặc `\r`: nhân đôi mọi dấu ngoặc kép bên trong (`"` -> `""`) và bao toàn bộ ô trong cặp dấu `"..."`, sau đó nối các cột bằng dấu `,`.
 */
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

/**
 * Thuật toán: Sinh tài liệu bảng CSV hoàn chỉnh theo lược đồ cột (Schema-Driven RFC 4180 CSV Builder)
 * Mục đích: Kết xuất danh sách bản ghi đối tượng thành nội dung tệp CSV chuẩn dòng kết thúc `\r\n` (CRLF).
 * Cơ chế hoạt động:
 *   - Định dạng dòng tiêu đề từ `columns.map(c => c.header)`, chiếu từng dòng dữ liệu theo thứ tự `columns.map(c => row[c.key])` qua `formatCsvRow`, rồi ghép nối bằng ký tự ngắt dòng chuẩn RFC 4180 `\r\n`.
 */
export function generateCsv<T extends Record<string, unknown>>(
  rows: T[],
  columns: Array<{ key: keyof T; header: string }>,
): string {
  const headerLine = formatCsvRow(columns.map((c) => c.header));
  const dataLines = rows.map((row) => formatCsvRow(columns.map((c) => row[c.key])));
  return [headerLine, ...dataLines].join('\r\n');
}

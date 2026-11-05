/**
 * Module: ExportFormatter — Động cơ dàn trang bảng biểu PDF đa trang (A4 Landscape `pdf-lib`) và kết xuất sổ tính Excel XLSX (`ExcelJS`) tích hợp phòng vệ Formula Injection.
 */
import ExcelJS from 'exceljs';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';

export interface ExportColumn {
  key: string;
  header: string;
  width?: number;
}

/**
 * Thuật toán: Chuyển tự Unicode NFD sang bảng mã ASCII in được tương thích WinAnsi (Unicode-to-WinAnsi Transliteration)
 * Mục đích: Ngăn lỗi mã hóa phông chữ chuẩn `Helvetica` của `pdf-lib` khi tiêu đề hoặc dữ liệu báo cáo chứa dấu tiếng Việt/ký tự đặc biệt.
 * Cơ chế hoạt động:
 *   - Phân rã tổ hợp dấu bằng chuẩn hóa Unicode `NFD`, tước bỏ dải dấu phụ kết hợp `[\u0300-\u036f]`, chuyển `đ/Đ` thành `d/D`, thay ký tự ngoài miền in ASCII `[\x20-\x7E]` bằng khoảng trắng và gom gọn khoảng trắng thừa.
 *
 * Transliterates Vietnamese / Unicode text to ASCII-compatible string for WinAnsi standard PDF fonts.
 */
export function sanitizeForPdf(text: string): string {
  if (!text) return '';
  return text
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/gu, '')
    .replace(/[đĐ]/gu, (c) => (c === 'đ' ? 'd' : 'D'))
    .replace(/[^\x20-\x7E]/gu, ' ')
    .replace(/\s+/gu, ' ')
    .trim();
}

/**
 * Thuật toán: Dàn trang bảng biểu PDF khổ ngang A4 đa trang (Multi-Page A4 Landscape Tabular Layout Engine)
 * Mục đích: Kết xuất tập dữ liệu kiểm toán/sự cố thành tệp PDF có tiêu đề, thanh cột, dòng xen kẽ màu (Zebra Striping), đánh số trang và chân trang bảo mật.
 * Cơ chế hoạt động:
 *   - Thiết lập khổ giấy A4 ngang (`841.89 x 595.28 pt`, lề `36 pt`), chia đều độ rộng cột `colWidth = usableWidth / max(1, columns.length)`.
 *   - Tính sức chứa dòng mỗi trang `rowsPerPage = max(1, floor((usableHeight - 65) / rowHeight))` và tổng số trang `ceil(rows.length / rowsPerPage)`.
 *   - Với từng trang: vẽ tiêu đề, metadata trang, thanh header nền tối, lát cắt dữ liệu `rows.slice(pageIdx * rowsPerPage, (pageIdx + 1) * rowsPerPage)` có cắt ngắn chuỗi dài (`> 24` ký tự) và đóng dấu chân trang bảo mật.
 *
 * Generates a structured multi-page PDF tabular document.
 */
export async function generatePdfTable(
  title: string,
  columns: ExportColumn[],
  rows: Record<string, string>[],
): Promise<Buffer> {
  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

  // A4 Landscape: 841.89 x 595.28 points
  const pageWidth = 841.89;
  const pageHeight = 595.28;
  const margin = 36;
  const usableWidth = pageWidth - margin * 2;
  const usableHeight = pageHeight - margin * 2;

  const colWidth = usableWidth / Math.max(1, columns.length);
  const rowHeight = 16;
  const rowsPerPage = Math.max(1, Math.floor((usableHeight - 65) / rowHeight));
  const totalPages = Math.max(1, Math.ceil(rows.length / rowsPerPage));

  const cleanTitle = sanitizeForPdf(title);

  for (let pageIdx = 0; pageIdx < totalPages; pageIdx++) {
    const page = pdfDoc.addPage([pageWidth, pageHeight]);
    let y = pageHeight - margin;

    // Header Title
    page.drawText(cleanTitle, {
      x: margin,
      y: y - 14,
      size: 13,
      font: fontBold,
      color: rgb(0.08, 0.14, 0.28),
    });

    const pageMeta = `Page ${pageIdx + 1} of ${totalPages} | Total Records: ${rows.length} | Generated: ${new Date().toISOString()}`;
    page.drawText(pageMeta, {
      x: pageWidth - margin - 320,
      y: y - 14,
      size: 8,
      font,
      color: rgb(0.4, 0.45, 0.5),
    });

    y -= 30;

    // Table Header Bar
    page.drawRectangle({
      x: margin,
      y: y - 14,
      width: usableWidth,
      height: 18,
      color: rgb(0.12, 0.18, 0.3),
    });

    columns.forEach((col, colIdx) => {
      const headerText = sanitizeForPdf(col.header).slice(0, 18);
      page.drawText(headerText, {
        x: margin + colIdx * colWidth + 4,
        y: y - 10,
        size: 7.5,
        font: fontBold,
        color: rgb(1, 1, 1),
      });
    });

    y -= 18;

    // Table Rows
    const pageRows = rows.slice(pageIdx * rowsPerPage, (pageIdx + 1) * rowsPerPage);
    for (let rIdx = 0; rIdx < pageRows.length; rIdx++) {
      const row = pageRows[rIdx];
      if (!row) continue;
      const isEven = rIdx % 2 === 0;

      if (isEven) {
        page.drawRectangle({
          x: margin,
          y: y - rowHeight + 3,
          width: usableWidth,
          height: rowHeight,
          color: rgb(0.96, 0.97, 0.98),
        });
      }

      columns.forEach((col, colIdx) => {
        let val = sanitizeForPdf(row[col.key] ?? '');
        if (val.length > 24) val = val.slice(0, 22) + '...';
        page.drawText(val, {
          x: margin + colIdx * colWidth + 4,
          y: y - rowHeight + 6,
          size: 7,
          font,
          color: rgb(0.15, 0.15, 0.15),
        });
      });

      y -= rowHeight;
    }

    // Confidentiality Footer
    page.drawText('CONFIDENTIAL - SECURE DOCUMENT ACCESS AUDIT REPORT - TAMPER EVIDENT', {
      x: margin,
      y: margin - 15,
      size: 7,
      font,
      color: rgb(0.5, 0.55, 0.6),
    });
  }

  const pdfBytes = await pdfDoc.save();
  return Buffer.from(pdfBytes);
}

/**
 * Thuật toán: Kết xuất bảng tính Excel XLSX có định dạng & khử công thức độc hại (Formula-Safe Styled XLSX Workbook Generator)
 * Mục đích: Tạo tệp `.xlsx` chuyên nghiệp phục vụ lưu trữ/phân tích kiểm toán trong khi ngăn chặn tấn công chèn công thức bảng tính (CWE-1236).
 * Cơ chế hoạt động:
 *   - Khởi tạo `ExcelJS.Workbook`, giới hạn tên trang tính tối đa 30 ký tự (chuẩn OOXML Worksheet Name Limit) và tính độ rộng cột tự động `max(header.length + 6, 16)`.
 *   - Trước khi chèn từng ô dữ liệu, kiểm tra biểu thức chính quy `/^[=+\-@\t\r]/u` và ghép tiền tố `'` nếu phát hiện ký tự khởi đầu công thức; tô màu nền xen kẽ cho các dòng lẻ.
 *
 * Generates an Excel XLSX workbook using ExcelJS.
 */
export async function generateExcelTable(
  sheetName: string,
  columns: ExportColumn[],
  rows: Record<string, string>[],
): Promise<Buffer> {
  const workbook = new ExcelJS.Workbook();
  workbook.creator = 'Secure Document Access System';
  workbook.lastModifiedBy = 'Secure Document Access Export Service';
  workbook.created = new Date();
  workbook.modified = new Date();

  const worksheet = workbook.addWorksheet(sheetName.slice(0, 30));

  worksheet.columns = columns.map((col) => ({
    header: col.header,
    key: col.key,
    width: col.width ?? Math.max(col.header.length + 6, 16),
  }));

  // Style Header Row
  const headerRow = worksheet.getRow(1);
  headerRow.font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 10 };
  headerRow.fill = {
    type: 'pattern',
    pattern: 'solid',
    fgColor: { argb: 'FF0F172A' },
  };
  headerRow.alignment = { vertical: 'middle', horizontal: 'center' };
  headerRow.height = 26;

  // Add Data Rows with alternating colors and formula injection sanitization
  rows.forEach((row, idx) => {
    const sanitizedRow: Record<string, string> = {};
    for (const col of columns) {
      let val = row[col.key] ?? '';
      // Formula Injection Sanitization
      if (/^[=+\-@\t\r]/u.test(val)) {
        val = `'${val}`;
      }
      sanitizedRow[col.key] = val;
    }

    const addedRow = worksheet.addRow(sanitizedRow);
    addedRow.height = 20;
    addedRow.alignment = { vertical: 'middle' };

    if (idx % 2 === 1) {
      addedRow.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFF8FAFC' },
      };
    }
  });

  const buffer = await workbook.xlsx.writeBuffer();
  return Buffer.from(buffer);
}

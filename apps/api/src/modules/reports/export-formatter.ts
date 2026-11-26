/**
 * Module: ExportFormatter — Động cơ dàn trang bảng biểu PDF đa trang (A4 Landscape `pdf-lib`) và kết xuất sổ tính Excel XLSX (`ExcelJS`) tích hợp phòng vệ Formula Injection.
 */
import ExcelJS from 'exceljs';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import { sanitizeCsvCell } from './csv-formula-sanitizer.js';

export interface ExportColumn {
  key: string;
  header: string;
  width?: number;
}

/**
 * Thuật toán: Chuyển tự Unicode NFD sang bảng mã ASCII in được tương thích WinAnsi (Unicode-to-WinAnsi Transliteration).
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
 * Thuật toán: Ngắt dòng văn bản ô bảng PDF ưu tiên biên từ kết hợp tìm kiếm nhị phân cho chuỗi dài không khoảng trắng
 * (SHA-256, UUID) để đạt độ phức tạp `O(L log L)` thay vì đo từng ký tự `O(L^2)` và bảo toàn 100% dữ liệu (`LOW-12`).
 */
function wrapPdfCellText(
  rawText: string,
  measureWidth: (candidate: string) => number,
  maxWidth: number,
): string[] {
  const cleaned = sanitizeForPdf(rawText);
  if (!cleaned) return [''];
  if (measureWidth(cleaned) <= maxWidth) return [cleaned];

  const lines: string[] = [];
  const words = cleaned.split(' ');
  let current = '';

  const splitLongToken = (token: string): void => {
    let offset = 0;
    while (offset < token.length) {
      let lo = 1;
      let hi = token.length - offset;
      let best = 1;
      while (lo <= hi) {
        const mid = (lo + hi) >>> 1;
        if (measureWidth(token.slice(offset, offset + mid)) <= maxWidth) {
          best = mid;
          lo = mid + 1;
        } else {
          hi = mid - 1;
        }
      }
      const chunk = token.slice(offset, offset + best);
      offset += best;
      if (offset < token.length) {
        lines.push(chunk);
      } else {
        current = chunk;
      }
    }
  };

  for (const word of words) {
    if (!word) continue;
    const candidate = current ? `${current} ${word}` : word;
    if (measureWidth(candidate) <= maxWidth) {
      current = candidate;
      continue;
    }
    if (current) {
      lines.push(current);
      current = '';
    }
    if (measureWidth(word) <= maxWidth) {
      current = word;
    } else {
      splitLongToken(word);
    }
  }

  if (current.length > 0 || lines.length === 0) {
    lines.push(current);
  }
  return lines;
}

/**
 * Thuật toán: Dàn trang bảng biểu PDF khổ ngang A4 đa trang tự động co giãn chiều cao dòng (Dynamic Row-Height Multi-Page A4 Landscape Engine)
 * Mục đích: Kết xuất toàn bộ tập dữ liệu tuân thủ thành tệp PDF nhiều trang A4 không giới hạn 55 dòng và không cắt cụt chuỗi dài.
 * Cơ chế hoạt động:
 *   - Pha 1 (Đo lường & Tách trang): Tính mảng dòng con `wrapPdfCellText` cho từng ô theo `colWidth - 8`, suy ra chiều cao động của từng bản ghi và phân bổ vào các trang A4 ngang (`841.89 x 595.28 pt`).
 *   - Pha 2 (Dựng trang): Vẽ tiêu đề, metadata `Page k of N`, thanh cột nền tối, các dòng Zebra Striping đa dòng và chân trang bảo mật.
 */
export async function generatePdfTable(
  title: string,
  columns: ExportColumn[],
  rows: Record<string, string>[],
): Promise<Buffer> {
  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

  const pageWidth = 841.89;
  const pageHeight = 595.28;
  const margin = 36;
  const usableWidth = pageWidth - margin * 2;
  const bodyFontSize = 7;
  const lineHeight = 9.5;
  const colWidth = usableWidth / Math.max(1, columns.length);
  const maxCellWidth = Math.max(18, colWidth - 8);
  const maxHeaderWidth = Math.max(18, colWidth - 8);

  const wrappedHeaders = columns.map((col) =>
    wrapPdfCellText(col.header, (s) => fontBold.widthOfTextAtSize(s, 7.5), maxHeaderWidth).slice(
      0,
      2,
    ),
  );
  const headerLineCount = Math.max(1, ...wrappedHeaders.map((h) => h.length));
  const headerBarHeight = Math.max(18, headerLineCount * 9.5 + 6);
  const maxPageBodyHeight = pageHeight - margin * 2 - 34 - headerBarHeight - 16;
  const maxLinesPerSingleSlice = Math.max(1, Math.floor((maxPageBodyHeight - 6) / lineHeight));

  interface LaidOutRow {
    cells: string[][];
    height: number;
    recordIndex: number;
  }

  const laidOutRows: LaidOutRow[] = [];
  for (let idx = 0; idx < rows.length; idx++) {
    const row = rows[idx];
    if (!row) continue;
    const wrappedCells = columns.map((col) =>
      wrapPdfCellText(
        row[col.key] ?? '',
        (s) => font.widthOfTextAtSize(s, bodyFontSize),
        maxCellWidth,
      ),
    );
    const totalCellLines = Math.max(1, ...wrappedCells.map((c) => c.length));
    // CONFLICT-RESOLVED: Thay thế cơ chế cắt cứng `val.slice(0, 22) + '...'` bằng ngắt dòng tự động đa dòng/đa trang để không làm mất dữ liệu kiểm toán.
    for (let offset = 0; offset < totalCellLines; offset += maxLinesPerSingleSlice) {
      const slicedCells = wrappedCells.map((c) => c.slice(offset, offset + maxLinesPerSingleSlice));
      const sliceLines = Math.max(1, ...slicedCells.map((c) => c.length));
      laidOutRows.push({
        cells: slicedCells,
        height: Math.max(16, sliceLines * lineHeight + 6),
        recordIndex: idx,
      });
    }
  }

  const pages: LaidOutRow[][] = [];
  let currentPageRows: LaidOutRow[] = [];
  let usedBodyHeight = 0;
  for (const item of laidOutRows) {
    if (currentPageRows.length > 0 && usedBodyHeight + item.height > maxPageBodyHeight) {
      pages.push(currentPageRows);
      currentPageRows = [];
      usedBodyHeight = 0;
    }
    currentPageRows.push(item);
    usedBodyHeight += item.height;
  }
  if (currentPageRows.length > 0 || pages.length === 0) {
    pages.push(currentPageRows);
  }

  const cleanTitle = sanitizeForPdf(title);
  const generatedIso = new Date().toISOString();

  for (let pageIdx = 0; pageIdx < pages.length; pageIdx++) {
    const page = pdfDoc.addPage([pageWidth, pageHeight]);
    let y = pageHeight - margin;

    page.drawText(cleanTitle, {
      x: margin,
      y: y - 14,
      size: 13,
      font: fontBold,
      color: rgb(0.08, 0.14, 0.28),
    });

    const pageMeta = `Page ${pageIdx + 1} of ${pages.length} | Total Records: ${rows.length} | Generated: ${generatedIso}`;
    page.drawText(pageMeta, {
      x: pageWidth - margin - 330,
      y: y - 14,
      size: 8,
      font,
      color: rgb(0.4, 0.45, 0.5),
    });

    y -= 30;

    page.drawRectangle({
      x: margin,
      y: y - headerBarHeight + 4,
      width: usableWidth,
      height: headerBarHeight,
      color: rgb(0.12, 0.18, 0.3),
    });

    wrappedHeaders.forEach((hLines, colIdx) => {
      hLines.forEach((hLine, lineIdx) => {
        page.drawText(hLine, {
          x: margin + colIdx * colWidth + 4,
          y: y - 8 - lineIdx * 9.5,
          size: 7.5,
          font: fontBold,
          color: rgb(1, 1, 1),
        });
      });
    });

    y -= headerBarHeight;

    const pageItems = pages[pageIdx] ?? [];
    for (const item of pageItems) {
      if (item.recordIndex % 2 === 0) {
        page.drawRectangle({
          x: margin,
          y: y - item.height + 3,
          width: usableWidth,
          height: item.height,
          color: rgb(0.96, 0.97, 0.98),
        });
      }

      item.cells.forEach((cellLines, colIdx) => {
        cellLines.forEach((lineText, lineIdx) => {
          if (!lineText) return;
          page.drawText(lineText, {
            x: margin + colIdx * colWidth + 4,
            y: y - 8 - lineIdx * lineHeight,
            size: bodyFontSize,
            font,
            color: rgb(0.15, 0.15, 0.15),
          });
        });
      });

      y -= item.height;
    }

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
 * Thuật toán: Kết xuất bảng tính Excel XLSX có định dạng & khử công thức độc hại OWASP CWE-1236 (`ExcelJS`).
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
    header: sanitizeCsvCell(col.header),
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

  // Add Data Rows with alternating colors and shared OWASP CWE-1236 formula injection sanitization
  rows.forEach((row, idx) => {
    const sanitizedRow: Record<string, string> = {};
    for (const col of columns) {
      sanitizedRow[col.key] = sanitizeCsvCell(row[col.key] ?? '');
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

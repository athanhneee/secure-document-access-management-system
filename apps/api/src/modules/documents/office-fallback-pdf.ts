/**
 * @module OfficeFallbackPdf
 * Thuật toán: Kết xuất tài liệu Office sang PDF qua máy khách HTTP Gotenberg có cắt ngưỡng thời gian (`AbortController`)
 * và kiểm tra chữ ký ma thuật `%PDF`, kết hợp bộ dựng PDF A4 phân trang tự động ngắt dòng (word-wrap không cắt cụt)
 * và vẽ khung lưới bảng biểu (`| ... |`) bằng `pdf-lib`.
 */
import type { Logger } from '@nestjs/common';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';

/**
 * Thuật toán: Gửi biểu mẫu đa phần (`multipart/form-data`) tới `/forms/libreoffice/convert` của Gotenberg
 * kèm `AbortController` giới hạn tối đa `min(timeoutMs, 8000)` ms và xác thực 4 byte đầu `%PDF`.
 */
export async function convertWithGotenberg(
  gotenbergUrl: string,
  gotenbergEnabled: boolean,
  officeBuffer: Buffer,
  filename: string,
  timeoutMs: number,
  logger: Logger,
): Promise<Buffer | null> {
  if (!gotenbergEnabled || !gotenbergUrl) {
    return null;
  }

  try {
    const endpoint = `${gotenbergUrl.replace(/\/+$/, '')}/forms/libreoffice/convert`;
    const formData = new FormData();
    const slice = officeBuffer.buffer.slice(
      officeBuffer.byteOffset,
      officeBuffer.byteOffset + officeBuffer.byteLength,
    ) as ArrayBuffer;
    formData.append('files', new Blob([slice]), filename);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.min(timeoutMs, 8_000));

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        body: formData,
        signal: controller.signal,
      });

      if (!response.ok) {
        logger.warn(
          `Gotenberg conversion returned HTTP ${response.status} for ${filename}. Falling back to internal engine.`,
        );
        return null;
      }

      const pdfBuffer = Buffer.from(await response.arrayBuffer());
      if (pdfBuffer.length < 4 || pdfBuffer.subarray(0, 4).toString('ascii') !== '%PDF') {
        logger.warn(`Gotenberg response for ${filename} is not a valid PDF.`);
        return null;
      }

      return pdfBuffer;
    } finally {
      clearTimeout(timer);
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.debug(
      `Gotenberg conversion unavailable for ${filename} (${msg}). Falling back to internal engine.`,
    );
    return null;
  }
}

interface WrappedDisplayLine {
  text: string;
  isTableRow: boolean;
}

function wrapContentLines(content: string, maxChars: number = 90): WrappedDisplayLine[] {
  const output: WrappedDisplayLine[] = [];
  for (const rawLine of content.split('\n')) {
    const safe = toWinAnsiSafeText(rawLine.trim());
    if (!safe) continue;
    const isTableRow = safe.startsWith('| ') && safe.endsWith(' |');
    if (safe.length <= maxChars) {
      output.push({ text: safe, isTableRow });
      continue;
    }
    const words = safe.split(/\s+/u);
    let current = '';
    for (const word of words) {
      const candidate = current ? `${current} ${word}` : word;
      if (candidate.length <= maxChars) {
        current = candidate;
      } else {
        if (current) output.push({ text: current, isTableRow });
        current = word.length > maxChars ? word.slice(0, maxChars) : word;
      }
    }
    if (current) output.push({ text: current, isTableRow });
  }
  return output;
}

/**
 * Thuật toán: Phân trang văn bản và bảng biểu đã khử mã độc lên khổ giấy A4 (`595.28 x 841.89` pt, tối đa `40` dòng/trang,
 * trần `maxPages` trang) kèm tự động xuống dòng (word-wrap) và tô khung dòng bảng biểu.
 */
export async function renderSanitizedTextToPdf(
  title: string,
  content: string,
  maxPages: number = 50,
): Promise<Buffer> {
  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const safeTitle = toWinAnsiSafeText(title);

  const lines = wrapContentLines(content, 90);
  const linesPerPage = 40;
  let pageCount = 0;
  let lineIdx = 0;

  while (lineIdx < lines.length && pageCount < maxPages) {
    const page = pdfDoc.addPage([595.28, 841.89]);
    pageCount++;
    const { width, height } = page.getSize();

    if (pageCount === 1) {
      page.drawText(`Converted Document: ${safeTitle}`, {
        x: 40,
        y: height - 40,
        size: 14,
        font: boldFont,
        color: rgb(0.1, 0.1, 0.1),
      });
      page.drawText('Sanitized Structured Office Preview (Macros/Scripts Blocked)', {
        x: 40,
        y: height - 58,
        size: 9,
        font,
        color: rgb(0.4, 0.4, 0.4),
      });
    }

    let yPos = pageCount === 1 ? height - 86 : height - 46;
    const endLine = Math.min(lineIdx + linesPerPage, lines.length);

    for (let i = lineIdx; i < endLine; i++) {
      const entry = lines[i];
      if (!entry) continue;
      if (entry.isTableRow) {
        page.drawRectangle({
          x: 36,
          y: yPos - 4,
          width: width - 72,
          height: 16,
          color: i % 2 === 0 ? rgb(0.96, 0.97, 0.98) : rgb(1, 1, 1),
          borderColor: rgb(0.84, 0.86, 0.89),
          borderWidth: 0.5,
        });
      }
      page.drawText(entry.text, {
        x: 40,
        y: yPos,
        size: 9.5,
        font,
        color: rgb(0.14, 0.14, 0.14),
      });
      yPos -= 17;
    }

    page.drawText(`Page ${pageCount}`, {
      x: width - 80,
      y: 20,
      size: 8,
      font,
      color: rgb(0.5, 0.5, 0.5),
    });

    lineIdx = endLine;
  }

  if (lines.length === 0 || pageCount === 0) {
    const page = pdfDoc.addPage([595.28, 841.89]);
    page.drawText(`Converted Document: ${safeTitle}`, {
      x: 40,
      y: 800,
      size: 14,
      font: boldFont,
    });
    page.drawText('(Document has no printable text content)', {
      x: 40,
      y: 770,
      size: 10,
      font,
    });
  }

  return Buffer.from(await pdfDoc.save());
}

/**
 * Thuật toán: Chuẩn hóa chuỗi Unicode NFD sang tập ký tự WinAnsi (`0x20..0x7E`, `0xA0..0xFF`) tránh lỗi mã hóa phông PDF.
 */
function toWinAnsiSafeText(input: string): string {
  return input
    .replace(/Đ/gu, 'D')
    .replace(/đ/gu, 'd')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/gu, '')
    .replace(/[^\x20-\x7E\xA0-\xFF]/gu, '?');
}

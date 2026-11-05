/**
 * Module: Gotenberg LibreOffice Client & Sanitized Fallback PDF Renderer
 * Algorithm: Converts Office binaries via headless LibreOffice HTTP multipart form with `%PDF` header verification,
 *   or paginates WinAnsi-folded plain text across bounded A4 portrait pages using `pdf-lib`.
 */
import type { Logger } from '@nestjs/common';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';

/**
 * Algorithm: Bounded-Timeout Gotenberg Headless Conversion
 * Submits multipart binary to `/forms/libreoffice/convert` with `AbortController` and verifies `%PDF` magic bytes.
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

/**
 * Algorithm: Safe WinAnsi A4 Text-to-PDF Pagination
 * Folds Unicode diacritics to WinAnsi-compatible characters and lays out up to `maxPages` (42 lines/page).
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

  const lines = content.split('\n');
  const linesPerPage = 42;
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
      page.drawText('Sanitized Office Preview (Macros/Scripts Blocked)', {
        x: 40,
        y: height - 58,
        size: 9,
        font,
        color: rgb(0.4, 0.4, 0.4),
      });
    }

    let yPos = pageCount === 1 ? height - 85 : height - 45;
    const endLine = Math.min(lineIdx + linesPerPage, lines.length);

    for (let i = lineIdx; i < endLine; i++) {
      const rawLine = lines[i] ?? '';
      const truncated = toWinAnsiSafeText(
        rawLine.length > 95 ? `${rawLine.substring(0, 92)}...` : rawLine,
      );
      page.drawText(truncated, {
        x: 40,
        y: yPos,
        size: 10,
        font,
        color: rgb(0.15, 0.15, 0.15),
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

function toWinAnsiSafeText(input: string): string {
  return input
    .replace(/Đ/gu, 'D')
    .replace(/đ/gu, 'd')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/gu, '')
    .replace(/[^\x20-\x7E\xA0-\xFF]/gu, '?');
}

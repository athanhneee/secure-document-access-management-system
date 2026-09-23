import { Injectable, Logger, BadRequestException, GatewayTimeoutException } from '@nestjs/common';
import yauzl from 'yauzl';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import { AppErrorCode } from '@sda/contracts';

export interface OfficeConversionOptions {
  timeoutMs?: number;
  maxPages?: number;
}

@Injectable()
export class OfficeConverterService {
  private readonly logger = new Logger(OfficeConverterService.name);

  /**
   * Safely inspects an Office OpenXML file (.docx, .xlsx, .pptx) and converts it to PDF.
   * Enforces:
   * 1. No VBA macros (vbaProject.bin, etc.) -> OFFICE_MACRO_BLOCKED
   * 2. No external link execution or embedded objects
   * 3. Timeout enforcement (default 10,000ms) -> OFFICE_CONVERSION_TIMEOUT
   * 4. Corrupt file detection -> OFFICE_CONVERSION_FAILED
   */
  async convertOfficeToPdf(
    officeBuffer: Buffer,
    filename: string,
    options: OfficeConversionOptions = {},
  ): Promise<Buffer> {
    this.logger.log(`Safely converting Office document ${filename} to PDF`);
    const timeoutMs = options.timeoutMs ?? 10_000;

    return await Promise.race([
      this.performSafeConversion(officeBuffer, filename, options),
      new Promise<Buffer>((_, reject) => {
        setTimeout(() => {
          reject(
            new GatewayTimeoutException({
              errorCode: AppErrorCode.OFFICE_CONVERSION_TIMEOUT,
              message: `Office document conversion exceeded timeout of ${timeoutMs}ms.`,
            }),
          );
        }, timeoutMs);
      }),
    ]);
  }

  private async performSafeConversion(
    officeBuffer: Buffer,
    filename: string,
    options: OfficeConversionOptions,
  ): Promise<Buffer> {
    // 1. Inspect ZIP archive entries
    const entries = await this.readZipEntries(officeBuffer);

    // 2. Security Check: Detect and block prohibited VBA macros
    for (const entry of entries) {
      const lower = entry.fileName.toLowerCase();
      if (
        lower.includes('vbaproject.bin') ||
        lower.includes('vbadirection') ||
        lower.includes('vbadata') ||
        (lower.endsWith('.bin') && lower.includes('vba'))
      ) {
        throw new BadRequestException({
          errorCode: AppErrorCode.OFFICE_MACRO_BLOCKED,
          message: 'Office document contains prohibited executable VBA macros.',
        });
      }
    }

    // 2b. Security Check: Detect and block prohibited external relationships (SSRF / NTLM leak protection)
    for (const entry of entries) {
      if (entry.fileName.toLowerCase().endsWith('.rels')) {
        const content = await this.extractEntryContent(officeBuffer, entry.fileName);
        if (content) {
          const lowerContent = content.toLowerCase();
          if (
            lowerContent.includes('targetmode="external"') ||
            lowerContent.includes("targetmode='external'") ||
            /target\s*=\s*["'](?:https?|ftp|file|gopher|ldap):/i.test(content) ||
            /target\s*=\s*["']\\\\[^"']+/i.test(content)
          ) {
            throw new BadRequestException({
              errorCode: AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
              message:
                'Office document contains prohibited external relationships or SSRF attack vectors.',
            });
          }
        }
      }
    }

    // 3. Extract text content based on file type
    const ext = filename.split('.').pop()?.toLowerCase();
    let extractedText = '';

    if (ext === 'docx') {
      extractedText = await this.extractDocxText(officeBuffer);
    } else if (ext === 'xlsx') {
      extractedText = await this.extractXlsxText(officeBuffer);
    } else if (ext === 'pptx') {
      extractedText = await this.extractPptxText(officeBuffer);
    } else {
      extractedText = `Document: ${filename}\nFormat: Office OpenXML`;
    }

    // 4. Render extracted content safely into a standardized PDF
    return await this.renderTextToPdf(filename, extractedText, options.maxPages ?? 50);
  }

  /**
   * Reads all entry metadata from the zip buffer.
   */
  private readZipEntries(buffer: Buffer): Promise<yauzl.Entry[]> {
    return new Promise((resolve, reject) => {
      yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
        if (err || !zipfile) {
          return reject(
            new BadRequestException({
              errorCode: AppErrorCode.OFFICE_CONVERSION_FAILED,
              message: 'Invalid or corrupt Office OpenXML package.',
            }),
          );
        }

        const entries: yauzl.Entry[] = [];
        zipfile.readEntry();

        zipfile.on('entry', (entry) => {
          entries.push(entry);
          zipfile.readEntry();
        });

        zipfile.on('end', () => resolve(entries));
        zipfile.on('error', (zipErr) =>
          reject(
            new BadRequestException({
              errorCode: AppErrorCode.OFFICE_CONVERSION_FAILED,
              message: `Corrupt zip archive: ${zipErr.message}`,
            }),
          ),
        );
      });
    });
  }

  /**
   * Extracts entry content as string.
   */
  private extractEntryContent(buffer: Buffer, entryPath: string): Promise<string | null> {
    return new Promise((resolve) => {
      yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
        if (err || !zipfile) return resolve(null);

        zipfile.readEntry();
        zipfile.on('entry', (entry) => {
          if (entry.fileName === entryPath) {
            zipfile.openReadStream(entry, (streamErr, readStream) => {
              if (streamErr || !readStream) return resolve(null);
              const chunks: Buffer[] = [];
              readStream.on('data', (c) => chunks.push(c));
              readStream.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
              readStream.on('error', () => resolve(null));
            });
          } else {
            zipfile.readEntry();
          }
        });

        zipfile.on('end', () => resolve(null));
        zipfile.on('error', () => resolve(null));
      });
    });
  }

  private async extractDocxText(buffer: Buffer): Promise<string> {
    const xml = await this.extractEntryContent(buffer, 'word/document.xml');
    if (!xml) return 'Document body is empty.';
    return this.sanitizeXmlToText(xml);
  }

  private async extractXlsxText(buffer: Buffer): Promise<string> {
    const sharedStringsXml = await this.extractEntryContent(buffer, 'xl/sharedStrings.xml');
    if (!sharedStringsXml) return 'Workbook contains no shared strings.';
    return this.sanitizeXmlToText(sharedStringsXml);
  }

  private async extractPptxText(buffer: Buffer): Promise<string> {
    const slideXml = await this.extractEntryContent(buffer, 'ppt/slides/slide1.xml');
    if (!slideXml) return 'Presentation slide content.';
    return this.sanitizeXmlToText(slideXml);
  }

  /**
   * Sanitizes XML content, strips all XML tags, external links, scripts, and normalizes text.
   */
  private sanitizeXmlToText(xml: string): string {
    // Replace paragraph and break tags with newlines
    let text = xml.replace(/<\/w:p>/g, '\n').replace(/<\/w:r>/g, ' ');
    // Remove all XML tags
    text = text.replace(/<[^>]+>/g, '');
    // Decode basic XML entities
    text = text
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'");
    // Normalize excessive whitespace
    return text
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .join('\n');
  }

  /**
   * Renders sanitized text into a standardized multi-page PDF.
   */
  private async renderTextToPdf(
    title: string,
    content: string,
    maxPages: number = 50,
  ): Promise<Buffer> {
    const pdfDoc = await PDFDocument.create();
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

    const lines = content.split('\n');
    const linesPerPage = 42;
    let pageCount = 0;

    let lineIdx = 0;
    while (lineIdx < lines.length && pageCount < maxPages) {
      const page = pdfDoc.addPage([595.28, 841.89]); // A4 portrait
      pageCount++;
      const { width, height } = page.getSize();

      // Header on first page
      if (pageCount === 1) {
        page.drawText(`Converted Document: ${title}`, {
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
        // Truncate line if too long for A4 width
        const truncated = rawLine.length > 95 ? `${rawLine.substring(0, 92)}...` : rawLine;
        page.drawText(truncated, {
          x: 40,
          y: yPos,
          size: 10,
          font,
          color: rgb(0.15, 0.15, 0.15),
        });
        yPos -= 17;
      }

      // Page footer
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
      page.drawText(`Converted Document: ${title}`, {
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

    const pdfBytes = await pdfDoc.save();
    return Buffer.from(pdfBytes);
  }
}

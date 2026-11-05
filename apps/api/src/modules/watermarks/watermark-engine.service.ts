/**
 * Module: Multi-Layer Forensic PDF Watermark Engine Service
 * Algorithm: Overlays diagonal repeating attribution text, top/bottom security banners, and QR codes
 *   across PDF pages (`pdf-lib`), enforces fail-closed denial on mandated watermark errors, and extracts 1-indexed pages.
 */
import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  Optional,
} from '@nestjs/common';
import crypto, { randomUUID } from 'node:crypto';
import { degrees, PDFDocument, rgb, StandardFonts } from 'pdf-lib';
import { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import {
  formatForensicWatermarkText,
  generateCryptographicWatermarkToken,
  parseHexColor,
  renderQrCodePngBuffer,
  resolveWatermarkConfig,
  toWinAnsiSafeText,
  type WatermarkConfigData,
  type WatermarkDocumentData,
  type WatermarkResult,
  type WatermarkUserData,
} from './watermark-crypto.helper.js';

export type { WatermarkConfigData, WatermarkDocumentData, WatermarkResult, WatermarkUserData };

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class WatermarkEngineService {
  private readonly logger = new Logger(WatermarkEngineService.name);
  private readonly database: PrismaClient;

  constructor(@Optional() databaseClient?: PrismaClient) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Algorithm: 192-Bit CSPRNG Watermark Token Generation (`WM-<48-hex>`)
   */
  generateWatermarkToken(): string {
    return generateCryptographicWatermarkToken();
  }

  /**
   * Algorithm: Forensic Attribution Template Interpolation
   */
  formatWatermarkText(
    template: string,
    user: WatermarkUserData,
    document: WatermarkDocumentData,
    token: string,
    now: Date = new Date(),
  ): string {
    return formatForensicWatermarkText(template, user, document, token, now);
  }

  /**
   * Algorithm: Error-Correction-M QR Code PNG Generation
   */
  async generateQrCodeBuffer(payload: string): Promise<Buffer> {
    return renderQrCodePngBuffer(payload);
  }

  /**
   * Algorithm: Multi-Layer PDF Forensic Watermark Overlay with Fail-Closed Guard
   * Renders diagonal text lattice, top/bottom banners, and corner verification QR code onto every page;
   * throws `ForbiddenException(WATERMARK_GENERATION_FAILED)` if rendering fails on a watermark-mandated document.
   */
  async applyWatermarkToPdf(
    pdfBuffer: Buffer,
    user: WatermarkUserData,
    document: WatermarkDocumentData,
    config: WatermarkConfigData,
    existingToken?: string,
    now: Date = new Date(),
  ): Promise<WatermarkResult> {
    const start = performance.now();
    try {
      const watermarkToken = existingToken || this.generateWatermarkToken();
      const renderedText = this.formatWatermarkText(
        config.template_text,
        user,
        document,
        watermarkToken,
        now,
      );

      const pdfDoc = await PDFDocument.load(pdfBuffer, { ignoreEncryption: true });
      const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
      const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
      const pages = pdfDoc.getPages();
      const pageCount = pages.length;

      const { r, g, b } = parseHexColor(config.color_hex);
      const color = rgb(r, g, b);
      const opacity = Math.min(Math.max(config.opacity_percent / 100, 0.05), 1.0);
      const rotation = degrees(config.rotation_degrees);
      const fontSize = Math.min(Math.max(config.font_size, 8), 72);
      const safeRenderedText = toWinAnsiSafeText(renderedText);

      let qrImage: Awaited<ReturnType<typeof pdfDoc.embedPng>> | null = null;
      if (config.include_qr_code) {
        try {
          const qrPayload = JSON.stringify({
            token: watermarkToken,
            u: user.username,
            d: document.documentCode || document.id.slice(0, 8),
            t: now.toISOString(),
          });
          qrImage = await pdfDoc.embedPng(await this.generateQrCodeBuffer(qrPayload));
        } catch (qrErr) {
          this.logger.warn(`QR code generation failed, proceeding with text watermark: ${qrErr}`);
        }
      }

      for (const page of pages) {
        const { width, height } = page.getSize();
        if (!config.is_visible) continue;

        const diagonalStepX = width / 2;
        const diagonalStepY = height / 3;
        for (let x = width * 0.1; x < width * 0.9; x += diagonalStepX) {
          for (let y = height * 0.15; y < height * 0.85; y += diagonalStepY) {
            page.drawText(safeRenderedText, {
              x,
              y,
              size: fontSize,
              font,
              color,
              rotate: rotation,
              opacity,
            });
          }
        }

        const bannerText = `[SECURE-DOC] ${safeRenderedText}`;
        const bannerOpts = {
          x: 20,
          size: 7,
          font: boldFont,
          color: rgb(0.4, 0.4, 0.4),
          opacity: 0.7,
        };
        page.drawText(bannerText, { ...bannerOpts, y: height - 15 });
        page.drawText(bannerText, { ...bannerOpts, y: 8 });

        if (qrImage) {
          const qrSize = 45;
          page.drawImage(qrImage, {
            x: width - qrSize - 15,
            y: 15,
            width: qrSize,
            height: qrSize,
            opacity: 0.8,
          });
        }
      }

      const watermarkedBuffer = Buffer.from(await pdfDoc.save());
      const outputSha256Hash = crypto.createHash('sha256').update(watermarkedBuffer).digest('hex');

      await this.recordMetric((performance.now() - start) / 1000, true);
      return { watermarkedBuffer, watermarkToken, outputSha256Hash, renderedText, pageCount };
    } catch (err: unknown) {
      await this.recordMetric((performance.now() - start) / 1000, false, 'pdf_render_error');
      this.logger.error(`Watermark generation failed: ${err}`);
      if (document.requireWatermark) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.WATERMARK_GENERATION_FAILED,
          message: 'Failed to generate required security watermark. Access denied.',
        });
      }
      throw err;
    }
  }

  /**
   * Algorithm: 1-Indexed Single-Page PDF Sub-Document Extraction
   */
  async extractPdfPage(pdfBuffer: Buffer, pageNumber: number): Promise<Buffer> {
    const srcDoc = await PDFDocument.load(pdfBuffer, { ignoreEncryption: true });
    const pageIndex = pageNumber - 1;
    const totalPages = srcDoc.getPageCount();

    if (pageIndex < 0 || pageIndex >= totalPages) {
      throw new BadRequestException({
        errorCode: AppErrorCode.RESOURCE_NOT_FOUND,
        message: `Page ${pageNumber} does not exist (total pages: ${totalPages}).`,
      });
    }

    const subDoc = await PDFDocument.create();
    const [copiedPage] = await subDoc.copyPages(srcDoc, [pageIndex]);
    subDoc.addPage(copiedPage);
    return Buffer.from(await subDoc.save());
  }

  async recordWatermarkInstance(params: {
    watermarkConfigId: bigint;
    accessSessionId: string;
    documentVersionId: bigint;
    userId: bigint;
    watermarkToken: string;
    renderedText: string;
    outputSha256Hash: string;
    generatedAt?: Date;
  }): Promise<void> {
    await this.database.watermarkInstance.create({
      data: {
        id: randomUUID(),
        watermark_config_id: params.watermarkConfigId,
        access_session_id: params.accessSessionId,
        document_version_id: params.documentVersionId,
        user_id: params.userId,
        watermark_token: params.watermarkToken,
        rendered_text: params.renderedText.slice(0, 1000),
        output_sha256_hash: params.outputSha256Hash,
        generated_at: params.generatedAt ?? new Date(),
      },
    });
  }

  async getWatermarkConfig(classificationLevelId?: bigint | null): Promise<WatermarkConfigData> {
    return resolveWatermarkConfig(this.database, classificationLevelId);
  }

  private async recordMetric(
    durationSeconds: number,
    success: boolean,
    reason?: string,
  ): Promise<void> {
    try {
      const { MetricsService } = await import('../system-health/metrics.service.js');
      MetricsService.getInstance().recordWatermarkRender(durationSeconds, success, reason);
    } catch {
      // Optional metrics fallback
    }
  }
}

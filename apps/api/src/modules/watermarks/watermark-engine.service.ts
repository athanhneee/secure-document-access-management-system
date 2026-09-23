import { Injectable, Logger, ForbiddenException, BadRequestException } from '@nestjs/common';
import crypto, { randomUUID } from 'node:crypto';
import { PDFDocument, rgb, degrees, StandardFonts } from 'pdf-lib';
import QRCode from 'qrcode';
import { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface WatermarkUserData {
  id: bigint;
  username: string;
  fullName?: string | null | undefined;
  employeeCode?: string | null | undefined;
}

export interface WatermarkDocumentData {
  id: string;
  documentCode?: string | null | undefined;
  title: string;
  classificationName?: string | undefined;
  requireWatermark: boolean;
}

export interface WatermarkConfigData {
  id: bigint;
  template_text: string;
  opacity_percent: number;
  rotation_degrees: number;
  font_size: number;
  color_hex: string;
  include_qr_code: boolean;
  is_visible: boolean;
}

export interface WatermarkResult {
  watermarkedBuffer: Buffer;
  watermarkToken: string;
  outputSha256Hash: string;
  renderedText: string;
  pageCount: number;
}

@Injectable()
export class WatermarkEngineService {
  private readonly logger = new Logger(WatermarkEngineService.name);
  private readonly database: PrismaClient;

  constructor(databaseClient?: PrismaClient) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Generates a cryptographically strong, unique watermark token.
   */
  generateWatermarkToken(): string {
    return `WM-${crypto.randomBytes(24).toString('hex')}`;
  }

  /**
   * Parse hex color string (e.g. #808080) to pdf-lib RGB values (0..1).
   */
  private parseHexColor(hex: string): { r: number; g: number; b: number } {
    const clean = hex.replace('#', '');
    if (clean.length === 6) {
      const r = parseInt(clean.substring(0, 2), 16) / 255;
      const g = parseInt(clean.substring(2, 4), 16) / 255;
      const b = parseInt(clean.substring(4, 6), 16) / 255;
      return { r: isNaN(r) ? 0.5 : r, g: isNaN(g) ? 0.5 : g, b: isNaN(b) ? 0.5 : b };
    }
    return { r: 0.5, g: 0.5, b: 0.5 };
  }

  /**
   * Formats the visible watermark text template according to Prompt 13 requirement 4:
   * Full name or username, employee code, UTC timestamp, document code, and short token.
   */
  formatWatermarkText(
    template: string,
    user: WatermarkUserData,
    document: WatermarkDocumentData,
    token: string,
    now: Date = new Date(),
  ): string {
    const fullName = user.fullName?.trim() || user.username;
    const employeeCode = user.employeeCode?.trim() || `UID:${user.id.toString()}`;
    const documentCode = document.documentCode?.trim() || document.id.slice(0, 8);
    const utcTimestamp = now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    const classification = document.classificationName || 'CONFIDENTIAL';
    const cleanToken = token.replace(/^WM-/, '');
    const shortToken = cleanToken.slice(0, 12);

    let text = template;
    text = text.replace(/{classification}/g, classification);
    text = text.replace(/{fullName}/g, fullName);
    text = text.replace(/{username}/g, user.username);
    text = text.replace(/{employeeCode}/g, employeeCode);
    text = text.replace(/{documentCode}/g, documentCode);
    text = text.replace(/{timestamp}/g, utcTimestamp);
    text = text.replace(/{utcTimestamp}/g, utcTimestamp);
    text = text.replace(/{shortToken}/g, shortToken);

    // If template has no placeholders, generate standard full composite string
    if (!text.includes(user.username) && !text.includes(fullName)) {
      text = `${fullName} (${employeeCode}) | ${documentCode} | ${utcTimestamp} | ${shortToken}`;
    }

    return text;
  }

  /**
   * Generates a PNG QR code buffer encoding the watermark verification payload.
   */
  async generateQrCodeBuffer(payload: string): Promise<Buffer> {
    return await QRCode.toBuffer(payload, {
      type: 'png',
      width: 90,
      margin: 1,
      errorCorrectionLevel: 'M',
    });
  }

  /**
   * Applies visible watermark overlay and QR code onto all pages of a PDF document.
   * Requirement 6: Original file and hash remain unchanged; output derivative gets new SHA-256.
   * Requirement 4: Visible watermark with full name/username, employee code, timestamp, doc code, token.
   * Fail-Closed: If watermarking fails on a required document, throws ForbiddenException.
   */
  async applyWatermarkToPdf(
    pdfBuffer: Buffer,
    user: WatermarkUserData,
    document: WatermarkDocumentData,
    config: WatermarkConfigData,
    existingToken?: string,
    now: Date = new Date(),
  ): Promise<WatermarkResult> {
    try {
      const watermarkToken = existingToken || this.generateWatermarkToken();
      const renderedText = this.formatWatermarkText(
        config.template_text,
        user,
        document,
        watermarkToken,
        now,
      );

      // Load PDF
      const pdfDoc = await PDFDocument.load(pdfBuffer, { ignoreEncryption: true });
      const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
      const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
      const pages = pdfDoc.getPages();
      const pageCount = pages.length;

      const { r, g, b } = this.parseHexColor(config.color_hex);
      const color = rgb(r, g, b);
      const opacity = Math.min(Math.max(config.opacity_percent / 100, 0.05), 1.0);
      const rotation = degrees(config.rotation_degrees);
      const fontSize = Math.min(Math.max(config.font_size, 8), 24);

      // QR Code generation if enabled
      let qrImage: Awaited<ReturnType<typeof pdfDoc.embedPng>> | null = null;
      if (config.include_qr_code) {
        try {
          const qrPayload = JSON.stringify({
            token: watermarkToken,
            u: user.username,
            d: document.documentCode || document.id.slice(0, 8),
            t: now.toISOString(),
          });
          const qrBuffer = await this.generateQrCodeBuffer(qrPayload);
          qrImage = await pdfDoc.embedPng(qrBuffer);
        } catch (qrErr) {
          this.logger.warn(`QR code generation failed, proceeding with text watermark: ${qrErr}`);
        }
      }

      // Draw watermark on each page
      for (const page of pages) {
        const { width, height } = page.getSize();

        if (config.is_visible) {
          // 1. Repeating diagonal watermark grid
          const diagonalStepX = width / 2;
          const diagonalStepY = height / 3;

          for (let x = width * 0.1; x < width * 0.9; x += diagonalStepX) {
            for (let y = height * 0.15; y < height * 0.85; y += diagonalStepY) {
              page.drawText(renderedText, {
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

          // 2. Fixed security banner at top and bottom of page
          const bannerText = `[SECURE-DOC] ${renderedText}`;
          page.drawText(bannerText, {
            x: 20,
            y: height - 15,
            size: 7,
            font: boldFont,
            color: rgb(0.4, 0.4, 0.4),
            opacity: 0.7,
          });

          page.drawText(bannerText, {
            x: 20,
            y: 8,
            size: 7,
            font: boldFont,
            color: rgb(0.4, 0.4, 0.4),
            opacity: 0.7,
          });

          // 3. QR code at bottom-right corner if available
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
      }

      const watermarkedBytes = await pdfDoc.save();
      const watermarkedBuffer = Buffer.from(watermarkedBytes);
      const outputSha256Hash = crypto.createHash('sha256').update(watermarkedBuffer).digest('hex');

      return {
        watermarkedBuffer,
        watermarkToken,
        outputSha256Hash,
        renderedText,
        pageCount,
      };
    } catch (err: unknown) {
      this.logger.error(`Watermark generation failed: ${err}`);
      if (document.requireWatermark) {
        // Fail-closed: Never deliver unwatermarked document
        throw new ForbiddenException({
          errorCode: AppErrorCode.WATERMARK_GENERATION_FAILED,
          message: 'Failed to generate required security watermark. Access denied.',
        });
      }
      throw err;
    }
  }

  /**
   * Extracts a single page from a PDF for page-by-page preview streaming.
   * pageNumber is 1-indexed.
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

    const pageBytes = await subDoc.save();
    return Buffer.from(pageBytes);
  }

  /**
   * Records a watermark instance in the database.
   */
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
        rendered_text: params.renderedText,
        output_sha256_hash: params.outputSha256Hash,
        generated_at: params.generatedAt ?? new Date(),
      },
    });
  }

  /**
   * Retrieve active watermark configuration for a document classification level,
   * falling back to default or standard configuration.
   */
  async getWatermarkConfig(classificationLevelId?: bigint | null): Promise<WatermarkConfigData> {
    if (classificationLevelId) {
      const config = await this.database.watermarkConfig.findFirst({
        where: {
          classification_level_id: classificationLevelId,
          is_active: true,
        },
      });
      if (config) {
        return {
          id: config.id,
          template_text: config.template_text,
          opacity_percent: config.opacity_percent,
          rotation_degrees: config.rotation_degrees,
          font_size: config.font_size,
          color_hex: config.color_hex,
          include_qr_code: config.include_qr_code,
          is_visible: config.is_visible,
        };
      }
    }

    // Default config in database
    const defaultConfig = await this.database.watermarkConfig.findFirst({
      where: {
        is_default: true,
        is_active: true,
      },
    });

    if (defaultConfig) {
      return {
        id: defaultConfig.id,
        template_text: defaultConfig.template_text,
        opacity_percent: defaultConfig.opacity_percent,
        rotation_degrees: defaultConfig.rotation_degrees,
        font_size: defaultConfig.font_size,
        color_hex: defaultConfig.color_hex,
        include_qr_code: defaultConfig.include_qr_code,
        is_visible: defaultConfig.is_visible,
      };
    }

    // Built-in fallback config
    return {
      id: 1n,
      template_text: '{fullName} ({employeeCode}) | {documentCode} | {utcTimestamp} | {shortToken}',
      opacity_percent: 25,
      rotation_degrees: -30,
      font_size: 11,
      color_hex: '#808080',
      include_qr_code: true,
      is_visible: true,
    };
  }
}

/**
 * Module: Safe Sandboxed Office-to-PDF Converter Service
 * Algorithm: Pre-conversion OOXML security inspection followed by `Promise.race` deadline enforcement
 *   over headless Gotenberg conversion with deterministic internal A4 PDF fallback.
 */
import { GatewayTimeoutException, Injectable, Logger, Optional } from '@nestjs/common';
import { AppErrorCode } from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
import {
  extractOfficeFallbackText,
  inspectOfficeArchiveSecurity,
} from './office-archive-inspector.js';
import { convertWithGotenberg, renderSanitizedTextToPdf } from './office-fallback-pdf.js';

export interface OfficeConversionOptions {
  timeoutMs?: number;
  maxPages?: number;
}

@Injectable()
export class OfficeConverterService {
  private readonly logger = new Logger(OfficeConverterService.name);
  private readonly gotenbergUrl: string;
  private readonly gotenbergEnabled: boolean;

  constructor(@Optional() config?: AppConfigService) {
    if (config) {
      this.gotenbergUrl = config.get('GOTENBERG_URL');
      this.gotenbergEnabled = config.get('GOTENBERG_ENABLED') ?? true;
    } else {
      this.gotenbergUrl = process.env['GOTENBERG_URL'] ?? 'http://127.0.0.1:3003';
      this.gotenbergEnabled =
        process.env['NODE_ENV'] === 'test'
          ? process.env['GOTENBERG_ENABLED'] === 'true'
          : process.env['GOTENBERG_ENABLED'] !== 'false';
    }
  }

  /**
   * Algorithm: Deadline-Bounded Safe Office-to-PDF Conversion
   * Races `performSafeConversion` against a hard `timeoutMs` timer raising `OFFICE_CONVERSION_TIMEOUT`.
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
    await inspectOfficeArchiveSecurity(officeBuffer);

    const timeoutMs = options.timeoutMs ?? 10_000;
    const gotenbergPdf = await convertWithGotenberg(
      this.gotenbergUrl,
      this.gotenbergEnabled,
      officeBuffer,
      filename,
      timeoutMs,
      this.logger,
    );
    if (gotenbergPdf) {
      this.logger.log(`Rendered ${filename} to PDF using Gotenberg/LibreOffice headless engine.`);
      return gotenbergPdf;
    }

    this.logger.log(`Rendering ${filename} via built-in safe text-to-PDF fallback engine.`);
    const extractedText = await extractOfficeFallbackText(officeBuffer, filename);
    return await renderSanitizedTextToPdf(filename, extractedText, options.maxPages ?? 50);
  }
}

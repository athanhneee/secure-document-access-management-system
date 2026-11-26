/**
 * @module OfficeConverterService
 * Thuật toán: Chuyển đổi tài liệu Office (`.docx`, `.xlsx`, `.pptx`) sang PDF an toàn trong môi trường cô lập (`BUG-059`) —
 *   1. Dọn dẹp `clearTimeout(timeoutHandle)` trong `finally` tránh rò bộ hẹn giờ.
 *   2. Trên `NODE_ENV === 'production'` khi `gotenbergEnabled === true` mà bộ chuyển đổi lỗi, từ chối Fail-Closed `503 OFFICE_CONVERTER_UNAVAILABLE` thay vì âm thầm xuất PDF văn bản mất biểu đồ rồi ghi vào cache phái sinh 30 phút.
 *   3. Trên `development` / `test`, giữ nguyên fallback dựng PDF văn bản có cấu trúc để không phụ thuộc cứng Docker Gotenberg.
 */
import {
  GatewayTimeoutException,
  Injectable,
  Logger,
  Optional,
  ServiceUnavailableException,
} from '@nestjs/common';
import { AppErrorCode } from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
import {
  extractOfficeFallbackText,
  inspectOfficeArchiveSecurity,
} from './office-archive-inspector.js';
import { convertWithLocalLibreOffice } from './local-libreoffice.helper.js';
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
  private readonly nodeEnv: string;

  constructor(@Optional() config?: AppConfigService) {
    if (config) {
      this.gotenbergUrl = config.get('GOTENBERG_URL');
      this.gotenbergEnabled = config.get('GOTENBERG_ENABLED') ?? true;
      this.nodeEnv = config.get('NODE_ENV') ?? process.env['NODE_ENV'] ?? 'development';
    } else {
      this.nodeEnv = process.env['NODE_ENV'] ?? 'development';
      this.gotenbergUrl = process.env['GOTENBERG_URL'] ?? 'http://127.0.0.1:3003';
      this.gotenbergEnabled =
        this.nodeEnv === 'test'
          ? process.env['GOTENBERG_ENABLED'] === 'true'
          : process.env['GOTENBERG_ENABLED'] !== 'false';
    }
  }

  /**
   * Thuật toán: Chuyển đổi tài liệu Office sang PDF có ràng buộc thời hạn cứng (`Promise.race`) và thu dọn `clearTimeout` trong `finally`.
   */
  async convertOfficeToPdf(
    officeBuffer: Buffer,
    filename: string,
    options: OfficeConversionOptions = {},
  ): Promise<Buffer> {
    this.logger.log(`Safely converting Office document ${filename} to PDF`);
    const timeoutMs = options.timeoutMs ?? 10_000;
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;

    try {
      return await Promise.race([
        this.performSafeConversion(officeBuffer, filename, options),
        new Promise<Buffer>((_, reject) => {
          timeoutHandle = setTimeout(() => {
            reject(
              new GatewayTimeoutException({
                errorCode: AppErrorCode.OFFICE_CONVERSION_TIMEOUT,
                message: `Office document conversion exceeded timeout of ${timeoutMs}ms.`,
              }),
            );
          }, timeoutMs);
        }),
      ]);
    } finally {
      if (timeoutHandle !== undefined) {
        clearTimeout(timeoutHandle);
      }
    }
  }

  /**
   * Thuật toán: Kiểm định an ninh gói nén OOXML, ưu tiên kết xuất qua Gotenberg / LibreOffice;
   * Fail-Closed `503 OFFICE_CONVERTER_UNAVAILABLE` trên `production` khi `gotenbergEnabled === true`, và rơi về `renderSanitizedTextToPdf` ở `development`/`test`.
   */
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

    const localLibreOfficePdf = await convertWithLocalLibreOffice(
      officeBuffer,
      filename,
      timeoutMs,
    );
    if (localLibreOfficePdf) {
      this.logger.log(`Rendered ${filename} to PDF using host LibreOffice headless binary.`);
      return localLibreOfficePdf;
    }

    if (this.nodeEnv === 'production' && this.gotenbergEnabled) {
      this.logger.error(
        `Fail-closed: Office converter unavailable in production for ${filename}; refusing lossy text fallback.`,
      );
      throw new ServiceUnavailableException({
        errorCode:
          (AppErrorCode as Record<string, string>)['OFFICE_CONVERTER_UNAVAILABLE'] ??
          'OFFICE_CONVERTER_UNAVAILABLE',
        message: 'Office document conversion service is currently unavailable.',
      });
    }

    this.logger.log(`Rendering ${filename} via built-in safe text-to-PDF fallback engine.`);
    const extractedText = await extractOfficeFallbackText(officeBuffer, filename);
    return await renderSanitizedTextToPdf(filename, extractedText, options.maxPages ?? 50);
  }
}

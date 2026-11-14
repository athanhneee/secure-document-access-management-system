/**
 * @module OfficeConverterService
 * Thuật toán: Chuyển đổi tài liệu Office (`.docx`, `.xlsx`, `.pptx`) sang PDF an toàn trong môi trường cô lập —
 * kiểm tra an ninh cấu trúc lưu trữ OOXML trước khi xử lý, chạy đua thời hạn cứng (`Promise.race` `timeoutMs`)
 * qua dịch vụ Gotenberg/LibreOffice headless và tự động chuyển sang bộ dựng PDF văn bản thuần dự phòng khi cần.
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
   * Thuật toán: Chuyển đổi tài liệu Office sang PDF có ràng buộc thời hạn cứng (`Promise.race`).
   * Ném `GatewayTimeoutException(OFFICE_CONVERSION_TIMEOUT)` ngay khi thời gian xử lý vượt ngưỡng `timeoutMs`.
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

  /**
   * Thuật toán: Thực thi tuần tự quy trình kiểm định an ninh gói nén OOXML, ưu tiên kết xuất qua Gotenberg
   * và rơi về bộ phân trang văn bản thuần `renderSanitizedTextToPdf` nếu Gotenberg không khả dụng.
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

    this.logger.log(`Rendering ${filename} via built-in safe text-to-PDF fallback engine.`);
    const extractedText = await extractOfficeFallbackText(officeBuffer, filename);
    return await renderSanitizedTextToPdf(filename, extractedText, options.maxPages ?? 50);
  }
}

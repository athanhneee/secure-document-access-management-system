import type { DlpScanOptions, DlpScanResult, DlpViolation } from './icap.types.js';
import { decompressHttpContentForDlp } from './icap-content-decoder.js';
import { buildNormalizedDlpSurfaces } from './dlp-decoders.js';
import { evaluateDlpTextSurfaces, isValidLuhnCard, maskSensitiveSnippet } from './dlp-rules.js';
import {
  extractUncompressedZipXmlTextsSync,
  extractZipXmlTextsAsync,
} from './dlp-zip-inspector.js';

/**
 * Thuật toán / Tổng quan module:
 * Bộ máy phân tích và phòng chống thất thoát dữ liệu đa tầng (Multi-Surface Network DLP Engine):
 * - Quét bất đồng bộ (`scanPayloadAsync`) và đồng bộ (`scanPayload`) trên toàn bộ bề mặt: URI/query string,
 *   HTTP headers đóng gói, chuỗi giải mã URL, khối giải mã Base64 (`>= 24` ký tự), văn bản UTF-16LE và nội dung XML
 *   bên trong kho lưu trữ `.docx`/`.xlsx` (`word/document.xml`, `xl/sharedStrings.xml`).
 * - Cưỡng chế chặn **Fail-Closed** đối với `Content-Encoding` lạ/hỏng, bom nén và tệp ZIP mã hóa.
 */
export class DlpEngine {
  /**
   * Thuật toán: Kiểm tra tổng kiểm Luhn (Modulo-10 Checksum) cho dãy số thẻ thanh toán quốc tế.
   */
  public static isValidLuhn(cardNumber: string): boolean {
    return isValidLuhnCard(cardNumber);
  }

  /**
   * Thuật toán: Che giấu thông tin nhạy cảm (Partial Redaction Masking) cho bằng chứng pháp chứng.
   */
  public static maskSnippet(text: string): string {
    return maskSensitiveSnippet(text);
  }

  /**
   * Thuật toán: Đường ống quét DLP bất đồng bộ đầy đủ (`gzip`/`deflate`/`br`/`zstd` + `.docx`/`.xlsx` DEFLATE + Fail-Closed).
   */
  public static async scanPayloadAsync(
    buffer: Buffer,
    config?: DlpScanOptions,
  ): Promise<DlpScanResult> {
    const initialViolations: DlpViolation[] = [];
    const decompressed = await decompressHttpContentForDlp(buffer, {
      contentEncoding: config?.contentEncoding,
      allowTruncatedPreview: config?.allowTruncatedPreview,
      maxBodyBytes: config?.maxBodyBytes,
    });

    if (decompressed.bombDetected) {
      initialViolations.push({
        type: 'TOP_SECRET_CLASSIFICATION',
        severity: 'CRITICAL',
        rule: 'RULE_COMPRESSED_BOMB_EGRESS_PREVENTION',
        description:
          'Phát hiện luồng dữ liệu nén vượt ngưỡng an toàn DLP (nghi vấn né tránh bộ lọc bằng bom nén).',
        matchedSnippet: '[COMPRESSED_STREAM_LIMIT_EXCEEDED]',
      });
    } else if (decompressed.encodingError) {
      initialViolations.push({
        type: 'TOP_SECRET_CLASSIFICATION',
        severity: 'CRITICAL',
        rule: 'RULE_UNSUPPORTED_OR_CORRUPT_CONTENT_ENCODING',
        description:
          'Chặn Fail-Closed do Content-Encoding không được phép hoặc dữ liệu nén bị làm hỏng để né DLP.',
        matchedSnippet: `[${decompressed.encodingError}]`,
      });
    }

    const effectiveBuffer = decompressed.buffer;
    const zipInspection = await extractZipXmlTextsAsync(
      effectiveBuffer,
      config?.maxBodyBytes,
      Boolean(config?.allowTruncatedPreview),
    );
    if (zipInspection.bombDetected) {
      initialViolations.push({
        type: 'TOP_SECRET_CLASSIFICATION',
        severity: 'CRITICAL',
        rule: 'RULE_ARCHIVE_BOMB_EGRESS_PREVENTION',
        description: 'Phát hiện tệp lưu trữ ZIP/OOXML vượt ngưỡng giải nén an toàn (Zip Bomb).',
        matchedSnippet: '[ARCHIVE_LIMIT_EXCEEDED]',
      });
    } else if (zipInspection.archiveError) {
      initialViolations.push({
        type: 'TOP_SECRET_CLASSIFICATION',
        severity: 'CRITICAL',
        rule: 'RULE_UNINSPECTABLE_ARCHIVE_EGRESS_PREVENTION',
        description:
          'Chặn Fail-Closed đối với kho lưu trữ mã hóa hoặc luồng nén OOXML bất thường không thể kiểm tra DLP.',
        matchedSnippet: `[${zipInspection.archiveError}]`,
      });
    }

    const surfaces = buildNormalizedDlpSurfaces(effectiveBuffer, config, zipInspection.texts);
    const scannedBytes = Math.max(buffer.length, effectiveBuffer.length);
    return evaluateDlpTextSurfaces(surfaces, scannedBytes, config, initialViolations);
  }

  /**
   * Thuật toán: Quét đồng bộ trên bộ đệm không nén phục vụ kiểm thử đơn vị trong bộ nhớ (In-Memory Sync Scanner).
   */
  public static scanPayload(buffer: Buffer, config?: DlpScanOptions): DlpScanResult {
    const initialViolations: DlpViolation[] = [];
    if (config?.contentEncoding && config.contentEncoding.trim().toLowerCase() !== 'identity') {
      initialViolations.push({
        type: 'TOP_SECRET_CLASSIFICATION',
        severity: 'CRITICAL',
        rule: 'RULE_UNSUPPORTED_OR_CORRUPT_CONTENT_ENCODING',
        description: 'Yêu cầu sử dụng scanPayloadAsync cho luồng nén Content-Encoding.',
        matchedSnippet: '[SYNC_COMPRESSED_UNSUPPORTED]',
      });
    }
    const zipSync = extractUncompressedZipXmlTextsSync(buffer, config?.maxBodyBytes);
    if (zipSync.bombDetected || zipSync.archiveError) {
      initialViolations.push({
        type: 'TOP_SECRET_CLASSIFICATION',
        severity: 'CRITICAL',
        rule: 'RULE_UNINSPECTABLE_ARCHIVE_EGRESS_PREVENTION',
        description: 'Kho lưu trữ vượt ngưỡng hoặc mã hóa.',
        matchedSnippet: `[${zipSync.archiveError ?? 'ARCHIVE_LIMIT'}]`,
      });
    }
    const surfaces = buildNormalizedDlpSurfaces(buffer, config, zipSync.texts);
    return evaluateDlpTextSurfaces(surfaces, buffer.length, config, initialViolations);
  }
}

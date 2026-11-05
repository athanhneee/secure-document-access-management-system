/**
 * Module: PKZIP Handle Initialization & Entry Stream Inflation Helper
 * Thuật toán: Mở kho lưu trữ PKZIP chế độ `lazyEntries` (ánh xạ lỗi định dạng sang `400 INVALID_FILE_TYPE`)
 *   và đếm byte giải nén thực tế trên từng luồng để chặn Zip Bomb giả mạo header 32-bit.
 */
import { BadRequestException } from '@nestjs/common';
import yauzl, { type Entry, type ZipFile } from 'yauzl';
import { AppErrorCode } from '@sda/contracts';
import { createXmlStreamingSecurityScanner } from './zip-xml-security.helper.js';

/**
 * Thuật toán: Khởi tạo con trỏ PKZIP lười (`lazyEntries: true`) kèm chuẩn hóa lỗi mở tệp sang `400 INVALID_FILE_TYPE`.
 * Chặn việc `yauzl` ném `Error` thô gây HTTP 500 khi người dùng tải lên tệp nén bị cắt cụt hoặc sai chữ ký EOCD.
 */
export function openYauzlZip(source: Buffer | string): Promise<ZipFile> {
  // CONFLICT-RESOLVED: Bọc lỗi mở kho lưu trữ yauzl thành BadRequestException(INVALID_FILE_TYPE) thay vì để lọt Error thô sinh HTTP 500.
  const toInvalidZipError = (err?: Error | null) =>
    new BadRequestException({
      errorCode: AppErrorCode.INVALID_FILE_TYPE,
      message: `Invalid or corrupted Office OpenXML archive: ${err?.message ?? 'failed to open zip'}`,
    });

  return new Promise((resolve, reject) => {
    if (typeof source === 'string') {
      yauzl.open(source, { lazyEntries: true, autoClose: false }, (err, zip) => {
        if (err || !zip) return reject(toInvalidZipError(err));
        resolve(zip);
      });
    } else {
      yauzl.fromBuffer(source, { lazyEntries: true, autoClose: false }, (err, zip) => {
        if (err || !zip) return reject(toInvalidZipError(err));
        resolve(zip);
      });
    }
  });
}

/**
 * Thuật toán: Giải nén luồng kiểm soát định mức byte thực tế kết hợp quét cửa sổ trượt XML/RELS (Fail-Closed Stream Inflation).
 * Đếm trực tiếp số byte giải nén thực tế để đánh bại kỹ thuật làm giả trường `uncompressedSize` trong ZIP header,
 * đồng thời đưa 100% luồng `.xml`/`.rels` qua bộ quét XXE/SSRF mà không có ngoại lệ bỏ qua tệp lớn.
 */
export function inflateAndInspectZipEntry(params: {
  zipFile: ZipFile;
  entry: Entry;
  lowerName: string;
  maxTotalUncompressedSize: number;
  maxCompressionRatio: number;
  addActualBytes: (delta: number) => number;
  isSettled: () => boolean;
  finishReject: (err: Error) => void;
}): void {
  const {
    zipFile,
    entry,
    lowerName,
    maxTotalUncompressedSize,
    maxCompressionRatio,
    addActualBytes,
    isSettled,
    finishReject,
  } = params;
  const shouldInspectXml = lowerName.endsWith('.xml') || lowerName.endsWith('.rels');
  const xmlScanner = shouldInspectXml
    ? createXmlStreamingSecurityScanner(lowerName.endsWith('.rels'))
    : null;
  let entryActualBytes = 0;

  zipFile.openReadStream(entry, (streamErr, readStream) => {
    if (isSettled()) return;
    if (streamErr || !readStream) {
      return finishReject(
        new BadRequestException({
          errorCode: AppErrorCode.INVALID_FILE_TYPE,
          message: `Failed to read zip entry ${entry.fileName}: ${streamErr?.message ?? 'corrupt stream'}`,
        }),
      );
    }

    readStream.on('data', (chunk: Buffer) => {
      if (isSettled()) {
        readStream.destroy();
        return;
      }
      entryActualBytes += chunk.length;
      const actualTotal = addActualBytes(chunk.length);
      if (actualTotal > maxTotalUncompressedSize) {
        readStream.destroy();
        return finishReject(
          new BadRequestException({
            errorCode: AppErrorCode.VALIDATION_FAILED,
            message: `Zip archive actual inflated size exceeds limit of ${maxTotalUncompressedSize} bytes.`,
          }),
        );
      }
      if (entry.compressedSize > 64) {
        const actualRatio = entryActualBytes / entry.compressedSize;
        if (actualRatio > maxCompressionRatio) {
          readStream.destroy();
          return finishReject(
            new BadRequestException({
              errorCode: AppErrorCode.VALIDATION_FAILED,
              message: `Zip archive actual compression ratio (${actualRatio.toFixed(1)}) exceeds limit of ${maxCompressionRatio}.`,
            }),
          );
        }
      }
      if (xmlScanner) {
        const xmlIssue = xmlScanner.push(chunk);
        if (xmlIssue) {
          readStream.destroy();
          return finishReject(xmlIssue);
        }
      }
    });

    readStream.on('error', (err) => {
      finishReject(
        new BadRequestException({
          errorCode: AppErrorCode.INVALID_FILE_TYPE,
          message: `Corrupt compressed stream in zip archive: ${err.message}`,
        }),
      );
    });

    readStream.on('end', () => {
      if (isSettled()) return;
      if (xmlScanner) {
        const finalIssue = xmlScanner.finish();
        if (finalIssue) return finishReject(finalIssue);
      }
      zipFile.readEntry();
    });
  });
}

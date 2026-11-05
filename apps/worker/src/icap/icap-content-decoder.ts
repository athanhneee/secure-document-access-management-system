import {
  brotliDecompressSync,
  constants as zlibConstants,
  gunzipSync,
  inflateRawSync,
  inflateSync,
} from 'node:zlib';

/**
 * Thuật toán / Tổng quan module:
 * Bộ giải mã luồng khung truyền tải phân mảnh tuyến tính $O(N)$ (`IcapChunkStreamTracker`) và giải nén an toàn
 * `Content-Encoding` (`gzip`, `x-gzip`, `deflate`, `br`) có giới hạn trần chống bom giải nén (`25 MiB`) phục vụ DLP mạng.
 */

const MAX_DLP_DECOMPRESSED_BYTES = 25 * 1024 * 1024;
const MAX_DECOMPRESSION_LAYERS = 3;
const MAX_CHUNK_CONTROL_LINE_BYTES = 4096;

type ChunkTrackerPhase = 'SIZE_LINE' | 'DATA_PAYLOAD' | 'DATA_CRLF' | 'TRAILER_LINE';

/**
 * Algorithm / Thuật toán: Máy Trạng Thái Theo Dõi Khung Chunked Tuyến Tính $O(N)$ (Incremental RFC 3507 Chunk Framing Tracker).
 * Cơ chế hoạt động:
 *   - Duyệt từng mảnh `Buffer` TCP mới đến một lần duy nhất mà không nối mảng `Buffer.concat` lặp lại ($O(N^2)$).
 *   - Ở pha `DATA_PAYLOAD`, nhảy cóc con trỏ qua phần dữ liệu nhị phân bằng phép cộng số học $O(1)$ (`offset += skip`),
 *     vừa tiết kiệm CPU vừa tránh nhận nhầm chuỗi `0\r\n\r\n` nằm bên trong nội dung tệp.
 *   - Hỗ trợ đầy đủ tham số mở rộng chunk hợp lệ `;ext` (ví dụ `0; ieof\r\n\r\n`, `0;token=abc\r\n\r\n`) và trailer tùy chọn.
 */
export class IcapChunkStreamTracker {
  private phase: ChunkTrackerPhase = 'SIZE_LINE';
  private lineByteBuffer: number[] = [];
  private remainingDataBytes = 0;
  private crlfStage: 0 | 1 = 0;
  public zeroChunksCompleted = 0;
  public hasIeofTerminator = false;
  private pendingZeroHasIeof = false;

  public feed(chunk: Buffer): void {
    let offset = 0;
    while (offset < chunk.length) {
      if (this.phase === 'DATA_PAYLOAD') {
        const skip = Math.min(this.remainingDataBytes, chunk.length - offset);
        offset += skip;
        this.remainingDataBytes -= skip;
        if (this.remainingDataBytes === 0) {
          this.phase = 'DATA_CRLF';
          this.crlfStage = 0;
        }
        continue;
      }

      if (this.phase === 'DATA_CRLF') {
        const byte = chunk[offset++]!;
        if (this.crlfStage === 0) {
          if (byte !== 0x0d) {
            throw new Error('ICAP_400: Missing CR after chunk payload');
          }
          this.crlfStage = 1;
        } else {
          if (byte !== 0x0a) {
            throw new Error('ICAP_400: Missing LF after chunk payload');
          }
          this.phase = 'SIZE_LINE';
          this.lineByteBuffer.length = 0;
        }
        continue;
      }

      const byte = chunk[offset++]!;
      this.lineByteBuffer.push(byte);
      if (this.lineByteBuffer.length > MAX_CHUNK_CONTROL_LINE_BYTES) {
        throw new Error('ICAP_400: Chunk control line exceeds maximum safe length');
      }

      const len = this.lineByteBuffer.length;
      if (
        len >= 2 &&
        this.lineByteBuffer[len - 2] === 0x0d &&
        this.lineByteBuffer[len - 1] === 0x0a
      ) {
        const lineText = Buffer.from(this.lineByteBuffer.slice(0, len - 2)).toString('utf-8');
        this.lineByteBuffer.length = 0;

        if (this.phase === 'SIZE_LINE') {
          const trimmed = lineText.trim();
          const semiParts = trimmed.split(';');
          const hexSizeStr = semiParts[0]?.trim() ?? '';
          if (!/^[0-9a-fA-F]+$/u.test(hexSizeStr)) {
            throw new Error('ICAP_400: Invalid chunk size hex encoding');
          }
          const chunkSize = parseInt(hexSizeStr, 16);
          if (!Number.isSafeInteger(chunkSize) || chunkSize < 0) {
            throw new Error('ICAP_400: Invalid chunk size');
          }

          if (chunkSize === 0) {
            const extensions = semiParts
              .slice(1)
              .map((part) => part.trim().toLowerCase())
              .filter(Boolean);
            this.pendingZeroHasIeof = extensions.includes('ieof');
            this.phase = 'TRAILER_LINE';
          } else {
            this.remainingDataBytes = chunkSize;
            this.phase = 'DATA_PAYLOAD';
          }
        } else {
          // TRAILER_LINE: an empty line (\r\n right after 0[;ext]\r\n or after trailer headers) finishes the zero-chunk.
          if (lineText.length === 0) {
            this.zeroChunksCompleted += 1;
            if (this.pendingZeroHasIeof) {
              this.hasIeofTerminator = true;
            }
            this.pendingZeroHasIeof = false;
            this.phase = 'SIZE_LINE';
          }
        }
      }
    }
  }
}

function isMaxOutputExceededError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const code = (err as { code?: string }).code;
  const message = (err as { message?: string }).message ?? '';
  return (
    code === 'ERR_BUFFER_TOO_LARGE' ||
    message.includes('maxOutputLength') ||
    message.includes('Cannot create a Buffer larger than')
  );
}

/**
 * Algorithm / Thuật toán: Giải Nén Tải Trọng HTTP Có Trần Chống Bom Giải Nén (Bounded HTTP Content-Encoding Decoder).
 * Cơ chế hoạt động:
 *   - Phân tách chuỗi `Content-Encoding` theo thứ tự ngược chiều nén (tối đa 3 lớp lồng nhau: `gzip`, `x-gzip`, `deflate`, `br`).
 *   - Áp trần cứng `maxOutputLength = 25 MiB` trên mọi bộ giải nén `node:zlib`; hỗ trợ `Z_SYNC_FLUSH` cho luồng Preview cắt ngắn.
 *   - Nếu vượt trần `maxOutputLength`, bật cờ `bombDetected = true` để bộ lọc DLP chặn Fail-Closed.
 */
export function decompressHttpContentForDlp(
  buffer: Buffer,
  contentEncoding?: string,
  allowTruncatedPreview = false,
): { buffer: Buffer; bombDetected: boolean } {
  if (buffer.length === 0) {
    return { buffer, bombDetected: false };
  }

  let encodings: string[] = [];
  if (contentEncoding && contentEncoding.trim().length > 0) {
    encodings = contentEncoding
      .split(',')
      .map((item) => item.trim().toLowerCase())
      .filter((item) => item.length > 0 && item !== 'identity');
  } else if (buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b) {
    encodings = ['gzip'];
  }

  if (encodings.length === 0) {
    return { buffer, bombDetected: false };
  }
  if (encodings.length > MAX_DECOMPRESSION_LAYERS) {
    return { buffer, bombDetected: true };
  }

  let current = buffer;
  for (let i = encodings.length - 1; i >= 0; i--) {
    const enc = encodings[i]!;
    try {
      if (enc === 'gzip' || enc === 'x-gzip') {
        current = gunzipSync(current, {
          maxOutputLength: MAX_DLP_DECOMPRESSED_BYTES,
          ...(allowTruncatedPreview ? { finishFlush: zlibConstants.Z_SYNC_FLUSH } : {}),
        });
      } else if (enc === 'br') {
        current = brotliDecompressSync(current, {
          maxOutputLength: MAX_DLP_DECOMPRESSED_BYTES,
          ...(allowTruncatedPreview ? { finishFlush: zlibConstants.BROTLI_OPERATION_FLUSH } : {}),
        });
      } else if (enc === 'deflate') {
        try {
          current = inflateSync(current, {
            maxOutputLength: MAX_DLP_DECOMPRESSED_BYTES,
            ...(allowTruncatedPreview ? { finishFlush: zlibConstants.Z_SYNC_FLUSH } : {}),
          });
        } catch (zlibErr) {
          if (isMaxOutputExceededError(zlibErr)) throw zlibErr;
          current = inflateRawSync(current, {
            maxOutputLength: MAX_DLP_DECOMPRESSED_BYTES,
            ...(allowTruncatedPreview ? { finishFlush: zlibConstants.Z_SYNC_FLUSH } : {}),
          });
        }
      }
    } catch (err) {
      if (isMaxOutputExceededError(err)) {
        return { buffer: current, bombDetected: true };
      }
      // On truncated preview or mislabelled header, return best-effort decoded buffer so raw fallback still scans.
      return { buffer: current, bombDetected: false };
    }
  }

  return { buffer: current, bombDetected: false };
}

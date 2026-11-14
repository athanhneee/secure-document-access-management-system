import { promisify } from 'node:util';
import {
  brotliDecompress,
  constants as zlibConstants,
  gunzip,
  inflate,
  inflateRaw,
  zstdDecompress,
} from 'node:zlib';

/**
 * Thuật toán / Tổng quan module:
 * - Máy trạng thái khung truyền tải `IcapChunkStreamTracker` tuyến tính $O(N)$ dừng sạch ngay tại `0\r\n\r\n` mà không nuốt byte pipelining.
 * - Bộ giải nén bất đồng bộ `decompressHttpContentForDlp` (`gzip`, `deflate`, `br`, `zstd` trên Node 24) áp trần `maxOutputLength`
 *   và chặn **Fail-Closed** mọi `Content-Encoding` lạ hoặc dữ liệu nén hỏng.
 */

export const MAX_DLP_DECOMPRESSED_BYTES = 25 * 1024 * 1024;
const MAX_DECOMPRESSION_LAYERS = 3;
const MAX_CHUNK_CONTROL_LINE_BYTES = 4096;

const gunzipAsync = promisify(gunzip);
const inflateAsync = promisify(inflate);
const inflateRawAsync = promisify(inflateRaw);
const brotliDecompressAsync = promisify(brotliDecompress);
const zstdDecompressAsync = promisify(zstdDecompress);

type ChunkTrackerPhase = 'SIZE_LINE' | 'DATA_PAYLOAD' | 'DATA_CRLF' | 'TRAILER_LINE';

/**
 * Thuật toán: Máy Trạng Thái Theo Dõi Khung Chunked Tuyến Tính $O(N)$ Hỗ Trợ Pipelining Keep-Alive.
 * Dừng quét ngay khi đạt đủ `targetZeroChunks` (hoặc `ieof`) để không đọc nhầm dòng yêu cầu ICAP kế tiếp trên cùng socket.
 */
export class IcapChunkStreamTracker {
  private phase: ChunkTrackerPhase = 'SIZE_LINE';
  private lineByteBuffer: number[] = [];
  private remainingDataBytes = 0;
  private crlfStage: 0 | 1 = 0;
  public zeroChunksCompleted = 0;
  public hasIeofTerminator = false;
  private pendingZeroHasIeof = false;

  public feed(chunk: Buffer, targetZeroChunks = 1): void {
    let offset = 0;
    while (offset < chunk.length) {
      if (this.hasIeofTerminator || this.zeroChunksCompleted >= targetZeroChunks) {
        return;
      }

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
          if (byte !== 0x0d) throw new Error('ICAP_400: Missing CR after chunk payload');
          this.crlfStage = 1;
        } else {
          if (byte !== 0x0a) throw new Error('ICAP_400: Missing LF after chunk payload');
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
          const semiParts = lineText.trim().split(';');
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
        } else if (lineText.length === 0) {
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

export function isMaxOutputExceededError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const code = (err as { code?: string }).code;
  const message = (err as { message?: string }).message ?? '';
  return (
    code === 'ERR_BUFFER_TOO_LARGE' ||
    message.includes('maxOutputLength') ||
    message.includes('Cannot create a Buffer larger than')
  );
}

export interface DecompressionResult {
  buffer: Buffer;
  bombDetected: boolean;
  encodingError?: string;
}

/**
 * Thuật toán: Giải Nén Bất Đồng Bộ Tải Trọng HTTP Có Trần Chống Bom Nén & Cưỡng Chế Fail-Closed (`gzip`, `deflate`, `br`, `zstd`).
 * - Từ chối Fail-Closed (`encodingError`) mọi `Content-Encoding` không nằm trong danh sách trắng hoặc dữ liệu nén hỏng trên luồng hoàn chỉnh.
 */
export async function decompressHttpContentForDlp(
  buffer: Buffer,
  options?: {
    contentEncoding?: string | undefined;
    allowTruncatedPreview?: boolean | undefined;
    maxBodyBytes?: number | undefined;
  },
): Promise<DecompressionResult> {
  const maxOutputLength = options?.maxBodyBytes ?? MAX_DLP_DECOMPRESSED_BYTES;
  const allowTruncatedPreview = Boolean(options?.allowTruncatedPreview);
  const explicitHeader = Boolean(options?.contentEncoding && options.contentEncoding.trim());

  let encodings: string[] = [];
  if (explicitHeader) {
    encodings = options!
      .contentEncoding!.split(',')
      .map((item) => item.trim().toLowerCase())
      .filter((item) => item.length > 0 && item !== 'identity');
  } else if (buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b) {
    encodings = ['gzip'];
  } else if (
    buffer.length >= 4 &&
    buffer[0] === 0x28 &&
    buffer[1] === 0xb5 &&
    buffer[2] === 0x2f &&
    buffer[3] === 0xfd
  ) {
    encodings = ['zstd'];
  }

  if (encodings.length === 0) return { buffer, bombDetected: false };
  if (encodings.length > MAX_DECOMPRESSION_LAYERS) return { buffer, bombDetected: true };

  for (const enc of encodings) {
    if (enc !== 'gzip' && enc !== 'x-gzip' && enc !== 'deflate' && enc !== 'br' && enc !== 'zstd') {
      return { buffer, bombDetected: false, encodingError: `UNSUPPORTED_CONTENT_ENCODING:${enc}` };
    }
  }

  if (buffer.length === 0) return { buffer, bombDetected: false };

  let current = buffer;
  for (let i = encodings.length - 1; i >= 0; i--) {
    const enc = encodings[i]!;
    try {
      if (enc === 'gzip' || enc === 'x-gzip') {
        current = await gunzipAsync(current, {
          maxOutputLength,
          ...(allowTruncatedPreview ? { finishFlush: zlibConstants.Z_SYNC_FLUSH } : {}),
        });
      } else if (enc === 'br') {
        current = await brotliDecompressAsync(current, {
          maxOutputLength,
          ...(allowTruncatedPreview ? { finishFlush: zlibConstants.BROTLI_OPERATION_FLUSH } : {}),
        });
      } else if (enc === 'zstd') {
        current = await zstdDecompressAsync(current, {
          maxOutputLength,
          ...(allowTruncatedPreview ? { finishFlush: zlibConstants.ZSTD_e_flush } : {}),
        });
      } else if (enc === 'deflate') {
        try {
          current = await inflateAsync(current, {
            maxOutputLength,
            ...(allowTruncatedPreview ? { finishFlush: zlibConstants.Z_SYNC_FLUSH } : {}),
          });
        } catch (zlibErr) {
          if (isMaxOutputExceededError(zlibErr)) throw zlibErr;
          current = await inflateRawAsync(current, {
            maxOutputLength,
            ...(allowTruncatedPreview ? { finishFlush: zlibConstants.Z_SYNC_FLUSH } : {}),
          });
        }
      }
    } catch (err) {
      if (isMaxOutputExceededError(err)) return { buffer: current, bombDetected: true };
      if (allowTruncatedPreview) return { buffer: current, bombDetected: false };
      return {
        buffer: current,
        bombDetected: false,
        encodingError: `CORRUPT_CONTENT_ENCODING:${enc}`,
      };
    }
  }

  return { buffer: current, bombDetected: false };
}

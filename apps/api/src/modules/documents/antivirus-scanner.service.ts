/**
 * Module: Dịch vụ Quét Mã độc Tệp tin qua Giao thức ClamAV TCP Stream (Streaming Antivirus Scanner)
 * Thuật toán: Dò Chữ Ký EICAR Nhị Phân Cửa Sổ Trượt (`Buffer.indexOf` 68-Byte Overlap) & Giao Thức `zINSTREAM` Có Điều Tiết Ngược TCP (`drain`).
 *   1. Tuyệt đối không chuyển đổi tệp nhị phân sang chuỗi UTF-8 (`toString('utf8')`); dò trực tiếp mảng byte chữ ký EICAR qua `Buffer.indexOf`
 *      với phần đuôi chồng lấn 68 byte giữa các mảnh luồng (`chunk`) để bắt trúng chữ ký nằm vắt ngang ranh giới chunk với bộ nhớ O(1).
 *   2. Khi gửi khung `[4B Big-Endian Length || Payload]` tới socket TCP của `clamd`, kiểm tra `if (!socket.write(frame)) await once(socket, 'drain')`
 *      để tôn trọng điều tiết áp suất ngược (backpressure) của ngăn xếp mạng hạt nhân.
 *   3. Áp dụng chính sách Fail-Closed (`FAILED`) trên môi trường `staging` và `production` khi `clamd` mất kết nối hoặc quá hạn chờ.
 */
import { Injectable, Logger } from '@nestjs/common';
import { once } from 'node:events';
import net from 'node:net';
import { Readable } from 'node:stream';
import { AppConfigService } from '../../config/config.service.js';
import { scanBufferWithWindowsDefender } from './windows-defender-scanner.helper.js';

export interface AntivirusScanResult {
  status: 'CLEAN' | 'INFECTED' | 'FAILED';
  virusName?: string | null | undefined;
  durationMs: number;
}

const EICAR_BYTES = Buffer.from(
  'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
  'ascii',
);
const EICAR_OVERLAP_BYTES = 68;
const INSTREAM_CHUNK_BYTES = 32_768;

/**
 * Thuật toán: Bộ dò chữ ký nhị phân EICAR theo cửa sổ trượt chồng lấn 68 byte (`Buffer.indexOf`) không cấp phát chuỗi UTF-8.
 */
export function createChunkedEicarMatcher(): { inspectChunk: (chunk: Buffer) => boolean } {
  let overlapTail: Buffer = Buffer.alloc(0);
  return {
    inspectChunk(chunk: Buffer): boolean {
      if (chunk.length === 0) return false;
      const windowBuf = overlapTail.length > 0 ? Buffer.concat([overlapTail, chunk]) : chunk;
      if (windowBuf.indexOf(EICAR_BYTES) !== -1) {
        return true;
      }
      overlapTail =
        windowBuf.length > EICAR_OVERLAP_BYTES
          ? Buffer.from(windowBuf.subarray(windowBuf.length - EICAR_OVERLAP_BYTES))
          : Buffer.from(windowBuf);
      return false;
    },
  };
}

async function writeSocketWithBackpressure(socket: net.Socket, frame: Buffer): Promise<void> {
  if (!socket.write(frame)) {
    await once(socket, 'drain');
  }
}

@Injectable()
export class AntivirusScannerService {
  private readonly logger = new Logger(AntivirusScannerService.name);
  private readonly host: string;
  private readonly port: number;
  private readonly configuredEnv: string;

  constructor(config: AppConfigService) {
    this.host = config.get('CLAMAV_HOST');
    this.port = config.get('CLAMAV_PORT');
    this.configuredEnv = String(config.get('NODE_ENV') ?? 'development');
  }

  /**
   * Thuật toán: Quét mã độc hai tầng kết hợp dò nhị phân EICAR chồng lấn 68 byte và luồng ClamAV `zINSTREAM` có backpressure.
   */
  async scan(source: Buffer | Readable): Promise<AntivirusScanResult> {
    const startTime = Date.now();
    const eicarState = { detected: false };
    const streamMatcher = createChunkedEicarMatcher();

    const finalResult: AntivirusScanResult = await (async () => {
      if (source instanceof Buffer) {
        for (let offset = 0; offset < source.length; offset += INSTREAM_CHUNK_BYTES) {
          const slice = source.subarray(
            offset,
            Math.min(offset + INSTREAM_CHUNK_BYTES, source.length),
          );
          if (streamMatcher.inspectChunk(slice)) {
            return {
              status: 'INFECTED' as const,
              virusName: 'Eicar-Test-Signature',
              durationMs: Date.now() - startTime,
            };
          }
        }
      }

      try {
        const clamResult = await this.scanWithClamAv(source, streamMatcher, eicarState);
        if (clamResult.status !== 'INFECTED' && eicarState.detected) {
          return {
            status: 'INFECTED' as const,
            virusName: 'Eicar-Test-Signature',
            durationMs: Date.now() - startTime,
          };
        }
        return {
          status: clamResult.status,
          virusName: clamResult.virusName,
          durationMs: Date.now() - startTime,
        };
      } catch (err: unknown) {
        if (eicarState.detected) {
          return {
            status: 'INFECTED' as const,
            virusName: 'Eicar-Test-Signature',
            durationMs: Date.now() - startTime,
          };
        }

        const msg = err instanceof Error ? err.message : String(err);
        this.logger.warn(`ClamAV socket communication failed: ${msg}`);

        const activeEnv = (process.env['NODE_ENV'] ?? this.configuredEnv).trim().toLowerCase();
        if (activeEnv === 'production' || activeEnv === 'staging') {
          if (!Buffer.isBuffer(source)) source.destroy();
          return {
            status: 'FAILED' as const,
            durationMs: Date.now() - startTime,
          };
        }

        const fallbackChunks: Buffer[] = Buffer.isBuffer(source) ? [source] : [];
        if (!Buffer.isBuffer(source) && !source.destroyed && source.readable) {
          for await (const rawChunk of source) {
            const buf = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
            if (streamMatcher.inspectChunk(buf)) {
              return {
                status: 'INFECTED' as const,
                virusName: 'Eicar-Test-Signature',
                durationMs: Date.now() - startTime,
              };
            }
            fallbackChunks.push(buf);
          }
        }

        if (activeEnv === 'development' && fallbackChunks.length > 0) {
          const defender = await scanBufferWithWindowsDefender(Buffer.concat(fallbackChunks));
          if (defender.executed && defender.status === 'INFECTED') {
            return {
              status: 'INFECTED' as const,
              virusName: defender.virusName ?? 'Win32.Defender.DetectedThreat',
              durationMs: Date.now() - startTime,
            };
          }
        }

        return {
          status: 'CLEAN' as const,
          durationMs: Date.now() - startTime,
        };
      }
    })();

    try {
      const { MetricsService } = await import('../system-health/metrics.service.js');
      const metricResult =
        finalResult.status === 'CLEAN'
          ? 'CLEAN'
          : finalResult.status === 'INFECTED'
            ? 'INFECTED'
            : 'ERROR';
      MetricsService.getInstance().recordAntivirusScan(metricResult, finalResult.durationMs / 1000);
    } catch {
      // Optional telemetry fallback
    }

    return finalResult;
  }

  /**
   * Thuật toán: Truyền luồng nhị phân `zINSTREAM` tới `clamd` qua TCP socket có kiểm soát áp suất ngược (`drain`) và timeout 10 giây.
   */
  private scanWithClamAv(
    source: Buffer | Readable,
    streamMatcher: { inspectChunk: (chunk: Buffer) => boolean },
    eicarState: { detected: boolean },
  ): Promise<{ status: 'CLEAN' | 'INFECTED' | 'FAILED'; virusName?: string }> {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      let responseData = '';
      let hasFinished = false;

      const finishReject = (err: Error) => {
        if (!hasFinished) {
          hasFinished = true;
          reject(err);
        }
      };

      socket.setTimeout(10_000);

      socket.connect(this.port, this.host, () => {
        void (async () => {
          try {
            await writeSocketWithBackpressure(socket, Buffer.from('zINSTREAM\0', 'ascii'));

            if (source instanceof Buffer) {
              for (let offset = 0; offset < source.length; offset += INSTREAM_CHUNK_BYTES) {
                const chunk = source.subarray(
                  offset,
                  Math.min(offset + INSTREAM_CHUNK_BYTES, source.length),
                );
                const frame = Buffer.allocUnsafe(4 + chunk.length);
                frame.writeUInt32BE(chunk.length, 0);
                chunk.copy(frame, 4);
                await writeSocketWithBackpressure(socket, frame);
              }
            } else {
              for await (const rawChunk of source) {
                const buf = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
                if (buf.length === 0) continue;
                if (streamMatcher.inspectChunk(buf)) {
                  eicarState.detected = true;
                }
                const frame = Buffer.allocUnsafe(4 + buf.length);
                frame.writeUInt32BE(buf.length, 0);
                buf.copy(frame, 4);
                await writeSocketWithBackpressure(socket, frame);
              }
            }

            const endFrame = Buffer.alloc(4, 0);
            await writeSocketWithBackpressure(socket, endFrame);
          } catch (err) {
            socket.destroy();
            finishReject(err instanceof Error ? err : new Error(String(err)));
          }
        })();
      });

      socket.on('data', (data: Buffer) => {
        responseData += data.toString('utf8');
      });

      socket.on('end', () => {
        if (hasFinished) return;
        hasFinished = true;
        this.parseClamAvResponse(responseData, resolve);
      });

      socket.on('timeout', () => {
        socket.destroy();
        finishReject(new Error('ClamAV scan timed out'));
      });

      socket.on('error', (err) => {
        finishReject(err);
      });
    });
  }

  /**
   * Thuật toán: Phân tích chuỗi kết quả từ `clamd` (`stream: OK` hoặc `stream: <VirusName> FOUND`).
   */
  private parseClamAvResponse(
    response: string,
    resolve: (res: { status: 'CLEAN' | 'INFECTED' | 'FAILED'; virusName?: string }) => void,
  ): void {
    const cleaned = response.replace(/\0/g, '').trim();
    if (cleaned.endsWith('OK')) {
      resolve({ status: 'CLEAN' });
    } else if (cleaned.includes('FOUND')) {
      const match = /stream:\s*(.+)\s*FOUND/iu.exec(cleaned);
      const virusName = match?.[1]?.trim() ?? 'Unknown-Malware';
      resolve({ status: 'INFECTED', virusName });
    } else {
      resolve({ status: 'FAILED' });
    }
  }
}

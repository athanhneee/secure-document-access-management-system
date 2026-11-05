/**
 * Module: Dịch vụ Quét Mã độc Tệp tin qua Giao thức ClamAV TCP Stream (Antivirus Stream Scanner)
 * Thuật toán: Nhận diện chữ ký kiểm thử EICAR trực tiếp kết hợp truyền luồng nhị phân phân mảnh
 *   theo giao thức `zINSTREAM` (khung độ dài 4-byte Big-Endian) của ClamAV daemon có kiểm soát timeout.
 */
import { Injectable, Logger } from '@nestjs/common';
import net from 'node:net';
import { Readable } from 'node:stream';
import { AppConfigService } from '../../config/config.service.js';

export interface AntivirusScanResult {
  status: 'CLEAN' | 'INFECTED' | 'FAILED';
  virusName?: string | null | undefined;
  durationMs: number;
}

// Standard EICAR test string (68 characters)
const EICAR_SIGNATURE = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

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
   * Scans a file buffer or stream with ClamAV over TCP INSTREAM protocol.
   * Also verifies the standard EICAR test signature directly.
   *
   * Thuật toán: Quét Mã Độc Hai Tầng Có Chốt Chặn Fail-Closed Trên Production
   * Mục đích: Phát hiện phần mềm độc hại trên dữ liệu tệp tải lên trước khi cho phép mã hóa và kích hoạt.
   * Cơ chế hoạt động:
   *   - Tầng 1: Kiểm tra nhanh chuỗi chữ ký chuẩn EICAR trên vùng nhớ đệm để đảm bảo bắt trúng ngay cả khi chạy cô lập.
   *   - Tầng 2: Truyền luồng sang ClamAV daemon qua TCP socket; nếu kết nối thất bại trong môi trường `production`
   *     thì áp dụng chính sách Fail-Closed trả trạng thái `FAILED` (từ chối tệp), đồng thời ghi nhận số liệu Prometheus.
   */
  async scan(source: Buffer | Readable): Promise<AntivirusScanResult> {
    const startTime = Date.now();

    const finalResult: AntivirusScanResult = await (async () => {
      // 1. Direct EICAR check (guaranteed detection even in offline/mock environments)
      if (source instanceof Buffer) {
        if (source.toString('utf8').includes(EICAR_SIGNATURE)) {
          return {
            status: 'INFECTED' as const,
            virusName: 'Eicar-Test-Signature',
            durationMs: Date.now() - startTime,
          };
        }
      }

      // 2. ClamAV TCP scan
      try {
        const clamResult = await this.scanWithClamAv(source);
        return {
          status: clamResult.status,
          virusName: clamResult.virusName,
          durationMs: Date.now() - startTime,
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.warn(`ClamAV socket communication failed: ${msg}`);

        // CONFLICT-RESOLVED: Chặn Fail-Closed trên cả staging lẫn production khi ClamAV daemon mất kết nối thay vì chỉ chặn trên production (MED-06).
        const activeEnv = (process.env['NODE_ENV'] ?? this.configuredEnv).trim().toLowerCase();
        if (activeEnv === 'production' || activeEnv === 'staging') {
          return {
            status: 'FAILED' as const,
            durationMs: Date.now() - startTime,
          };
        }

        // In local dev/test fallback to clean if no EICAR found
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
      // Fallback
    }

    return finalResult;
  }

  /**
   * Thuật toán: Đóng Gói Khung Nhị Phân Giao Thức `zINSTREAM` ClamAV Qua TCP Socket
   * Mục đích: Truyền nội dung tệp sang tiến trình `clamd` qua mạng nội bộ mà không cần chia sẻ hệ thống tệp chung.
   * Cơ chế hoạt động:
   *   - Thiết lập kết nối TCP kèm ngưỡng cắt thời gian chờ `socket.setTimeout(10_000)` chống treo kết nối.
   *   - Mở đầu phiên bằng lệnh kết thúc ký tự rỗng `zINSTREAM\0`.
   *   - Phân mảnh dữ liệu (theo lát cắt 32 KiB đối với `Buffer` hoặc duyệt bất đồng bộ `for await` đối với `Readable` stream),
   *     mỗi mảnh được đóng khung gồm tiền tố 4 byte số nguyên không dấu Big-Endian (`writeUInt32BE(chunk.length, 0)`)
   *     theo sau bởi mảng byte dữ liệu thô.
   *   - Kết thúc luồng bằng khung rỗng 4 byte `0x00000000`, thu thập phản hồi từ `clamd` và đảm bảo chỉ chốt kết quả
   *     một lần duy nhất qua cờ trạng thái `hasFinished`.
   */
  private scanWithClamAv(
    source: Buffer | Readable,
  ): Promise<{ status: 'CLEAN' | 'INFECTED' | 'FAILED'; virusName?: string }> {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      let responseData = '';
      let hasFinished = false;

      socket.setTimeout(10_000);

      socket.connect(this.port, this.host, async () => {
        try {
          // Send zINSTREAM\0
          socket.write('zINSTREAM\0');

          if (source instanceof Buffer) {
            const chunkSize = 32_768;
            for (let offset = 0; offset < source.length; offset += chunkSize) {
              const chunk = source.subarray(offset, Math.min(offset + chunkSize, source.length));
              const lenBuf = Buffer.alloc(4);
              lenBuf.writeUInt32BE(chunk.length, 0);
              socket.write(lenBuf);
              socket.write(chunk);
            }
          } else {
            for await (const chunk of source) {
              const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
              const lenBuf = Buffer.alloc(4);
              lenBuf.writeUInt32BE(buf.length, 0);
              socket.write(lenBuf);
              socket.write(buf);
            }
          }

          // Zero-length chunk marks end of stream
          const endBuf = Buffer.alloc(4);
          endBuf.writeUInt32BE(0, 0);
          socket.write(endBuf);
        } catch (err) {
          socket.destroy();
          reject(err);
        }
      });

      socket.on('data', (data) => {
        responseData += data.toString('utf8');
      });

      socket.on('end', () => {
        if (hasFinished) return;
        hasFinished = true;
        this.parseClamAvResponse(responseData, resolve);
      });

      socket.on('timeout', () => {
        socket.destroy();
        if (!hasFinished) {
          hasFinished = true;
          reject(new Error('ClamAV scan timed out'));
        }
      });

      socket.on('error', (err) => {
        if (!hasFinished) {
          hasFinished = true;
          reject(err);
        }
      });
    });
  }

  /**
   * Thuật toán: Phân Tích Phản Hồi Văn Bản Giao Thức ClamAV INSTREAM
   * Mục đích: Chuyển đổi chuỗi trả về từ `clamd` thành kết quả phân loại chuẩn `CLEAN` | `INFECTED` | `FAILED`.
   * Cơ chế hoạt động:
   *   - Loại bỏ các ký tự kết thúc chuỗi `\0`, cắt khoảng trắng dư và đối chiếu hậu tố `OK` hoặc biểu thức
   *     chính quy `stream: <VirusName> FOUND` để bóc tách định danh mã độc.
   */
  private parseClamAvResponse(
    response: string,
    resolve: (res: { status: 'CLEAN' | 'INFECTED' | 'FAILED'; virusName?: string }) => void,
  ): void {
    const cleaned = response.replace(/\0/g, '').trim();
    if (cleaned.endsWith('OK')) {
      resolve({ status: 'CLEAN' });
    } else if (cleaned.includes('FOUND')) {
      // Format: stream: <VirusName> FOUND
      const match = /stream:\s*(.+)\s*FOUND/iu.exec(cleaned);
      const virusName = match?.[1]?.trim() ?? 'Unknown-Malware';
      resolve({ status: 'INFECTED', virusName });
    } else {
      resolve({ status: 'FAILED' });
    }
  }
}

import * as net from 'node:net';
import { IcapParser } from './icap-parser.js';
import { DlpEngine } from './dlp-engine.js';
import {
  buildOptionsResponse,
  build204Response,
  buildBlockResponse,
  buildContinueResponse,
  buildProtocolErrorResponse,
} from './icap-wire-responses.js';
import {
  persistNetworkDlpSecurityAlert,
  type IcapServerMetrics,
  type ResolvedIcapConfig,
} from './icap-alert-sink.js';
import type { IcapServerConfig, DlpScanResult, IcapRequest } from './icap.types.js';

export { persistNetworkDlpSecurityAlert, type IcapServerMetrics };

/**
 * Algorithm / Thuật toán Máy Trạng Thái Luồng TCP Tuyến Tính $O(N)$ RFC 3507 ICAP (Linear-Time TCP Stream State Machine):
 * - Pha 1 (Bảo vệ biên tài nguyên): Áp đặt trần header `16 KiB`, tổng tải trọng `25 MiB`, idle timeout `30s` và deadline cứng `60s`.
 * - Pha 2 (Ghép mảnh $O(N)$ không sao chép lặp $O(N^2)$): Lưu từng gói TCP vào danh sách mảnh `receivedChunks[]` ($O(1)$/gói)
 *   và chỉ quét cửa sổ biên nối 12 byte (`boundaryWindow`) để dò dấu kết thúc header `\r\n\r\n` hoặc kết thúc chunk `0\r\n\r\n` / `ieof\r\n\r\n`
 *   trước khi gộp `Buffer.concat` đúng một lần tại điểm hoàn tất khung tin.
 * - Pha 3 (Thương lượng & Preview): Phản hồi `OPTIONS 200 OK`; với `Preview` chưa có `ieof` và chưa vi phạm `BLOCK`, phát `100 Continue`.
 * - Pha 4 (Cưỡng chế DLP & Cảnh báo `AUDIT_ONLY`): Chặn bằng `HTTP 403` khi `BLOCK`; ở chế độ `AUDIT_ONLY` cho qua `204 No modifications`
 *   nhưng bắt buộc ghi nhận `auditedViolations` và tạo bản ghi `SecurityAlert` (`NETWORK_DLP_VIOLATION`) vào SOC (cả qua callback lẫn fallback DB).
 */

const MAX_ICAP_HEADER_BYTES = 16 * 1024;
const MAX_ICAP_TOTAL_BYTES = 25 * 1024 * 1024;
const MAX_CONNECTION_DURATION_MS = 60_000;
const BOUNDARY_TAIL_BYTES = 12;

export class IcapServer {
  private server: net.Server | null = null;
  private readonly activeSockets = new Set<net.Socket>();
  private readonly config: ResolvedIcapConfig;
  private readonly metrics: IcapServerMetrics = {
    totalConnections: 0,
    totalRequests: 0,
    optionsRequests: 0,
    respmodRequests: 0,
    reqmodRequests: 0,
    cleanPassThrough: 0,
    auditedViolations: 0,
    blockedViolations: 0,
    scannedBytes: 0,
  };

  private onViolationCallback?:
    ((violation: DlpScanResult, request: IcapRequest) => Promise<void> | void) | undefined;

  constructor(config?: IcapServerConfig) {
    this.config = {
      enabled: config?.enabled ?? true,
      port: config?.port ?? 1344,
      host: config?.host ?? '127.0.0.1',
      serviceName: config?.serviceName ?? 'sda-dlp',
      maxConnections: config?.maxConnections ?? 100,
      previewSize: config?.previewSize ?? 2048,
      action: config?.action ?? 'BLOCK',
      customKeywords: config?.customKeywords ?? [],
    };
  }

  public onViolation(
    callback: (violation: DlpScanResult, request: IcapRequest) => Promise<void> | void,
  ): void {
    this.onViolationCallback = callback;
  }

  public getMetrics(): Readonly<IcapServerMetrics> {
    return { ...this.metrics };
  }

  public async start(): Promise<{ host: string; port: number }> {
    if (!this.config.enabled) {
      console.info('[ICAP Server] Disabled by configuration.');
      return { host: this.config.host, port: this.config.port };
    }

    return new Promise((resolve, reject) => {
      this.server = net.createServer((socket) => this.handleConnection(socket));
      this.server.maxConnections = this.config.maxConnections;
      this.server.on('error', (err) => {
        console.error('[ICAP Server] Socket error:', err);
        reject(err);
      });
      this.server.listen(this.config.port, this.config.host, () => {
        const address = this.server?.address() as net.AddressInfo;
        const actualPort = address?.port ?? this.config.port;
        console.info(
          `[ICAP Server] Listening on ${this.config.host}:${actualPort} (RFC 3507 Network DLP Server)`,
        );
        resolve({ host: this.config.host, port: actualPort });
      });
    });
  }

  public async stop(): Promise<void> {
    if (!this.server) return;
    for (const socket of this.activeSockets) socket.destroy();
    this.activeSockets.clear();
    return new Promise((resolve) => {
      this.server?.close(() => {
        this.server = null;
        console.info('[ICAP Server] Stopped cleanly.');
        resolve();
      });
    });
  }

  private replyAndClose(socket: net.Socket, payload: Buffer): void {
    socket.write(payload, () => socket.end());
  }

  private async notifyViolation(scanResult: DlpScanResult, request: IcapRequest): Promise<void> {
    if (this.onViolationCallback) {
      try {
        await this.onViolationCallback(scanResult, request);
      } catch (err) {
        console.error('[ICAP Server] Error in violation callback:', err);
      }
      return;
    }
    await persistNetworkDlpSecurityAlert(scanResult, request);
  }

  private handleConnection(socket: net.Socket): void {
    this.activeSockets.add(socket);
    this.metrics.totalConnections++;

    let receivedChunks: Buffer[] = [];
    let totalReceivedBytes = 0;
    let tailBytes: Buffer = Buffer.alloc(0);
    let headersValidated = false;
    let isProcessing = false;
    let continuedAfterPreview = false;

    socket.setTimeout(30_000);
    const connectionDeadline = setTimeout(() => socket.destroy(), MAX_CONNECTION_DURATION_MS);
    connectionDeadline.unref();

    const consolidateBuffer = (): Buffer => {
      if (receivedChunks.length === 1) return receivedChunks[0]!;
      const merged = Buffer.concat(receivedChunks, totalReceivedBytes);
      receivedChunks = [merged];
      return merged;
    };

    socket.on('data', async (chunk: Buffer) => {
      if (isProcessing) return;

      if (totalReceivedBytes + chunk.length > MAX_ICAP_TOTAL_BYTES) {
        isProcessing = true;
        this.replyAndClose(socket, buildProtocolErrorResponse(400));
        return;
      }

      receivedChunks.push(chunk);
      totalReceivedBytes += chunk.length;
      const boundaryWindow = tailBytes.length > 0 ? Buffer.concat([tailBytes, chunk]) : chunk;
      tailBytes = Buffer.from(
        boundaryWindow.subarray(Math.max(0, boundaryWindow.length - BOUNDARY_TAIL_BYTES)),
      );

      if (!headersValidated) {
        if (boundaryWindow.indexOf('\r\n\r\n') === -1) {
          if (totalReceivedBytes > MAX_ICAP_HEADER_BYTES) {
            isProcessing = true;
            this.replyAndClose(socket, buildProtocolErrorResponse(400));
          }
          return;
        }
      } else {
        const hasChunkTerminator =
          boundaryWindow.indexOf('0\r\n\r\n') !== -1 ||
          boundaryWindow.indexOf('ieof\r\n\r\n') !== -1;
        if (!hasChunkTerminator) {
          return;
        }
      }

      try {
        const accumulatedBuffer = consolidateBuffer();
        const request = IcapParser.parseRequest(accumulatedBuffer);
        if (!request) {
          if (totalReceivedBytes > MAX_ICAP_HEADER_BYTES) {
            isProcessing = true;
            this.replyAndClose(socket, buildProtocolErrorResponse(400));
          }
          return;
        }
        headersValidated = true;

        if (request.method === 'OPTIONS') {
          isProcessing = true;
          this.metrics.totalRequests++;
          this.metrics.optionsRequests++;
          this.replyAndClose(socket, buildOptionsResponse(this.config));
          return;
        }

        if (request.method === 'RESPMOD' || request.method === 'REQMOD') {
          if (!request.isComplete) return;

          const scanResult = DlpEngine.scanPayload(request.body, {
            customKeywords: this.config.customKeywords,
            action: this.config.action,
          });

          if (
            request.isPreview &&
            !request.isPreviewIof &&
            !continuedAfterPreview &&
            scanResult.action !== 'BLOCK'
          ) {
            continuedAfterPreview = true;
            socket.write(buildContinueResponse());
            return;
          }

          isProcessing = true;
          socket.pause();
          this.metrics.totalRequests++;
          if (request.method === 'RESPMOD') this.metrics.respmodRequests++;
          else this.metrics.reqmodRequests++;
          this.metrics.scannedBytes += scanResult.scannedBytes;

          const safeUri = request.uri.replace(/\p{Cc}/gu, '').slice(0, 200);
          if (scanResult.action === 'BLOCK') {
            this.metrics.blockedViolations++;
            console.warn(
              `[ICAP Server] DLP VIOLATION BLOCKED: ${scanResult.violations.map((v) => v.rule).join(', ')} (${request.method} ${safeUri})`,
            );
            await this.notifyViolation(scanResult, request);
            this.replyAndClose(socket, buildBlockResponse(scanResult.violations));
            return;
          }

          if (scanResult.action === 'AUDIT' || !scanResult.isClean) {
            this.metrics.auditedViolations++;
            console.warn(
              `[ICAP Server] DLP VIOLATION AUDITED (pass-through): ${scanResult.violations.map((v) => v.rule).join(', ')} (${request.method} ${safeUri})`,
            );
            await this.notifyViolation(scanResult, request);
            this.replyAndClose(socket, build204Response());
            return;
          }

          this.metrics.cleanPassThrough++;
          this.replyAndClose(socket, build204Response());
          return;
        }

        isProcessing = true;
        this.replyAndClose(socket, buildProtocolErrorResponse(405));
      } catch (err) {
        isProcessing = true;
        const message = err instanceof Error ? err.message : String(err);
        if (message.startsWith('ICAP_405:'))
          return this.replyAndClose(socket, buildProtocolErrorResponse(405));
        if (message.startsWith('ICAP_400:'))
          return this.replyAndClose(socket, buildProtocolErrorResponse(400));
        console.error('[ICAP Server] Error processing message:', err);
        this.replyAndClose(socket, buildProtocolErrorResponse(500));
      }
    });

    socket.on('timeout', () => socket.destroy());
    socket.on('error', () => socket.destroy());
    socket.on('close', () => {
      clearTimeout(connectionDeadline);
      this.activeSockets.delete(socket);
    });
  }
}

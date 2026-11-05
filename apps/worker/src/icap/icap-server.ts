import * as net from 'node:net';
import { IcapParser } from './icap-parser.js';
import { IcapChunkStreamTracker } from './icap-content-decoder.js';
import { buildOptionsResponse, buildProtocolErrorResponse } from './icap-wire-responses.js';
import {
  persistNetworkDlpSecurityAlert,
  type IcapServerMetrics,
  type ResolvedIcapConfig,
} from './icap-alert-sink.js';
import { executeIcapDlpEvaluation, type ConnectionStreamState } from './icap-request-handler.js';
import type { IcapServerConfig, DlpScanResult, IcapRequest } from './icap.types.js';

export { persistNetworkDlpSecurityAlert, type IcapServerMetrics };

/**
 * Algorithm / Thuật toán Máy Trạng Thái Luồng TCP Tuyến Tính $O(N)$ RFC 3507 ICAP (Linear-Time TCP Stream State Machine):
 * - Pha 1 (Bảo vệ biên tài nguyên): Áp đặt trần header kết hợp `16 KiB`, tổng tải trọng `25 MiB`, idle timeout `30s` và deadline cứng `60s`.
 * - Pha 2 (Ghép mảnh $O(N)$ hỗ trợ `null-body` phân mảnh TCP): Giữ `headersValidated = false` khi `request.incompleteHeaders === true`
 *   để chờ nhận đủ HTTP header đóng gói; ngay khi `!request.incompleteHeaders` và `request.isComplete === true` (bao gồm `null-body`),
 *   xử lý tức thì mà không treo 30s chờ `0\r\n\r\n`.
 * - Pha 3 (Thương lượng & Preview): Phản hồi `OPTIONS 200 OK`; với `Preview` chưa có `ieof` và chưa vi phạm `BLOCK`, phát `100 Continue`.
 * - Pha 4 (Cưỡng chế DLP & Cảnh báo `AUDIT_ONLY`): Ủy quyền cho `executeIcapDlpEvaluation` chặn `403` hoặc ghi cảnh báo `204`.
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

  private async handleParsedRequest(
    socket: net.Socket,
    request: IcapRequest,
    state: ConnectionStreamState,
  ): Promise<void> {
    await executeIcapDlpEvaluation({
      socket,
      request,
      state,
      config: this.config,
      metrics: this.metrics,
      onViolationCallback: this.onViolationCallback,
    });
  }

  /**
   * Thuật toán: Máy trạng thái ghép khung TCP ICAP hai giai đoạn tuyến tính $O(N)$ (`!headersValidated` -> `IcapChunkStreamTracker`),
   * xử lý dứt điểm `null-body` phân mảnh TCP, chống bypass `Preview: 0` phân mảnh (CRIT-03), triệt tiêu nối mảng $O(N^2)$ và hỗ trợ mọi `;ext` hợp lệ.
   */
  private handleConnection(socket: net.Socket): void {
    this.activeSockets.add(socket);
    this.metrics.totalConnections++;

    let receivedChunks: Buffer[] = [];
    let totalReceivedBytes = 0;
    let tailBytes: Buffer = Buffer.alloc(0);
    let icapHeaderComplete = false;
    let headersValidated = false;
    let isPreviewRequest = false;
    let chunkTracker: IcapChunkStreamTracker | null = null;
    const state: ConnectionStreamState = {
      isProcessing: false,
      continuedAfterPreview: false,
    };

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
      if (state.isProcessing) return;

      if (totalReceivedBytes + chunk.length > MAX_ICAP_TOTAL_BYTES) {
        state.isProcessing = true;
        this.replyAndClose(socket, buildProtocolErrorResponse(400));
        return;
      }

      receivedChunks.push(chunk);
      totalReceivedBytes += chunk.length;

      try {
        if (!headersValidated) {
          const boundaryWindow = tailBytes.length > 0 ? Buffer.concat([tailBytes, chunk]) : chunk;
          tailBytes = Buffer.from(
            boundaryWindow.subarray(Math.max(0, boundaryWindow.length - BOUNDARY_TAIL_BYTES)),
          );

          if (!icapHeaderComplete) {
            if (boundaryWindow.indexOf('\r\n\r\n') === -1) {
              if (totalReceivedBytes > MAX_ICAP_HEADER_BYTES) {
                state.isProcessing = true;
                this.replyAndClose(socket, buildProtocolErrorResponse(400));
              }
              return;
            }
            icapHeaderComplete = true;
          }

          const accumulatedBuffer = consolidateBuffer();
          const request = IcapParser.parseRequest(accumulatedBuffer, {
            continuedAfterPreview: state.continuedAfterPreview,
          });
          // CONFLICT-RESOLVED: Giữ headersValidated = false khi request.incompleteHeaders === true và kiểm soát trần MAX_ICAP_HEADER_BYTES trên tổng ICAP + HTTP headers.
          if (!request || request.incompleteHeaders) {
            if (totalReceivedBytes > MAX_ICAP_HEADER_BYTES) {
              state.isProcessing = true;
              this.replyAndClose(socket, buildProtocolErrorResponse(400));
            }
            return;
          }

          const icapHeaderEnd = accumulatedBuffer.indexOf('\r\n\r\n');
          const bodyOffset = request.encapsulated.resBody ?? request.encapsulated.reqBody;
          const httpHeaderEnd = bodyOffset ?? request.encapsulated.nullBody ?? 0;
          if (icapHeaderEnd + 4 + httpHeaderEnd > MAX_ICAP_HEADER_BYTES) {
            state.isProcessing = true;
            this.replyAndClose(socket, buildProtocolErrorResponse(400));
            return;
          }

          if (request.method === 'OPTIONS') {
            headersValidated = true;
            state.isProcessing = true;
            this.metrics.totalRequests++;
            this.metrics.optionsRequests++;
            this.replyAndClose(socket, buildOptionsResponse(this.config));
            return;
          }

          if (request.method !== 'RESPMOD' && request.method !== 'REQMOD') {
            state.isProcessing = true;
            this.replyAndClose(socket, buildProtocolErrorResponse(405));
            return;
          }

          // CONFLICT-RESOLVED: Không tự ý phát 100 Continue trước khi nhận khung chunk 0\r\n\r\n của Preview: 0 (chặn CRIT-03).
          headersValidated = true;
          isPreviewRequest = Boolean(request.isPreview);
          tailBytes = Buffer.alloc(0);

          if (request.encapsulated.nullBody === undefined && bodyOffset !== undefined) {
            chunkTracker = new IcapChunkStreamTracker();
            const bodyStart = icapHeaderEnd + 4 + bodyOffset;
            if (bodyStart < accumulatedBuffer.length) {
              chunkTracker.feed(accumulatedBuffer.subarray(bodyStart));
            }
          }

          if (!request.isComplete) {
            return;
          }

          await this.handleParsedRequest(socket, request, state);
          return;
        }

        if (chunkTracker) {
          chunkTracker.feed(chunk);
          const requiredZeroChunks = isPreviewRequest && state.continuedAfterPreview ? 2 : 1;
          if (
            chunkTracker.zeroChunksCompleted < requiredZeroChunks &&
            !chunkTracker.hasIeofTerminator
          ) {
            return;
          }
        }

        const request = IcapParser.parseRequest(consolidateBuffer(), {
          continuedAfterPreview: state.continuedAfterPreview,
        });
        if (!request || request.incompleteHeaders || !request.isComplete) {
          return;
        }
        await this.handleParsedRequest(socket, request, state);
      } catch (err) {
        state.isProcessing = true;
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

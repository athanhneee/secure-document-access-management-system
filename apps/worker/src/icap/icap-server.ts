import * as net from 'node:net';
import { IcapParser } from './icap-parser.js';
import { DlpEngine } from './dlp-engine.js';
import type { IcapServerConfig, DlpScanResult, IcapRequest } from './icap.types.js';

export interface IcapServerMetrics {
  totalConnections: number;
  totalRequests: number;
  optionsRequests: number;
  respmodRequests: number;
  reqmodRequests: number;
  cleanPassThrough: number;
  blockedViolations: number;
  scannedBytes: number;
}

interface ResolvedIcapConfig {
  enabled: boolean;
  port: number;
  host: string;
  serviceName: string;
  maxConnections: number;
  previewSize: number;
  action: 'BLOCK' | 'AUDIT_ONLY';
  customKeywords: string[];
}

const MAX_ICAP_HEADER_BYTES = 16 * 1024;
const MAX_ICAP_TOTAL_BYTES = 25 * 1024 * 1024;
const MAX_CONNECTION_DURATION_MS = 60_000;

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
      this.server = net.createServer((socket) => {
        this.handleConnection(socket);
      });

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
    if (!this.server) {
      return;
    }

    for (const socket of this.activeSockets) {
      socket.destroy();
    }
    this.activeSockets.clear();

    return new Promise((resolve) => {
      this.server?.close(() => {
        this.server = null;
        console.info('[ICAP Server] Stopped cleanly.');
        resolve();
      });
    });
  }

  private handleConnection(socket: net.Socket): void {
    this.activeSockets.add(socket);
    this.metrics.totalConnections++;

    let accumulatedBuffer = Buffer.alloc(0);
    let isProcessing = false;
    let continuedAfterPreview = false;

    socket.setTimeout(30_000); // 30 seconds idle timeout
    const connectionDeadline = setTimeout(() => {
      socket.destroy();
    }, MAX_CONNECTION_DURATION_MS);
    connectionDeadline.unref();

    socket.on('data', async (chunk) => {
      if (isProcessing) {
        return;
      }

      if (accumulatedBuffer.length + chunk.length > MAX_ICAP_TOTAL_BYTES) {
        isProcessing = true;
        const entityTooLarge = Buffer.from(
          'ICAP/1.0 400 Bad Request\r\nConnection: close\r\n\r\n',
          'utf-8',
        );
        socket.write(entityTooLarge, () => {
          socket.end();
        });
        return;
      }

      accumulatedBuffer = Buffer.concat([accumulatedBuffer, chunk]);

      if (
        accumulatedBuffer.indexOf('\r\n\r\n') === -1 &&
        accumulatedBuffer.length > MAX_ICAP_HEADER_BYTES
      ) {
        isProcessing = true;
        const headerTooLarge = Buffer.from(
          'ICAP/1.0 400 Bad Request\r\nConnection: close\r\n\r\n',
          'utf-8',
        );
        socket.write(headerTooLarge, () => {
          socket.end();
        });
        return;
      }

      try {
        const request = IcapParser.parseRequest(accumulatedBuffer);
        if (!request) {
          // Waiting for complete ICAP header (\r\n\r\n)
          return;
        }

        if (request.method === 'OPTIONS') {
          isProcessing = true;
          this.metrics.totalRequests++;
          this.metrics.optionsRequests++;
          const response = IcapParser.buildOptionsResponse(this.config);
          socket.write(response, () => {
            socket.end();
          });
          return;
        }

        if (request.method === 'RESPMOD' || request.method === 'REQMOD') {
          if (!request.isComplete) {
            // Wait for all chunked body segments (0\r\n\r\n) before making final pass/block decision
            return;
          }

          // Scan accumulated body against DLP engine
          const scanResult = DlpEngine.scanPayload(request.body, {
            customKeywords: this.config.customKeywords,
            action: this.config.action,
          });

          // RFC 3507 §4.5: If client sent an incomplete Preview (no ieof) and preview is clean so far,
          // request the remainder of the body via 100 Continue so full payload is inspected.
          if (
            request.isPreview &&
            !request.isPreviewIof &&
            !continuedAfterPreview &&
            scanResult.action !== 'BLOCK'
          ) {
            continuedAfterPreview = true;
            socket.write(Buffer.from('ICAP/1.0 100 Continue\r\n\r\n', 'utf-8'));
            return;
          }

          isProcessing = true;
          socket.pause();

          this.metrics.totalRequests++;
          if (request.method === 'RESPMOD') {
            this.metrics.respmodRequests++;
          } else {
            this.metrics.reqmodRequests++;
          }
          this.metrics.scannedBytes += scanResult.scannedBytes;

          if (scanResult.action === 'BLOCK') {
            this.metrics.blockedViolations++;
            const safeUri = request.uri.replace(/\p{Cc}/gu, '').slice(0, 200);
            console.warn(
              `[ICAP Server] DLP VIOLATION BLOCKED: ${scanResult.violations.map((v) => v.rule).join(', ')} (${request.method} ${safeUri})`,
            );

            if (this.onViolationCallback) {
              try {
                await this.onViolationCallback(scanResult, request);
              } catch (err) {
                console.error('[ICAP Server] Error in violation callback:', err);
              }
            }

            const blockResponse = IcapParser.buildBlockResponse(scanResult.violations);
            socket.write(blockResponse, () => {
              socket.end();
            });
            return;
          }

          // Allow: Clean content pass-through
          this.metrics.cleanPassThrough++;
          const allowResponse = IcapParser.build204Response();
          socket.write(allowResponse, () => {
            socket.end();
          });
          return;
        }

        isProcessing = true;
        const errorResponse = Buffer.from(
          'ICAP/1.0 405 Method Not Allowed\r\nConnection: close\r\n\r\n',
          'utf-8',
        );
        socket.write(errorResponse, () => {
          socket.end();
        });
      } catch (err) {
        isProcessing = true;
        const message = err instanceof Error ? err.message : String(err);
        if (message.startsWith('ICAP_405:')) {
          const methodNotAllowed = Buffer.from(
            'ICAP/1.0 405 Method Not Allowed\r\nConnection: close\r\n\r\n',
            'utf-8',
          );
          socket.write(methodNotAllowed, () => {
            socket.end();
          });
          return;
        }
        if (message.startsWith('ICAP_400:')) {
          const badRequest = Buffer.from(
            'ICAP/1.0 400 Bad Request\r\nConnection: close\r\n\r\n',
            'utf-8',
          );
          socket.write(badRequest, () => {
            socket.end();
          });
          return;
        }
        console.error('[ICAP Server] Error processing message:', err);
        const serverError = Buffer.from(
          'ICAP/1.0 500 Server Error\r\nConnection: close\r\n\r\n',
          'utf-8',
        );
        socket.write(serverError, () => {
          socket.end();
        });
      }
    });

    socket.on('timeout', () => {
      socket.destroy();
    });

    socket.on('error', () => {
      socket.destroy();
    });

    socket.on('close', () => {
      clearTimeout(connectionDeadline);
      this.activeSockets.delete(socket);
    });
  }
}

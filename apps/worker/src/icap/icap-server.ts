import * as net from 'node:net';
import { MAX_DLP_DECOMPRESSED_BYTES } from './icap-content-decoder.js';
import {
  persistNetworkDlpSecurityAlert,
  type IcapServerMetrics,
  type ResolvedIcapConfig,
} from './icap-alert-sink.js';
import { attachIcapConnectionHandler } from './icap-connection-handler.js';
import { InspectionSemaphore } from './icap-request-handler.js';
import type { IcapServerConfig, DlpScanResult, IcapRequest } from './icap.types.js';

export { persistNetworkDlpSecurityAlert, type IcapServerMetrics };

/**
 * Thuật toán Máy Chủ Mạng RFC 3507 ICAP DLP:
 * - Lắng nghe trên `ICAP_BIND_HOST ?? '0.0.0.0'` và giới hạn đồng thời tối đa `16` luồng giải nén qua `InspectionSemaphore`.
 * - Ủy quyền xử lý khung TCP phân mảnh, `Preview: 0` và pipelining keep-alive cho `attachIcapConnectionHandler`.
 */
export class IcapServer {
  private server: net.Server | null = null;
  private readonly activeSockets = new Set<net.Socket>();
  private readonly config: ResolvedIcapConfig;
  private readonly inspectionSemaphore: InspectionSemaphore;
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
    const resolvedHost =
      config?.host ??
      process.env['ICAP_BIND_HOST']?.trim() ??
      process.env['ICAP_SERVER_HOST']?.trim() ??
      '0.0.0.0';
    this.config = {
      enabled: config?.enabled ?? true,
      port: config?.port ?? 1344,
      host: resolvedHost,
      serviceName: config?.serviceName ?? 'sda-dlp',
      maxConnections: config?.maxConnections ?? 100,
      maxConcurrentInspections: config?.maxConcurrentInspections ?? 16,
      maxBodyBytes: config?.maxBodyBytes ?? MAX_DLP_DECOMPRESSED_BYTES,
      previewSize: config?.previewSize ?? 2048,
      action: config?.action ?? 'BLOCK',
      customKeywords: config?.customKeywords ?? [],
    };
    this.inspectionSemaphore = new InspectionSemaphore(this.config.maxConcurrentInspections);
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
      this.server = net.createServer((socket) =>
        attachIcapConnectionHandler({
          socket,
          activeSockets: this.activeSockets,
          config: this.config,
          metrics: this.metrics,
          semaphore: this.inspectionSemaphore,
          getViolationCallback: () => this.onViolationCallback,
        }),
      );
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
}

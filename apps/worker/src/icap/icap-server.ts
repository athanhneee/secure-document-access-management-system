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
 * Thuật toán: Phân giải đồng nhất địa chỉ lắng nghe ICAP từ tham số hoặc biến môi trường (`ICAP_BIND_HOST` / `ICAP_SERVER_HOST`).
 */
export function resolveIcapBindHost(
  explicitHost?: string,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const candidates = [explicitHost, env['ICAP_BIND_HOST'], env['ICAP_SERVER_HOST']];
  for (const candidate of candidates) {
    const trimmed = candidate?.trim();
    if (trimmed) return trimmed;
  }
  return '0.0.0.0';
}

/**
 * Thuật toán: Phân giải đồng nhất cổng lắng nghe ICAP từ tham số (`0` cho cổng động kiểm thử) hoặc biến môi trường (`ICAP_PORT` / `ICAP_SERVER_PORT`).
 */
export function resolveIcapListenPort(
  explicitPort?: number,
  env: NodeJS.ProcessEnv = process.env,
): number {
  if (
    explicitPort !== undefined &&
    Number.isInteger(explicitPort) &&
    explicitPort >= 0 &&
    explicitPort <= 65_535
  ) {
    return explicitPort;
  }
  for (const raw of [env['ICAP_PORT'], env['ICAP_SERVER_PORT']]) {
    const trimmed = raw?.trim();
    if (!trimmed) continue;
    const parsed = Number(trimmed);
    if (Number.isInteger(parsed) && parsed > 0 && parsed <= 65_535) {
      return parsed;
    }
  }
  return 1344;
}

/**
 * Thuật toán Máy Chủ Mạng RFC 3507 ICAP DLP:
 * - Lắng nghe trên `ICAP_BIND_HOST` / `ICAP_SERVER_HOST` (`'0.0.0.0'`) và cổng `ICAP_PORT` / `ICAP_SERVER_PORT` (`1344`),
 *   giới hạn đồng thời tối đa `16` luồng giải nén qua `InspectionSemaphore`.
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
    // CONFLICT-RESOLVED: Hỗ trợ đồng nhất cả `ICAP_PORT`/`ICAP_SERVER_PORT` và `ICAP_BIND_HOST`/`ICAP_SERVER_HOST` ngay trong constructor `IcapServer`.
    this.config = {
      enabled: config?.enabled ?? true,
      port: resolveIcapListenPort(config?.port),
      host: resolveIcapBindHost(config?.host),
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

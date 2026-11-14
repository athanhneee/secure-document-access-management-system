import {
  IcapServer,
  persistNetworkDlpSecurityAlert,
  resolveIcapBindHost,
  resolveIcapListenPort,
} from './icap-server.js';
import type { IcapServerConfig } from './icap.types.js';

/**
 * Thuật toán / Tổng quan module:
 * Trình khởi tạo và gắn kết dịch vụ nền máy chủ RFC 3507 ICAP Network DLP vào tiến trình Worker trung tâm,
 * lắng nghe trên `ICAP_BIND_HOST ?? '0.0.0.0'` và cổng `ICAP_PORT ?? 1344`, chuẩn hóa hành động chính sách Fail-Closed
 * và giới hạn đồng thời luồng giải nén DLP (`maxConcurrentInspections = 16`).
 */

/**
 * Thuật toán chuẩn hóa chế độ xử lý vi phạm ICAP DLP (`ICAP_DLP_ACTION`):
 * - Chấp nhận `BLOCK` (chặn luồng mạng HTTP 403) và `AUDIT_ONLY` (cho qua HTTP 204 nhưng ghi nhận cảnh báo SOC).
 * - Tương thích ngược với bí danh `MONITOR` -> ánh xạ sang `AUDIT_ONLY`; mọi giá trị lạ đều chặn Fail-Closed (`BLOCK`).
 */
export function resolveIcapDlpAction(rawAction: string | undefined): 'BLOCK' | 'AUDIT_ONLY' {
  const normalized = rawAction?.trim().toUpperCase();
  if (!normalized || normalized === 'BLOCK') {
    return 'BLOCK';
  }
  if (normalized === 'AUDIT_ONLY') {
    return 'AUDIT_ONLY';
  }
  if (normalized === 'MONITOR') {
    console.warn(
      '[ICAP DLP] ICAP_DLP_ACTION="MONITOR" is deprecated; mapping to "AUDIT_ONLY" mode.',
    );
    return 'AUDIT_ONLY';
  }
  console.warn(
    `[ICAP DLP] Unknown ICAP_DLP_ACTION="${rawAction}"; failing closed to "BLOCK" mode.`,
  );
  return 'BLOCK';
}

/**
 * Thuật toán: Khởi tạo máy chủ ICAP từ tham số/biến môi trường (`ICAP_BIND_HOST`, `ICAP_PORT`),
 * gắn đường ống lưu cảnh báo `NETWORK_DLP_VIOLATION` và nối kết tín hiệu `AbortSignal` để đóng sạch khi dừng.
 */
export function startIcapServerJob(options?: IcapServerConfig, signal?: AbortSignal): IcapServer {
  const enabled = options?.enabled ?? process.env['ICAP_SERVER_ENABLED'] !== 'false';
  // CONFLICT-RESOLVED: Dùng chung bộ phân giải `resolveIcapListenPort` và `resolveIcapBindHost` giữa `startIcapServerJob` và `IcapServer`.
  const port = resolveIcapListenPort(options?.port);
  const host = resolveIcapBindHost(options?.host);
  const maxConcurrentInspections =
    options?.maxConcurrentInspections ??
    Number(process.env['ICAP_MAX_CONCURRENT_INSPECTIONS'] ?? '16');
  const action = options?.action ?? resolveIcapDlpAction(process.env['ICAP_DLP_ACTION']);
  const customKeywords =
    options?.customKeywords ??
    (process.env['ICAP_DLP_CUSTOM_KEYWORDS']
      ? process.env['ICAP_DLP_CUSTOM_KEYWORDS']
          .split(',')
          .map((k) => k.trim())
          .filter(Boolean)
      : []);

  const server = new IcapServer({
    enabled,
    port,
    host,
    serviceName: options?.serviceName ?? 'sda-dlp',
    maxConnections: options?.maxConnections ?? 100,
    maxConcurrentInspections:
      Number.isFinite(maxConcurrentInspections) && maxConcurrentInspections > 0
        ? maxConcurrentInspections
        : 16,
    ...(options?.maxBodyBytes !== undefined ? { maxBodyBytes: options.maxBodyBytes } : {}),
    previewSize: options?.previewSize ?? 2048,
    action,
    customKeywords,
  });

  server.onViolation(async (scanResult, request) => {
    await persistNetworkDlpSecurityAlert(scanResult, request);
  });

  if (enabled) {
    void server.start().catch((err) => {
      console.error('[ICAP Server] Failed to start:', err);
    });
  }

  if (signal) {
    signal.addEventListener(
      'abort',
      () => {
        void server.stop();
      },
      { once: true },
    );
  }

  return server;
}

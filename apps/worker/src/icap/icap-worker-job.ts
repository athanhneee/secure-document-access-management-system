import { IcapServer, persistNetworkDlpSecurityAlert } from './icap-server.js';
import type { IcapServerConfig } from './icap.types.js';

/**
 * Thuật toán / Tổng quan module:
 * Trình khởi tạo và gắn kết dịch vụ nền máy chủ RFC 3507 ICAP Network DLP vào tiến trình Worker trung tâm,
 * chuẩn hóa cấu hình hành động chính sách theo nguyên lý Fail-Closed và chuyển đổi mọi sự kiện vi phạm DLP
 * (cả `BLOCK` lẫn `AUDIT_ONLY`) thành cảnh báo an ninh SOC (`security_alerts`) chịu lỗi cô lập.
 */

/**
 * Giải thuật chuẩn hóa chế độ xử lý vi phạm ICAP DLP (`ICAP_DLP_ACTION`):
 * - Chấp nhận `BLOCK` (chặn luồng mạng HTTP 403) và `AUDIT_ONLY` (cho qua HTTP 204 nhưng ghi nhận cảnh báo SOC).
 * - Tương thích ngược với bí danh `MONITOR` -> ánh xạ sang `AUDIT_ONLY` kèm cảnh báo cấu hình để tránh chặn ngầm ngoài ý muốn.
 * - Mọi giá trị không xác định sẽ ghi cảnh báo và áp dụng cơ chế Fail-Closed (`BLOCK`).
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
 * Thuật toán: Khởi tạo máy chủ ICAP từ tham số/biến môi trường, gắn đường ống lưu cảnh báo `NETWORK_DLP_VIOLATION`
 * cho cả hai chế độ `BLOCK` và `AUDIT_ONLY`, và nối kết tín hiệu `AbortSignal` để đóng máy chủ sạch khi tiến trình dừng.
 */
export function startIcapServerJob(options?: IcapServerConfig, signal?: AbortSignal): IcapServer {
  const enabled = options?.enabled ?? process.env['ICAP_SERVER_ENABLED'] !== 'false';
  const port = options?.port ?? Number(process.env['ICAP_SERVER_PORT'] ?? '1344');
  const host = options?.host ?? process.env['ICAP_SERVER_HOST'] ?? '127.0.0.1';
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

import fs from 'node:fs';
import path from 'node:path';
import { waitForShutdown } from './lifecycle.js';
import { startGrantExpiryJob } from './grant-expiry-job.js';
import { startDerivativeCleanupJob } from './derivative-cleanup-job.js';
import { startAuditVerificationJob } from './audit-verification-job.js';
import { startSecurityDetectionJob } from './security-detection-job.js';
import { startNotificationOutboxJob } from './notification-outbox-job.js';
import { startExportProcessorJob } from './export-processor-job.js';
import { startExportCleanupJob } from './export-cleanup-job.js';
import { startIcapServerJob } from './icap/icap-worker-job.js';
import { startWorkerHealthServer } from './worker-health-server.js';

/**
 * Thuật toán / Tổng quan module:
 * Điểm khởi chạy trung tâm (Bootstrap & Orchestrator) của tiến trình nền `@sda/worker`:
 * - Pha 1 (Khám phá biến môi trường phân cấp): Tìm nạp tệp cấu hình `.env` / `.local/dev.env` từ thư mục hiện hành lên gốc monorepo.
 * - Pha 2 (Đăng ký tín hiệu dừng mềm): Ánh xạ `SIGINT` và `SIGTERM` vào một `AbortController` dùng chung cho toàn bộ các tác vụ nền.
 * - Pha 3 (Hậu kiểm khóa mật mã Fail-Fast): Trong môi trường `production`, cưỡng chế từ chối khởi động nếu khóa toàn vẹn kiểm toán yếu/mặc định.
 * - Pha 4 (Kích hoạt đồng thời & Neo vòng đời): Khởi chạy máy chủ HTTP Health/Prometheus (`/health`, `/metrics`), `ExportProcessorJob`,
 *   và các dịch vụ nền độc lập cùng lắng nghe `shutdown.signal`.
 */

// Thuật toán: Tìm kiếm và nạp biến môi trường dự phòng theo chuỗi ứng viên phân cấp thư mục (Hierarchical Env Fallback Resolution)
if (!process.env['DATABASE_URL']) {
  const candidateGroups = [
    [
      path.resolve(process.cwd(), '.env'),
      path.resolve(process.cwd(), '../../.env'),
      path.resolve(import.meta.dirname, '../../../.env'),
    ],
    [
      path.resolve(process.cwd(), '.local/dev.env'),
      path.resolve(process.cwd(), '../../.local/dev.env'),
      path.resolve(import.meta.dirname, '../../../.local/dev.env'),
    ],
  ];
  for (const group of candidateGroups) {
    for (const candidate of group) {
      if (fs.existsSync(candidate)) {
        try {
          process.loadEnvFile(candidate);
          break;
        } catch {
          // Continue checking next candidate
        }
      }
    }
  }
}

const shutdown = new AbortController();
const requestShutdown = (): void => shutdown.abort();
process.once('SIGINT', requestShutdown);
process.once('SIGTERM', requestShutdown);

const GRANT_EXPIRY_INTERVAL_MS = Number(process.env['GRANT_EXPIRY_INTERVAL_MS'] ?? '60000');
const configuredAuditHmacKey =
  process.env['AUDIT_INTEGRITY_KEY'] ??
  process.env['DOCUMENT_AUDIT_HMAC_KEY'] ??
  process.env['AUDIT_HMAC_KEY'];

// Thuật toán: Kiểm tra điều kiện tiên quyết mật mã Fail-Fast trên môi trường Production chống chạy với khóa yếu/mặc định
if (process.env['NODE_ENV'] === 'production') {
  if (
    !configuredAuditHmacKey ||
    configuredAuditHmacKey.length < 32 ||
    configuredAuditHmacKey.includes('local-only-') ||
    configuredAuditHmacKey.toLowerCase().includes('change-me')
  ) {
    throw new Error(
      'AUDIT_INTEGRITY_KEY (>= 32 random chars, non-placeholder) is mandatory when running worker in production.',
    );
  }
}

const GRANT_AUDIT_HMAC_KEY =
  configuredAuditHmacKey ?? 'local-only-audit-integrity-hmac-key-0000000000000000';
const AUDIT_KEY_ROTATION_JSON = process.env['AUDIT_KEY_ROTATION_JSON'];

const DERIVATIVE_CLEANUP_INTERVAL_MS = Number(
  process.env['DERIVATIVE_CLEANUP_INTERVAL_MS'] ?? '300000',
);
const DERIVATIVE_TTL_MINUTES = Number(process.env['DERIVATIVE_TTL_MINUTES'] ?? '60');
const AUDIT_VERIFY_INTERVAL_MS = Number(process.env['AUDIT_VERIFY_INTERVAL_MS'] ?? '300000');
const SECURITY_DETECTION_INTERVAL_MS = Number(
  process.env['SECURITY_DETECTION_INTERVAL_MS'] ?? '60000',
);
const NOTIFICATION_OUTBOX_INTERVAL_MS = Number(
  process.env['NOTIFICATION_OUTBOX_INTERVAL_MS'] ?? '15000',
);
const EXPORT_PROCESSOR_INTERVAL_MS = Number(process.env['EXPORT_PROCESSOR_INTERVAL_MS'] ?? '5000');
const EXPORT_CLEANUP_INTERVAL_MS = Number(process.env['EXPORT_CLEANUP_INTERVAL_MS'] ?? '300000');

// Thuật toán: Khởi chạy điều phối song song máy chủ Health/Metrics và 8 tác vụ nền gắn kết chung tín hiệu hủy tập trung
startWorkerHealthServer(undefined, shutdown.signal);
startGrantExpiryJob(
  GRANT_EXPIRY_INTERVAL_MS,
  GRANT_AUDIT_HMAC_KEY,
  shutdown.signal,
  AUDIT_KEY_ROTATION_JSON,
);
startDerivativeCleanupJob(DERIVATIVE_CLEANUP_INTERVAL_MS, DERIVATIVE_TTL_MINUTES, shutdown.signal);
startAuditVerificationJob(
  AUDIT_VERIFY_INTERVAL_MS,
  GRANT_AUDIT_HMAC_KEY,
  shutdown.signal,
  AUDIT_KEY_ROTATION_JSON,
);
startSecurityDetectionJob(SECURITY_DETECTION_INTERVAL_MS, shutdown.signal);
startNotificationOutboxJob(NOTIFICATION_OUTBOX_INTERVAL_MS, shutdown.signal);
startExportProcessorJob(EXPORT_PROCESSOR_INTERVAL_MS, shutdown.signal);
startExportCleanupJob(EXPORT_CLEANUP_INTERVAL_MS, shutdown.signal);
startIcapServerJob(undefined, shutdown.signal);

console.info(
  'Worker initialized with health/metrics server, grant expiry, derivative/session cleanup, audit verification, security detection, notification outbox, export processor, export cleanup, and ICAP Network DLP server.',
);
try {
  await waitForShutdown(shutdown.signal);
  console.info('Worker stopped cleanly.');
} finally {
  process.removeListener('SIGINT', requestShutdown);
  process.removeListener('SIGTERM', requestShutdown);
}

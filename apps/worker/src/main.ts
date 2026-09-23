import { waitForShutdown } from './lifecycle.js';
import { startGrantExpiryJob } from './grant-expiry-job.js';
import { startDerivativeCleanupJob } from './derivative-cleanup-job.js';
import { startAuditVerificationJob } from './audit-verification-job.js';
import { startSecurityDetectionJob } from './security-detection-job.js';
import { startNotificationOutboxJob } from './notification-outbox-job.js';
import { startExportCleanupJob } from './export-cleanup-job.js';

const shutdown = new AbortController();
const requestShutdown = (): void => shutdown.abort();
process.once('SIGINT', requestShutdown);
process.once('SIGTERM', requestShutdown);

// Configuration with defaults
const GRANT_EXPIRY_INTERVAL_MS = Number(process.env['GRANT_EXPIRY_INTERVAL_MS'] ?? '60000');
const GRANT_AUDIT_HMAC_KEY =
  process.env['AUDIT_INTEGRITY_KEY'] ??
  process.env['DOCUMENT_AUDIT_HMAC_KEY'] ??
  'local-only-document-audit-hmac-key-0000000000000000';
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
const EXPORT_CLEANUP_INTERVAL_MS = Number(process.env['EXPORT_CLEANUP_INTERVAL_MS'] ?? '300000');

// Start worker jobs
startGrantExpiryJob(GRANT_EXPIRY_INTERVAL_MS, GRANT_AUDIT_HMAC_KEY, shutdown.signal);
startDerivativeCleanupJob(DERIVATIVE_CLEANUP_INTERVAL_MS, DERIVATIVE_TTL_MINUTES, shutdown.signal);
startAuditVerificationJob(AUDIT_VERIFY_INTERVAL_MS, GRANT_AUDIT_HMAC_KEY, shutdown.signal);
startSecurityDetectionJob(SECURITY_DETECTION_INTERVAL_MS, shutdown.signal);
startNotificationOutboxJob(NOTIFICATION_OUTBOX_INTERVAL_MS, shutdown.signal);
startExportCleanupJob(EXPORT_CLEANUP_INTERVAL_MS, shutdown.signal);

console.info(
  'Worker initialized with grant expiry, derivative cleanup, audit verification, security detection, notification outbox, and export cleanup consumers.',
);
try {
  await waitForShutdown(shutdown.signal);
  console.info('Worker stopped cleanly.');
} finally {
  process.removeListener('SIGINT', requestShutdown);
  process.removeListener('SIGTERM', requestShutdown);
}

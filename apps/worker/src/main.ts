import fs from 'node:fs';
import path from 'node:path';
import { waitForShutdown } from './lifecycle.js';
import { startGrantExpiryJob } from './grant-expiry-job.js';
import { startDerivativeCleanupJob } from './derivative-cleanup-job.js';
import { startAuditVerificationJob } from './audit-verification-job.js';
import { startSecurityDetectionJob } from './security-detection-job.js';
import { startNotificationOutboxJob } from './notification-outbox-job.js';
import { startExportCleanupJob } from './export-cleanup-job.js';
import { startIcapServerJob } from './icap/icap-worker-job.js';

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

// Configuration with defaults (fail-fast in production if audit HMAC secret is missing or placeholder)
const GRANT_EXPIRY_INTERVAL_MS = Number(process.env['GRANT_EXPIRY_INTERVAL_MS'] ?? '60000');
const configuredAuditHmacKey =
  process.env['AUDIT_INTEGRITY_KEY'] ??
  process.env['DOCUMENT_AUDIT_HMAC_KEY'] ??
  process.env['AUDIT_HMAC_KEY'];

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
startIcapServerJob(undefined, shutdown.signal);

console.info(
  'Worker initialized with grant expiry, derivative cleanup, audit verification, security detection, notification outbox, export cleanup, and ICAP Network DLP server.',
);
try {
  await waitForShutdown(shutdown.signal);
  console.info('Worker stopped cleanly.');
} finally {
  process.removeListener('SIGINT', requestShutdown);
  process.removeListener('SIGTERM', requestShutdown);
}

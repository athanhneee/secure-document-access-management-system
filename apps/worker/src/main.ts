import { waitForShutdown } from './lifecycle.js';
import { startGrantExpiryJob } from './grant-expiry-job.js';

const shutdown = new AbortController();
const requestShutdown = (): void => shutdown.abort();
process.once('SIGINT', requestShutdown);
process.once('SIGTERM', requestShutdown);

// Configuration with defaults
const GRANT_EXPIRY_INTERVAL_MS = Number(process.env['GRANT_EXPIRY_INTERVAL_MS'] ?? '60000');
const GRANT_AUDIT_HMAC_KEY =
  process.env['DOCUMENT_AUDIT_HMAC_KEY'] ?? 'local-only-document-audit-hmac-key-0000000000000000';

// Start the grant expiry worker
startGrantExpiryJob(GRANT_EXPIRY_INTERVAL_MS, GRANT_AUDIT_HMAC_KEY, shutdown.signal);

console.info('Worker initialized with grant expiry job consumer.');
try {
  await waitForShutdown(shutdown.signal);
  console.info('Worker stopped cleanly.');
} finally {
  process.removeListener('SIGINT', requestShutdown);
  process.removeListener('SIGTERM', requestShutdown);
}

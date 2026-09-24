import { IcapServer } from './icap-server.js';
import type { IcapServerConfig } from './icap.types.js';
import { getDatabaseClient } from '@sda/database';
import { randomUUID } from 'node:crypto';

export function startIcapServerJob(options?: IcapServerConfig, signal?: AbortSignal): IcapServer {
  const enabled = options?.enabled ?? process.env['ICAP_SERVER_ENABLED'] !== 'false';
  const port = options?.port ?? Number(process.env['ICAP_SERVER_PORT'] ?? '1344');
  const host = options?.host ?? process.env['ICAP_SERVER_HOST'] ?? '0.0.0.0';
  const action =
    options?.action ?? (process.env['ICAP_DLP_ACTION'] === 'AUDIT_ONLY' ? 'AUDIT_ONLY' : 'BLOCK');
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

  // Connect violation alerts to database if available
  server.onViolation(async (scanResult, request) => {
    try {
      const db = getDatabaseClient();
      const highestSeverity = scanResult.violations.some((v) => v.severity === 'CRITICAL')
        ? 'CRITICAL'
        : 'HIGH';

      const alertId = randomUUID();
      const violationSummary = scanResult.violations.map((v) => `[${v.type}] ${v.rule}`).join('; ');

      await db.securityAlert.create({
        data: {
          id: alertId,
          alert_type: 'NETWORK_DLP_VIOLATION',
          title: `[Network DLP] Phát hiện rò rỉ dữ liệu qua Gateway: ${scanResult.violations[0]?.type ?? 'UNKNOWN'}`,
          description: `Giao thức ICAP phát hiện vi phạm chính sách phòng chống thất thoát dữ liệu (${request.method} ${request.uri}): ${violationSummary}. Chi tiết vi phạm: ${scanResult.violations.map((v) => `${v.rule} (${v.matchedSnippet})`).join(', ')}`,
          severity: highestSeverity,
          status: 'OPEN',
        },
      });

      console.info(`[ICAP DLP] Created SecurityAlert [${alertId}] for network violation.`);
    } catch (err) {
      // Don't fail the ICAP stream if database logging has a glitch
      console.warn('[ICAP DLP] Could not record alert in database:', (err as Error).message);
    }
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

import { randomUUID } from 'node:crypto';
import { getDatabaseClient } from '@sda/database';
import type { DlpScanResult, IcapRequest } from './icap.types.js';

export interface IcapServerMetrics {
  totalConnections: number;
  totalRequests: number;
  optionsRequests: number;
  respmodRequests: number;
  reqmodRequests: number;
  cleanPassThrough: number;
  auditedViolations: number;
  blockedViolations: number;
  scannedBytes: number;
}

export interface ResolvedIcapConfig {
  enabled: boolean;
  port: number;
  host: string;
  serviceName: string;
  maxConnections: number;
  previewSize: number;
  action: 'BLOCK' | 'AUDIT_ONLY';
  customKeywords: string[];
}

/**
 * Algorithm / Thuật toán: Ghi nhận cảnh báo SOC `NETWORK_DLP_VIOLATION` cho cả hai chế độ `BLOCK` và `AUDIT_ONLY`.
 */
export async function persistNetworkDlpSecurityAlert(
  scanResult: DlpScanResult,
  request: IcapRequest,
): Promise<void> {
  if (!process.env['DATABASE_URL']) return;
  try {
    const db = getDatabaseClient();
    const highestSeverity = scanResult.violations.some((v) => v.severity === 'CRITICAL')
      ? 'CRITICAL'
      : scanResult.violations.some((v) => v.severity === 'HIGH')
        ? 'HIGH'
        : 'MEDIUM';

    const alertId = randomUUID();
    const safeUri = request.uri.replace(/\p{Cc}/gu, '').slice(0, 200);
    const modeTag = scanResult.action === 'AUDIT' ? 'AUDIT_ONLY' : 'BLOCKED';
    const violationSummary = scanResult.violations.map((v) => `[${v.type}] ${v.rule}`).join('; ');

    await db.securityAlert.create({
      data: {
        id: alertId,
        alert_type: 'NETWORK_DLP_VIOLATION',
        title: `[Network DLP][${modeTag}] Phát hiện rò rỉ dữ liệu qua Gateway: ${scanResult.violations[0]?.type ?? 'UNKNOWN'}`,
        description: `Giao thức ICAP (${modeTag}) phát hiện vi phạm chính sách DLP (${request.method} ${safeUri}): ${violationSummary}. Chi tiết: ${scanResult.violations.map((v) => `${v.rule} (${v.matchedSnippet})`).join(', ')}`,
        severity: highestSeverity,
        status: 'OPEN',
      },
    });
  } catch (err) {
    console.warn('[ICAP DLP] Could not record SecurityAlert in database:', (err as Error).message);
  }
}

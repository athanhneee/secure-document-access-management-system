/**
 * @module DlpStatusService
 * Thuật toán: Thăm Dò Sức Khỏe & Chế Độ Thực Thi Thực Tế Của Cổng ICAP Network DLP (`DlpStatusService`)
 * Mục đích:
 *   - Thay thế kiểm tra giả mạo qua `/health/ready` bằng truy vấn nội bộ tới tiến trình Worker (`WORKER_HEALTH_URL` / `http://127.0.0.1:9102/health`) có giới hạn thời gian cứng `1500ms`.
 *   - Áp dụng nguyên tắc fail-closed: nếu Worker không phản hồi, đang `degraded` hoặc ICAP chưa mở cổng lắng nghe, trả tường minh `OFFLINE` / `DEGRADED` và chế độ thực thi thật (`BLOCK` | `AUDIT_ONLY` | `DISABLED` | `OFFLINE`) mà không rò rỉ cổng/URL nội bộ ra trình duyệt (#06).
 */
import { Injectable, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import type { AuthPrincipal } from '../auth/auth.types.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import {
  applyAlertScopeToWhere,
  resolveAlertDepartmentScope,
} from './security-operations-scope.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export type DlpGatewayHealth = 'ONLINE' | 'DEGRADED' | 'OFFLINE';
export type DlpEnforcementMode = 'BLOCK' | 'AUDIT_ONLY' | 'DISABLED' | 'OFFLINE';

export interface NetworkDlpStatusResponse {
  gatewayHealth: DlpGatewayHealth;
  workerReachable: boolean;
  icapEnabled: boolean;
  icapListening: boolean;
  enforcementMode: DlpEnforcementMode;
  totalDlpAlerts: number;
  openDlpAlerts: number;
  checkedAt: string;
}

interface WorkerHealthPayload {
  status?: string;
  workerLoopAlive?: boolean;
  dbHealthy?: boolean;
  icap?: {
    enabled?: boolean;
    listening?: boolean;
    action?: 'BLOCK' | 'AUDIT_ONLY';
  };
}

/**
 * Thuật toán: Phân giải URL kiểm tra sức khỏe nội bộ của Worker từ biến môi trường với fallback an toàn về loopback `9102`.
 */
export function resolveInternalWorkerHealthUrl(env: NodeJS.ProcessEnv = process.env): string {
  const explicit = env['WORKER_HEALTH_URL']?.trim();
  if (explicit) return explicit;
  const rawPort = env['WORKER_HEALTH_PORT']?.trim();
  const parsedPort = Number.parseInt(rawPort ?? '9102', 10);
  const port =
    Number.isInteger(parsedPort) && parsedPort > 0 && parsedPort <= 65_535 ? parsedPort : 9102;
  return `http://127.0.0.1:${port}/health`;
}

@Injectable()
export class DlpStatusService {
  private readonly database: PrismaClient;

  constructor(
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly authorization?: AuthorizationService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Thuật toán: Thăm dò đồng thời sức khỏe ICAP Worker (timeout `1500ms`) và số lượng cảnh báo DLP thực tế trong CSDL theo phạm vi phòng ban.
   */
  async getNetworkDlpStatus(
    actor?: AuthPrincipal,
    fetcher: typeof fetch = fetch,
  ): Promise<NetworkDlpStatusResponse> {
    const [workerProbe, alertCounts] = await Promise.all([
      this.probeWorkerIcap(fetcher),
      this.countDlpAlerts(actor),
    ]);

    return {
      ...workerProbe,
      ...alertCounts,
      checkedAt: new Date().toISOString(),
    };
  }

  private async probeWorkerIcap(fetcher: typeof fetch): Promise<{
    gatewayHealth: DlpGatewayHealth;
    workerReachable: boolean;
    icapEnabled: boolean;
    icapListening: boolean;
    enforcementMode: DlpEnforcementMode;
  }> {
    const url = resolveInternalWorkerHealthUrl();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1_500);
    timeout.unref?.();

    try {
      const response = await fetcher(url, {
        method: 'GET',
        signal: controller.signal,
        headers: { Accept: 'application/json' },
      });
      if (!response.ok && response.status !== 503) {
        return {
          gatewayHealth: 'OFFLINE',
          workerReachable: false,
          icapEnabled: false,
          icapListening: false,
          enforcementMode: 'OFFLINE',
        };
      }
      const payload = (await response.json()) as WorkerHealthPayload;
      const icap = payload.icap;
      const workerHealthy = payload.status === 'ok' && payload.workerLoopAlive !== false;
      const icapEnabled = Boolean(icap?.enabled);
      const icapListening = Boolean(icap?.listening);

      if (!icapEnabled) {
        return {
          gatewayHealth: 'OFFLINE',
          workerReachable: true,
          icapEnabled: false,
          icapListening: false,
          enforcementMode: 'DISABLED',
        };
      }

      const enforcementMode: DlpEnforcementMode =
        icap?.action === 'AUDIT_ONLY' ? 'AUDIT_ONLY' : 'BLOCK';

      if (!icapListening) {
        return {
          gatewayHealth: 'DEGRADED',
          workerReachable: true,
          icapEnabled: true,
          icapListening: false,
          enforcementMode: 'OFFLINE',
        };
      }

      return {
        gatewayHealth: workerHealthy ? 'ONLINE' : 'DEGRADED',
        workerReachable: true,
        icapEnabled: true,
        icapListening: true,
        enforcementMode,
      };
    } catch {
      return {
        gatewayHealth: 'OFFLINE',
        workerReachable: false,
        icapEnabled: false,
        icapListening: false,
        enforcementMode: 'OFFLINE',
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  private async countDlpAlerts(
    actor?: AuthPrincipal,
  ): Promise<{ totalDlpAlerts: number; openDlpAlerts: number }> {
    if (!this.database || typeof this.database.securityAlert?.count !== 'function') {
      return { totalDlpAlerts: 0, openDlpAlerts: 0 };
    }
    try {
      const allowedDepts = await resolveAlertDepartmentScope(this.authorization, actor, 'VIEW');
      const baseWhere = applyAlertScopeToWhere(
        { alert_type: 'NETWORK_DLP_VIOLATION' },
        allowedDepts,
      );
      const openWhere = applyAlertScopeToWhere(
        { alert_type: 'NETWORK_DLP_VIOLATION', status: { in: ['OPEN', 'INVESTIGATING'] } },
        allowedDepts,
      );
      const [totalDlpAlerts, openDlpAlerts] = await Promise.all([
        this.database.securityAlert.count({ where: baseWhere }),
        this.database.securityAlert.count({ where: openWhere }),
      ]);
      return { totalDlpAlerts, openDlpAlerts };
    } catch {
      return { totalDlpAlerts: 0, openDlpAlerts: 0 };
    }
  }
}

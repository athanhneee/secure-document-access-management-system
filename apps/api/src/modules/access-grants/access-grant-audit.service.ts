/**
 * @module AccessGrantAuditService
 * Thuật toán: Ghi nối tiếp chuỗi băm mật mã HMAC vào phân vùng `ACCESS_GRANT` hỗ trợ liên kết giao dịch nguyên tử
 * và tự động thử lại có trễ lũy tiến kèm nhiễu ngẫu nhiên khi gặp xung đột tuần tự hóa (`40001` / `P2034`).
 */
import { Injectable, Logger } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import {
  appendChainedAuditLog,
  executeAuditWithRetry,
  resolveActiveAuditKey,
} from '../audit/audit-chain-helper.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';

export type GrantAuditAction =
  | 'GRANT_CREATED'
  | 'GRANT_EXTENDED'
  | 'GRANT_REVOKED'
  | 'GRANT_EXPIRED'
  | 'GRANT_SESSIONS_TERMINATED'
  | 'ACCESS_REQUEST_CREATED'
  | 'ACCESS_REQUEST_APPROVED'
  | 'ACCESS_REQUEST_REJECTED'
  | 'ACCESS_REQUEST_CANCELLED';

export interface GrantAuditEvent {
  action: GrantAuditAction;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  objectId?: string | null;
  documentId?: string | null;
  reasonCode?: string | null;
  details?: Record<string, string | number | boolean | null>;
}

@Injectable()
export class AccessGrantAuditService {
  private readonly logger = new Logger(AccessGrantAuditService.name);
  private readonly hmacKey: string;
  private readonly keyVersion: number;
  private readonly database = getDatabaseClient();

  constructor(config: AppConfigService) {
    // CONFLICT-RESOLVED: Sử dụng khóa xoay vòng đang kích hoạt kèm hmac_key_version đồng bộ với AuditWriterService.
    const active = resolveActiveAuditKey(config);
    this.hmacKey = active.hmacKey;
    this.keyVersion = active.keyVersion;
  }

  /**
   * Thuật toán: Ghi Nhật Ký Kiểm Toán Chuỗi Băm HMAC Đồng Giao Dịch Kèm Thử Lại Tuần Tự Hóa (`executeAuditWithRetry`).
   */
  async record(
    event: GrantAuditEvent,
    principal: AuthPrincipal,
    context: RequestContext,
    transactionClient?: Parameters<Parameters<typeof this.database.$transaction>[0]>[0],
  ): Promise<void> {
    const execute = async (
      tx: Parameters<Parameters<typeof this.database.$transaction>[0]>[0],
    ): Promise<void> => {
      await appendChainedAuditLog(tx, {
        partition: 'ACCESS_GRANT',
        hmacKey: this.hmacKey,
        keyVersion: this.keyVersion,
        action: event.action,
        outcome: event.outcome,
        objectType: 'ACCESS_GRANT',
        objectId: event.objectId ?? null,
        documentId: event.documentId ?? null,
        actorUserId: principal.userId,
        actorUsername: principal.username,
        reasonCode: event.reasonCode ?? null,
        details: event.details ?? {},
        context,
      });
    };

    try {
      if (transactionClient) {
        await executeAuditWithRetry(() => execute(transactionClient));
      } else {
        await executeAuditWithRetry(() =>
          this.database.$transaction(async (tx) => {
            await execute(tx);
          }),
        );
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Failed to record grant audit log: ${msg}`);
      const nodeEnv = process.env['NODE_ENV'];
      if (nodeEnv === 'production' || nodeEnv === 'staging') {
        throw new Error(`Audit logging failed: ${msg}`);
      }
    }
  }
}

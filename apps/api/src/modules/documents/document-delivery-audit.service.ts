/**
 * Module: Dịch vụ Nhật ký Kiểm toán Phân phối & Phiên Truy cập Tài liệu (Delivery & Session Audit Service)
 * Thuật toán: Ghi Nối Tiếp Chuỗi Băm HMAC Phân Vùng `ACCESS_SESSION` Kèm Thử Lại Giao Dịch Tuần Tự (`40001` / `P2034` Backoff).
 *   1. Khi có `transactionClient` ngoại vi, ghi trực tiếp trong phạm vi giao dịch của người gọi để bảo toàn tính nguyên tử.
 *   2. Khi tự mở giao dịch độc lập, bọc trong `runSerializableAuditTransaction` để tự động thử lại khi xảy ra tranh chấp khóa hoặc lỗi tuần tự hóa.
 */
import { Injectable, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import { appendChainedAuditLog, resolveActiveAuditKey } from '../audit/audit-chain-helper.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { runSerializableAuditTransaction } from './document-audit.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export type DeliveryAuditAction =
  | 'ACCESS_PERMITTED'
  | 'ACCESS_DENIED'
  | 'WATERMARK_GENERATED'
  | 'DOCUMENT_PREVIEWED'
  | 'DOCUMENT_DOWNLOADED'
  | 'SESSION_TERMINATED'
  | 'WATERMARK_TRACED';

export interface DeliveryAuditEvent {
  action: DeliveryAuditAction;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  objectId?: string | null;
  documentId?: string | null;
  sessionId?: string | null;
  reasonCode?: string | null;
  details?: Record<string, string | number | boolean | null>;
}

@Injectable()
export class DocumentDeliveryAuditService {
  private readonly hmacKey: string;
  private readonly keyVersion: number;
  private readonly database: PrismaClient;

  constructor(config: AppConfigService, @Optional() databaseClient?: PrismaClient) {
    const active = resolveActiveAuditKey(config);
    this.hmacKey = active.hmacKey;
    this.keyVersion = active.keyVersion;
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Thuật toán: Ghi nối tiếp sự kiện kiểm toán vào phân vùng `ACCESS_SESSION` có thử lại `40001`/`P2034` khi chạy giao dịch độc lập.
   */
  async record(
    event: DeliveryAuditEvent,
    principal: AuthPrincipal,
    context: RequestContext,
    transactionClient?: Parameters<Parameters<PrismaClient['$transaction']>[0]>[0],
  ): Promise<void> {
    const execute = async (
      tx: Parameters<Parameters<PrismaClient['$transaction']>[0]>[0],
    ): Promise<void> => {
      await appendChainedAuditLog(tx, {
        partition: 'ACCESS_SESSION',
        hmacKey: this.hmacKey,
        keyVersion: this.keyVersion,
        action: event.action,
        outcome: event.outcome,
        objectType: 'ACCESS_SESSION',
        objectId: event.objectId ?? null,
        documentId: event.documentId ?? null,
        accessSessionId: event.sessionId ?? null,
        actorUserId: principal.userId,
        actorUsername: principal.username,
        reasonCode: event.reasonCode ?? null,
        details: event.details ?? {},
        context,
      });
    };

    if (transactionClient) {
      await execute(transactionClient);
    } else {
      await runSerializableAuditTransaction(this.database, execute);
    }
  }
}

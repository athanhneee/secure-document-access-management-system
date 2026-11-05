/**
 * Module: Dịch vụ Nhật ký Kiểm toán Phân phối & Phiên Truy cập Tài liệu (Delivery & Session Audit Service)
 * Thuật toán: Ghi nối tiếp chuỗi băm HMAC phân vùng `ACCESS_SESSION` cho các sự kiện PEP, thủy vân và xem/tải tệp.
 */
import { Injectable } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import { appendChainedAuditLog, resolveActiveAuditKey } from '../audit/audit-chain-helper.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';

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
  private readonly database = getDatabaseClient();

  constructor(config: AppConfigService) {
    // CONFLICT-RESOLVED: Sử dụng khóa xoay vòng đang kích hoạt kèm hmac_key_version đồng bộ với AuditWriterService.
    const active = resolveActiveAuditKey(config);
    this.hmacKey = active.hmacKey;
    this.keyVersion = active.keyVersion;
  }

  /**
   * Record an access delivery audit event in the ACCESS_SESSION partition with HMAC chain integrity.
   *
   * Thuật toán: Ghi Kiểm Toán Chuỗi Băm HMAC Cho Phiên Phân Phối Tài Liệu (Session-Partition Chained Audit)
   * Mục đích: Liên kết bất biến từng hành vi xem trước, sinh thủy vân, tải xuống hoặc từ chối truy cập với `sessionId` và `documentId`.
   * Cơ chế hoạt động:
   *   - Tái sử dụng `transactionClient` ngoại vi nếu có hoặc mở giao dịch mới để gọi `appendChainedAuditLog` vào phân vùng `ACCESS_SESSION`.
   */
  async record(
    event: DeliveryAuditEvent,
    principal: AuthPrincipal,
    context: RequestContext,
    transactionClient?: Parameters<Parameters<typeof this.database.$transaction>[0]>[0],
  ): Promise<void> {
    const execute = async (
      tx: Parameters<Parameters<typeof this.database.$transaction>[0]>[0],
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
      await this.database.$transaction(execute);
    }
  }
}

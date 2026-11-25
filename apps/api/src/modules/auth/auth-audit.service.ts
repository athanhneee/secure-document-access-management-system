/**
 * @module AuthAuditService
 * Thuật toán: Ghi nhật ký kiểm toán xác thực chuỗi băm HMAC-SHA256 vào phân vùng `AUTH`
 * kèm cơ chế thử lại giao dịch có trễ lũy tiến + nhiễu ngẫu nhiên khi gặp xung đột tuần tự hóa (`40001` / `P2034`).
 */
import { Injectable } from '@nestjs/common';
import { getDatabaseClient, type Prisma } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import {
  appendChainedAuditLog,
  executeAuditWithRetry,
  resolveActiveAuditKey,
} from '../audit/audit-chain-helper.js';
import type { RequestContext } from './auth.types.js';

interface AuditEvent {
  action: string;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  actorUserId?: bigint | undefined;
  actorUsername?: string | undefined;
  objectId?: string | undefined;
  sessionId?: string | undefined;
  reasonCode?: string | undefined;
  details?: Record<string, string | number | boolean | null> | undefined;
}

@Injectable()
export class AuthAuditService {
  private readonly hmacKey: string;
  private readonly keyVersion: number;
  private readonly database = getDatabaseClient();

  constructor(config: AppConfigService) {
    // CONFLICT-RESOLVED: Trích xuất đồng thời khóa HMAC đang kích hoạt và hmac_key_version từ vòng khóa xoay vòng thay vì mặc định gắn cứng phiên bản 1.
    const active = resolveActiveAuditKey(config);
    this.hmacKey = active.hmacKey;
    this.keyVersion = active.keyVersion;
  }

  /**
   * Thuật toán: Ghi bản ghi kiểm toán `AUTH` nguyên tử (hỗ trợ tái dùng `externalTx` để gộp chung giao dịch đăng nhập/MFA,
   * hoặc mở giao dịch độc lập kèm thử lại khi đụng độ khóa tuần tự hóa tạm thời).
   */
  async record(
    event: AuditEvent,
    context: RequestContext,
    externalTx?: Prisma.TransactionClient,
  ): Promise<void> {
    const appendInTx = async (transaction: Prisma.TransactionClient): Promise<void> => {
      await appendChainedAuditLog(transaction, {
        partition: 'AUTH',
        hmacKey: this.hmacKey,
        keyVersion: this.keyVersion,
        action: event.action,
        outcome: event.outcome,
        objectType: 'AUTHENTICATION',
        objectId: event.objectId ?? null,
        actorUserId: event.actorUserId ?? null,
        actorUsername: event.actorUsername ?? null,
        accessSessionId: event.sessionId ?? null,
        reasonCode: event.reasonCode ?? null,
        details: event.details ?? {},
        context,
      });
    };

    if (externalTx) {
      await appendInTx(externalTx);
      return;
    }

    await executeAuditWithRetry(() => this.database.$transaction(appendInTx));
  }
}

/**
 * @module AbacAuditService
 * Thuật toán: Ghi nhật ký kiểm toán quản trị và mô phỏng chính sách ABAC vào phân vùng chuỗi băm `ABAC`
 * kèm cơ chế thử lại lũy tiến có nhiễu ngẫu nhiên khi gặp xung đột tuần tự hóa (`40001` / `P2034`).
 */
import { Injectable } from '@nestjs/common';
import type { Prisma } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import {
  appendChainedAuditLog,
  executeAuditWithRetry,
  resolveActiveAuditKey,
} from '../audit/audit-chain-helper.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';

export interface AbacAuditEvent {
  action:
    | 'POLICY_SIMULATED'
    | 'POLICY_ACTIVATED'
    | 'POLICY_DEACTIVATED'
    | 'POLICY_CREATED'
    | 'POLICY_UPDATED'
    | 'POLICY_DELETED';
  objectType: 'POLICY_SIMULATION' | 'POLICY';
  objectId: string;
  documentId?: string | undefined;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  details: Record<string, string | number | boolean | null>;
}

@Injectable()
export class AbacAuditService {
  private readonly hmacKey: string;
  private readonly keyVersion: number;

  constructor(config: AppConfigService) {
    // CONFLICT-RESOLVED: Sử dụng khóa xoay vòng đang kích hoạt kèm hmac_key_version đồng bộ với AuditWriterService.
    const active = resolveActiveAuditKey(config);
    this.hmacKey = active.hmacKey;
    this.keyVersion = active.keyVersion;
  }

  /**
   * Thuật toán: Nối tiếp bản ghi kiểm toán `ABAC`.
   *   - Khi nhận `TransactionClient` đang mở (không có `$transaction`), gọi thẳng `append(transaction)` để lỗi xung đột `40001` nổi nguyên vẹn cho `withSerializableTransaction` rollback và thử lại (`BUG-049`).
   *   - Khi nhận `PrismaClient` gốc có `$transaction`, bọc `executeAuditWithRetry` mở giao dịch mới mỗi lần thử.
   */
  async record(
    transaction: Prisma.TransactionClient,
    event: AbacAuditEvent,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<void> {
    const maybeClient = transaction as Prisma.TransactionClient & {
      $transaction?: <T>(fn: (tx: Prisma.TransactionClient) => Promise<T>) => Promise<T>;
    };
    const append = (tx: Prisma.TransactionClient) =>
      appendChainedAuditLog(tx, {
        partition: 'ABAC',
        hmacKey: this.hmacKey,
        keyVersion: this.keyVersion,
        action: event.action,
        outcome: event.outcome,
        objectType: event.objectType,
        objectId: event.objectId,
        actorUserId: principal.userId,
        actorUsername: principal.username,
        documentId: event.documentId ?? null,
        details: event.details,
        context,
      });

    if (typeof maybeClient.$transaction === 'function') {
      await executeAuditWithRetry(() => maybeClient.$transaction((tx) => append(tx)));
      return;
    }
    await append(transaction);
  }
}

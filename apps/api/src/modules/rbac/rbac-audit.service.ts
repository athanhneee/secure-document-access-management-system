/**
 * @module RbacAuditService
 * Thuật toán: Ghi nhật ký kiểm toán biến đổi RBAC/Người dùng/Phòng ban vào chuỗi băm phân vùng `RBAC`
 * kèm cơ chế thử lại lũy tiến có nhiễu ngẫu nhiên khi gặp xung đột tuần tự hóa tạm thời (`40001` / `P2034`).
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

export interface RbacAuditEvent {
  action: string;
  objectType: 'USER' | 'DEPARTMENT' | 'ROLE' | 'ROLE_PERMISSION' | 'USER_ROLE';
  objectId: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
}

@Injectable()
export class RbacAuditService {
  private readonly hmacKey: string;
  private readonly keyVersion: number;

  constructor(config: AppConfigService) {
    // CONFLICT-RESOLVED: Sử dụng khóa xoay vòng đang kích hoạt kèm hmac_key_version đồng bộ với AuditWriterService.
    const active = resolveActiveAuditKey(config);
    this.hmacKey = active.hmacKey;
    this.keyVersion = active.keyVersion;
  }

  /**
   * Thuật toán: Nối tiếp mắt xích kiểm toán `RBAC`.
   *   - Khi nhận `TransactionClient` đang mở (không có `$transaction`), gọi thẳng `append(transaction)` không bọc retry để lỗi `40001` nổi nguyên vẹn ra `withSerializableTransaction` bên ngoài thay vì biến thành `25P02` (`BUG-049`).
   *   - Khi nhận `PrismaClient` gốc có `$transaction`, bọc `executeAuditWithRetry` mở giao dịch mới mỗi lần thử lại.
   */
  async record(
    transaction: Prisma.TransactionClient,
    event: RbacAuditEvent,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<void> {
    const maybeClient = transaction as Prisma.TransactionClient & {
      $transaction?: <T>(fn: (tx: Prisma.TransactionClient) => Promise<T>) => Promise<T>;
    };
    const append = (tx: Prisma.TransactionClient) =>
      appendChainedAuditLog(tx, {
        partition: 'RBAC',
        hmacKey: this.hmacKey,
        keyVersion: this.keyVersion,
        action: event.action,
        outcome: 'SUCCESS',
        objectType: event.objectType,
        objectId: event.objectId,
        actorUserId: principal.userId,
        actorUsername: principal.username,
        details: { before: event.before, after: event.after },
        context,
      });

    if (typeof maybeClient.$transaction === 'function') {
      await executeAuditWithRetry(() => maybeClient.$transaction((tx) => append(tx)));
      return;
    }
    await append(transaction);
  }
}

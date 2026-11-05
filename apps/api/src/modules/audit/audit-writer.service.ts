/**
 * @module AuditWriterService
 * Algorithm: Partition-Locked RFC 8785 HMAC-SHA256 Audit Chain Writer (delegating core append to `appendChainedAuditLog`).
 */
import { randomUUID } from 'node:crypto';
import { Injectable, Logger, Optional } from '@nestjs/common';
import { DatabaseConflictError, getDatabaseClient, type Prisma } from '@sda/database';
import { AppErrorCode, type AuditKeyRing } from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
import type { RequestContext } from '../auth/auth.types.js';
import { AuditRedactionService } from './audit-redaction.service.js';
import { appendChainedAuditLog, resolveAuditKeyRing } from './audit-chain-helper.js';

export interface AuditWriteEvent {
  action: string;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  objectType: string;
  objectId?: string | null;
  actorUserId?: bigint | null;
  actorUsername?: string | null;
  documentId?: string | null;
  accessSessionId?: string | null;
  reasonCode?: string | null;
  details?: Record<string, unknown> | null;
  chainPartition?: string;
  occurredAt?: Date;
}

export class AuditWriteException extends Error {
  readonly code = AppErrorCode.AUDIT_WRITE_FAILED;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'AuditWriteException';
    if (cause) {
      this.cause = cause;
    }
  }
}

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class AuditWriterService {
  private readonly logger = new Logger(AuditWriterService.name);
  private readonly keyRing: AuditKeyRing;
  private readonly database: PrismaClient;

  constructor(
    private readonly config: AppConfigService,
    private readonly redactionService: AuditRedactionService,
    @Optional() databaseClient?: PrismaClient,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
    // CONFLICT-RESOLVED: Dùng chung bộ phân giải vòng khóa xoay vòng resolveAuditKeyRing với audit-chain-helper.ts và Worker để đảm bảo đồng bộ phiên bản khóa HMAC trên toàn hệ thống.
    this.keyRing = resolveAuditKeyRing(this.config, (err) => {
      this.logger.warn(`Failed to parse AUDIT_KEY_ROTATION_JSON: ${String(err)}`);
    });
  }

  getHmacKey(version = 1): string {
    return this.keyRing.getKey(version);
  }

  getActiveKeyVersion(): number {
    return this.keyRing.activeVersion;
  }

  async writeLog(
    event: AuditWriteEvent,
    context?: Partial<RequestContext>,
    externalTx?: Prisma.TransactionClient,
  ): Promise<{
    id: bigint;
    entry_hash: string;
    chain_partition: string;
    chain_sequence: bigint;
  }> {
    const ctx: RequestContext = {
      ip: context?.ip ?? '127.0.0.1',
      userAgent: context?.userAgent,
      correlationId: context?.correlationId ?? randomUUID(),
    };
    return this.record(event, ctx, externalTx);
  }

  /**
   * Thuật toán: Ghi chuỗi băm kiểm toán hỗ trợ đa phiên bản khóa xoay vòng (`pg_advisory_xact_lock` + Versioned HMAC-SHA256).
   * Ủy quyền thực thi lõi cho `appendChainedAuditLog` để loại bỏ nhân bản logic khóa phân vùng, che dấu dữ liệu và ký JCS.
   */
  async record(
    event: AuditWriteEvent,
    context: RequestContext,
    externalTx?: Prisma.TransactionClient,
  ): Promise<{
    id: bigint;
    entry_hash: string;
    chain_partition: string;
    chain_sequence: bigint;
  }> {
    const partition = event.chainPartition || 'GLOBAL';
    const keyVersion = this.getActiveKeyVersion();
    const activeKey = this.getHmacKey(keyVersion);

    const executeOperation = (tx: Prisma.TransactionClient) =>
      appendChainedAuditLog(tx, {
        partition,
        hmacKey: activeKey,
        keyVersion,
        action: event.action,
        outcome: event.outcome,
        objectType: event.objectType,
        objectId: event.objectId,
        actorUserId: event.actorUserId,
        actorUsername: event.actorUsername,
        documentId: event.documentId,
        accessSessionId: event.accessSessionId,
        reasonCode: event.reasonCode,
        details: event.details,
        occurredAt: event.occurredAt,
        context,
        redactor: this.redactionService,
      });

    try {
      if (externalTx) {
        return await executeOperation(externalTx);
      }
      return await this.executeStandaloneWithRetry(executeOperation);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(
        `Critical: Audit logging failed: ${msg}`,
        err instanceof Error ? err.stack : undefined,
      );
      throw new AuditWriteException(`Failed to reliably record audit event: ${msg}`, err);
    }
  }

  /**
   * Thuật toán: Thử lại có giới hạn với trễ lũy tiến cho giao dịch kiểm toán độc lập (Bounded Exponential Backoff Retry).
   * Tự động thử lại tối đa 3 lần khi gặp lỗi xung đột tuần tự hóa tạm thời (`40001`, `40P01`, `P2034`, `DatabaseConflictError`)
   * mà vẫn giữ nguyên lời gọi 1 đối số `this.database.$transaction(executeOperation)` tương thích với mock kiểm thử.
   */
  private async executeStandaloneWithRetry<T>(
    executeOperation: (tx: Prisma.TransactionClient) => Promise<T>,
  ): Promise<T> {
    const maxAttempts = 3;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        return await this.database.$transaction(executeOperation);
      } catch (err: unknown) {
        if (attempt >= maxAttempts || !isTransientAuditTxConflict(err)) {
          throw err;
        }
        await new Promise((resolve) => setTimeout(resolve, 15 * attempt));
      }
    }
    throw new Error('Unreachable audit retry exhaustion');
  }
}

/**
 * Thuật toán: Nhận diện xung đột giao dịch tạm thời PostgreSQL/Prisma (`40001`, `40P01`, `P2034`).
 */
function isTransientAuditTxConflict(error: unknown): boolean {
  if (error instanceof DatabaseConflictError) {
    return true;
  }
  const code =
    typeof error === 'object' && error !== null && 'code' in error
      ? String((error as { code?: unknown }).code)
      : '';
  return code === 'P2034' || code === '40001' || code === '40P01';
}

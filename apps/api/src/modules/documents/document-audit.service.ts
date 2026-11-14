/**
 * Module: Dịch vụ Nhật ký Kiểm toán Vòng đời Tài liệu (Document Lifecycle Hash-Chained Audit Service)
 * Thuật toán: Ghi Nối Tiếp Chuỗi Băm HMAC Phân Vùng `DOCUMENT` Kèm Thử Lại Giao Dịch Tuần Tự (`40001` / `P2034` Backoff).
 *   1. Mở giao dịch cô lập `Serializable` để nối bản ghi vào chuỗi băm HMAC phân vùng `DOCUMENT`.
 *   2. Khi xảy ra xung đột tuần tự hóa hoặc khóa tranh chấp (`40001`, `P2034`, deadlock), tự động thử lại tối đa 4 lần
 *      với độ trễ lũy thừa có nhiễu ngẫu nhiên (`exponential backoff + jitter`).
 *   3. Cưỡng chế Fail-Closed trong môi trường `production` nếu mọi lần thử đều thất bại.
 */
import { Injectable, Logger, Optional } from '@nestjs/common';
import { getDatabaseClient, type Prisma } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import { appendChainedAuditLog, resolveActiveAuditKey } from '../audit/audit-chain-helper.js';
import type { RequestContext } from '../auth/auth.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface DocumentAuditEvent {
  action:
    | 'DOCUMENT_UPLOAD_STARTED'
    | 'DOCUMENT_SCAN_RESULT'
    | 'DOCUMENT_UPLOAD_COMPLETED'
    | 'DOCUMENT_UPLOAD_FAILED'
    | 'DOCUMENT_CREATED'
    | 'DOCUMENT_METADATA_UPDATED'
    | 'DOCUMENT_CLASSIFIED'
    | 'DOCUMENT_RECLASSIFIED'
    | 'DOCUMENT_ACTIVATED'
    | 'DOCUMENT_ARCHIVED'
    | 'DOCUMENT_OWNER_TRANSFERRED'
    | 'DOCUMENT_CURRENT_VERSION_SET'
    | 'DOCUMENT_RETENTION_WARNING'
    | 'DOCUMENT_SEARCHED'
    | 'WATERMARK_CONFIG_UPDATED';
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  actorUserId?: bigint | null;
  actorUsername?: string | null;
  documentId?: string | null;
  versionNo?: number | null;
  reasonCode?: string | null;
  details?: Record<string, string | number | boolean | null>;
}

/**
 * Thuật toán: Nhận diện lỗi xung đột giao dịch tuần tự PostgreSQL (`40001`) hoặc Prisma (`P2034`) cần thử lại.
 */
export function isTransientSerializationError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const code = (err as { code?: unknown; meta?: { code?: unknown } }).code;
  const metaCode = (err as { meta?: { code?: unknown } }).meta?.code;
  if (code === 'P2034' || code === '40001' || metaCode === '40001') {
    return true;
  }
  const msg = err instanceof Error ? err.message : String(err);
  return /40001|P2034|could not serialize access|serialization failure|deadlock detected/iu.test(
    msg,
  );
}

/**
 * Thuật toán: Thực thi giao dịch `Serializable` kèm cơ chế lùi lũy thừa có nhiễu (`Exponential Backoff + Jitter`, tối đa 4 lần thử).
 */
export async function runSerializableAuditTransaction(
  database: PrismaClient,
  work: (tx: Parameters<Parameters<PrismaClient['$transaction']>[0]>[0]) => Promise<void>,
  maxAttempts = 4,
): Promise<void> {
  let lastError: unknown;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      await database.$transaction(work, {
        isolationLevel: 'Serializable' as Prisma.TransactionIsolationLevel,
      });
      return;
    } catch (err: unknown) {
      lastError = err;
      if (attempt + 1 >= maxAttempts || !isTransientSerializationError(err)) {
        throw err;
      }
      const delayMs = Math.min(250, 15 * 2 ** attempt) + Math.floor(Math.random() * 15);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  throw lastError;
}

@Injectable()
export class DocumentAuditService {
  private readonly logger = new Logger(DocumentAuditService.name);
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
   * Thuật toán: Ghi nối tiếp sự kiện kiểm toán phân vùng `DOCUMENT` có tự động thử lại khi tranh chấp chuỗi băm đồng thời.
   */
  async record(event: DocumentAuditEvent, context: RequestContext): Promise<void> {
    try {
      await runSerializableAuditTransaction(this.database, async (transaction) => {
        const mergedDetails = {
          ...(event.versionNo !== undefined && event.versionNo !== null
            ? { versionNo: event.versionNo }
            : {}),
          ...(event.details ?? {}),
        };
        await appendChainedAuditLog(transaction, {
          partition: 'DOCUMENT',
          hmacKey: this.hmacKey,
          keyVersion: this.keyVersion,
          action: event.action,
          outcome: event.outcome,
          objectType: 'DOCUMENT',
          objectId: event.documentId ?? null,
          documentId: event.documentId ?? null,
          actorUserId: event.actorUserId ?? null,
          actorUsername: event.actorUsername ?? null,
          reasonCode: event.reasonCode ?? null,
          details: mergedDetails,
          context,
        });
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Failed to record document audit log: ${msg}`);
      if (process.env['NODE_ENV'] === 'production') {
        throw new Error(`Audit logging failed: ${msg}`);
      }
    }
  }
}

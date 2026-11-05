/**
 * Module: Dịch vụ Nhật ký Kiểm toán Vòng đời Tài liệu (Document Lifecycle Hash-Chained Audit Service)
 * Thuật toán: Ghi nối tiếp sự kiện kiểm toán phân vùng `DOCUMENT` với chuỗi băm HMAC chống sửa đổi.
 */
import { Injectable, Logger } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import { appendChainedAuditLog, resolveActiveAuditKey } from '../audit/audit-chain-helper.js';
import type { RequestContext } from '../auth/auth.types.js';

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

@Injectable()
export class DocumentAuditService {
  private readonly logger = new Logger(DocumentAuditService.name);
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
   * Thuật toán: Ghi Nối Tiếp Chuỗi Băm Kiểm Toán Phân Vùng Tài Liệu (Fail-Closed Document Audit Append)
   * Mục đích: Đảm bảo mọi thao tác tải lên, quét mã độc, phân loại, kích hoạt và tìm kiếm tài liệu đều được ký chuỗi HMAC.
   * Cơ chế hoạt động:
   *   - Hợp nhất `versionNo` vào `details`, mở giao dịch gọi `appendChainedAuditLog` trên phân vùng `DOCUMENT`,
   *     và cưỡng chế ném lỗi Fail-Closed nếu ghi kiểm toán thất bại trong môi trường `production`.
   */
  async record(event: DocumentAuditEvent, context: RequestContext): Promise<void> {
    try {
      await this.database.$transaction(async (transaction) => {
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
      // D-BR18: Do not swallow audit logging failures in production
      if (process.env['NODE_ENV'] === 'production') {
        throw new Error(`Audit logging failed: ${msg}`);
      }
    }
  }
}

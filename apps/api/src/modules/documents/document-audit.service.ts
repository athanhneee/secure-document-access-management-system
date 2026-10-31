import { Injectable, Logger } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import { appendChainedAuditLog, resolveAuditHmacKey } from '../audit/audit-chain-helper.js';
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
  private readonly database = getDatabaseClient();

  constructor(config: AppConfigService) {
    this.hmacKey = resolveAuditHmacKey(config);
  }

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

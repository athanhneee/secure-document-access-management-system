import { createHmac, randomUUID } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import type { RequestContext } from '../auth/auth.types.js';

export interface DocumentAuditEvent {
  action:
    | 'DOCUMENT_UPLOAD_STARTED'
    | 'DOCUMENT_SCAN_RESULT'
    | 'DOCUMENT_UPLOAD_COMPLETED'
    | 'DOCUMENT_UPLOAD_FAILED';
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
    this.hmacKey = config.get('DOCUMENT_AUDIT_HMAC_KEY');
  }

  async record(event: DocumentAuditEvent, context: RequestContext): Promise<void> {
    try {
      await this.database.$transaction(async (transaction) => {
        const partition = 'DOCUMENT';
        await transaction.$executeRawUnsafe(
          'SELECT pg_advisory_xact_lock(hashtext($1))',
          partition,
        );
        const previous = await transaction.$queryRawUnsafe<
          Array<{ entry_hash: string; chain_sequence: bigint }>
        >(
          'SELECT entry_hash, chain_sequence FROM audit_logs WHERE chain_partition=$1 ORDER BY chain_sequence DESC LIMIT 1',
          partition,
        );
        const prior = previous[0];
        const sequence = (prior?.chain_sequence ?? 0n) + 1n;
        const correlationId =
          /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
            context.correlationId,
          )
            ? context.correlationId
            : randomUUID();

        // Sanitize details: ensure no file contents, no DEK, no raw IV
        const sanitizedDetails = { ...(event.details ?? {}) };
        delete sanitizedDetails['dek'];
        delete sanitizedDetails['content'];
        delete sanitizedDetails['plaintext'];
        delete sanitizedDetails['data'];

        const canonical = JSON.stringify({
          action: event.action,
          actorUserId: event.actorUserId?.toString() ?? null,
          actorUsername: event.actorUsername ?? null,
          correlationId,
          details: sanitizedDetails,
          documentId: event.documentId ?? null,
          outcome: event.outcome,
          previousHash: prior?.entry_hash ?? null,
          reasonCode: event.reasonCode ?? null,
          sequence: sequence.toString(),
        });

        const entryHash = createHmac('sha256', this.hmacKey).update(canonical).digest('hex');

        await transaction.auditLog.create({
          data: {
            actor_user_id: event.actorUserId ?? null,
            actor_username: event.actorUsername ?? (event.actorUserId ? null : 'anonymous'),
            action: event.action,
            object_type: 'DOCUMENT',
            object_id: event.documentId ?? null,
            document_id: event.documentId ?? null,
            outcome: event.outcome,
            reason_code: event.reasonCode ?? null,
            ip_address: context.ip,
            user_agent: context.userAgent ?? null,
            correlation_id: correlationId,
            details: sanitizedDetails,
            previous_hash: prior?.entry_hash ?? null,
            entry_hash: entryHash,
            chain_partition: partition,
            chain_sequence: sequence,
            hmac_key_version: 1,
          },
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

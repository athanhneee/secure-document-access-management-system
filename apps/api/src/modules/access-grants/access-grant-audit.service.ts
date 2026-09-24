import { createHmac, randomUUID } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';

export type GrantAuditAction =
  | 'GRANT_CREATED'
  | 'GRANT_EXTENDED'
  | 'GRANT_REVOKED'
  | 'GRANT_EXPIRED'
  | 'GRANT_SESSIONS_TERMINATED'
  | 'ACCESS_REQUEST_CREATED'
  | 'ACCESS_REQUEST_APPROVED'
  | 'ACCESS_REQUEST_REJECTED'
  | 'ACCESS_REQUEST_CANCELLED';

export interface GrantAuditEvent {
  action: GrantAuditAction;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  objectId?: string | null;
  documentId?: string | null;
  reasonCode?: string | null;
  details?: Record<string, string | number | boolean | null>;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

@Injectable()
export class AccessGrantAuditService {
  private readonly logger = new Logger(AccessGrantAuditService.name);
  private readonly hmacKey: string;
  private readonly database = getDatabaseClient();

  constructor(config: AppConfigService) {
    this.hmacKey = config.get('DOCUMENT_AUDIT_HMAC_KEY');
  }

  /**
   * Record an audit event in the ACCESS_GRANT partition with HMAC chain integrity.
   * Can be called within an existing Prisma transaction or standalone.
   */
  async record(
    event: GrantAuditEvent,
    principal: AuthPrincipal,
    context: RequestContext,
    transactionClient?: Parameters<Parameters<typeof this.database.$transaction>[0]>[0],
  ): Promise<void> {
    const execute = async (
      tx: Parameters<Parameters<typeof this.database.$transaction>[0]>[0],
    ): Promise<void> => {
      const partition = 'ACCESS_GRANT';
      await tx.$executeRawUnsafe('SELECT pg_advisory_xact_lock(hashtext($1))', partition);

      const previous = await tx.$queryRawUnsafe<
        Array<{ entry_hash: string; chain_sequence: bigint }>
      >(
        'SELECT entry_hash, chain_sequence FROM audit_logs WHERE chain_partition=$1 ORDER BY chain_sequence DESC LIMIT 1',
        partition,
      );
      const prior = previous[0];
      const sequence = (prior?.chain_sequence ?? 0n) + 1n;
      const correlationId = UUID_REGEX.test(context.correlationId)
        ? context.correlationId
        : randomUUID();

      // Sanitize details: redact sensitive fields
      const sanitizedDetails = { ...(event.details ?? {}) };
      delete sanitizedDetails['dek'];
      delete sanitizedDetails['token'];
      delete sanitizedDetails['password'];
      delete sanitizedDetails['content'];
      delete sanitizedDetails['secret'];

      const canonical = JSON.stringify({
        action: event.action,
        actorUserId: principal.userId.toString(),
        actorUsername: principal.username,
        correlationId,
        details: sanitizedDetails,
        documentId: event.documentId ?? null,
        objectId: event.objectId ?? null,
        outcome: event.outcome,
        previousHash: prior?.entry_hash ?? null,
        reasonCode: event.reasonCode ?? null,
        sequence: sequence.toString(),
      });

      const entryHash = createHmac('sha256', this.hmacKey).update(canonical).digest('hex');

      await tx.auditLog.create({
        data: {
          actor_user_id: principal.userId,
          actor_username: principal.username,
          action: event.action,
          object_type: 'ACCESS_GRANT',
          object_id: event.objectId ?? null,
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
    };

    try {
      if (transactionClient) {
        await execute(transactionClient);
      } else {
        await this.database.$transaction(async (tx) => {
          await execute(tx);
        });
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Failed to record grant audit log: ${msg}`);
      // D-BR18: Do not swallow audit logging failures in production
      if (process.env['NODE_ENV'] === 'production') {
        throw new Error(`Audit logging failed: ${msg}`);
      }
    }
  }
}

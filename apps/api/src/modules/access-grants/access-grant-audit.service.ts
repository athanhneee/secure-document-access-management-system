import { Injectable, Logger } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import { appendChainedAuditLog, resolveAuditHmacKey } from '../audit/audit-chain-helper.js';
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

@Injectable()
export class AccessGrantAuditService {
  private readonly logger = new Logger(AccessGrantAuditService.name);
  private readonly hmacKey: string;
  private readonly database = getDatabaseClient();

  constructor(config: AppConfigService) {
    this.hmacKey = resolveAuditHmacKey(config);
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
      await appendChainedAuditLog(tx, {
        partition: 'ACCESS_GRANT',
        hmacKey: this.hmacKey,
        action: event.action,
        outcome: event.outcome,
        objectType: 'ACCESS_GRANT',
        objectId: event.objectId ?? null,
        documentId: event.documentId ?? null,
        actorUserId: principal.userId,
        actorUsername: principal.username,
        reasonCode: event.reasonCode ?? null,
        details: event.details ?? {},
        context,
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

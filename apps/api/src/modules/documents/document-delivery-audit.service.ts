import { Injectable } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import { appendChainedAuditLog, resolveAuditHmacKey } from '../audit/audit-chain-helper.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';

export type DeliveryAuditAction =
  | 'ACCESS_PERMITTED'
  | 'ACCESS_DENIED'
  | 'WATERMARK_GENERATED'
  | 'DOCUMENT_PREVIEWED'
  | 'DOCUMENT_DOWNLOADED'
  | 'SESSION_TERMINATED'
  | 'WATERMARK_TRACED';

export interface DeliveryAuditEvent {
  action: DeliveryAuditAction;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  objectId?: string | null;
  documentId?: string | null;
  sessionId?: string | null;
  reasonCode?: string | null;
  details?: Record<string, string | number | boolean | null>;
}

@Injectable()
export class DocumentDeliveryAuditService {
  private readonly hmacKey: string;
  private readonly database = getDatabaseClient();

  constructor(config: AppConfigService) {
    this.hmacKey = resolveAuditHmacKey(config);
  }

  /**
   * Record an access delivery audit event in the ACCESS_SESSION partition with HMAC chain integrity.
   */
  async record(
    event: DeliveryAuditEvent,
    principal: AuthPrincipal,
    context: RequestContext,
    transactionClient?: Parameters<Parameters<typeof this.database.$transaction>[0]>[0],
  ): Promise<void> {
    const execute = async (
      tx: Parameters<Parameters<typeof this.database.$transaction>[0]>[0],
    ): Promise<void> => {
      await appendChainedAuditLog(tx, {
        partition: 'ACCESS_SESSION',
        hmacKey: this.hmacKey,
        action: event.action,
        outcome: event.outcome,
        objectType: 'ACCESS_SESSION',
        objectId: event.objectId ?? null,
        documentId: event.documentId ?? null,
        accessSessionId: event.sessionId ?? null,
        actorUserId: principal.userId,
        actorUsername: principal.username,
        reasonCode: event.reasonCode ?? null,
        details: event.details ?? {},
        context,
      });
    };

    if (transactionClient) {
      await execute(transactionClient);
    } else {
      await this.database.$transaction(execute);
    }
  }
}

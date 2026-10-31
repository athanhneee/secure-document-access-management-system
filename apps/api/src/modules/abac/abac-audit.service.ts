import { Injectable } from '@nestjs/common';
import type { Prisma } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import { appendChainedAuditLog, resolveAuditHmacKey } from '../audit/audit-chain-helper.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';

export interface AbacAuditEvent {
  action: 'POLICY_SIMULATED' | 'POLICY_ACTIVATED';
  objectType: 'POLICY_SIMULATION' | 'POLICY';
  objectId: string;
  documentId?: string | undefined;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  details: Record<string, string | number | boolean | null>;
}

@Injectable()
export class AbacAuditService {
  private readonly hmacKey: string;

  constructor(config: AppConfigService) {
    this.hmacKey = resolveAuditHmacKey(config);
  }

  async record(
    transaction: Prisma.TransactionClient,
    event: AbacAuditEvent,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<void> {
    await appendChainedAuditLog(transaction, {
      partition: 'ABAC',
      hmacKey: this.hmacKey,
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
  }
}

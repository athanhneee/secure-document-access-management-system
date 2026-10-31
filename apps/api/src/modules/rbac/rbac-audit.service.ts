import { Injectable } from '@nestjs/common';
import type { Prisma } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import { appendChainedAuditLog, resolveAuditHmacKey } from '../audit/audit-chain-helper.js';
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

  constructor(config: AppConfigService) {
    this.hmacKey = resolveAuditHmacKey(config);
  }

  async record(
    transaction: Prisma.TransactionClient,
    event: RbacAuditEvent,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<void> {
    await appendChainedAuditLog(transaction, {
      partition: 'RBAC',
      hmacKey: this.hmacKey,
      action: event.action,
      outcome: 'SUCCESS',
      objectType: event.objectType,
      objectId: event.objectId,
      actorUserId: principal.userId,
      actorUsername: principal.username,
      details: { before: event.before, after: event.after },
      context,
    });
  }
}

import { Injectable } from '@nestjs/common';
import type { Prisma } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import { appendChainedAuditLog, resolveActiveAuditKey } from '../audit/audit-chain-helper.js';
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
  private readonly keyVersion: number;

  constructor(config: AppConfigService) {
    // CONFLICT-RESOLVED: Sử dụng khóa xoay vòng đang kích hoạt kèm hmac_key_version đồng bộ với AuditWriterService.
    const active = resolveActiveAuditKey(config);
    this.hmacKey = active.hmacKey;
    this.keyVersion = active.keyVersion;
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
      keyVersion: this.keyVersion,
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

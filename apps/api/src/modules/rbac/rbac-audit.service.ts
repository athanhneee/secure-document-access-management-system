import { createHmac, randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import type { Prisma } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
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
    this.hmacKey = config.get('AUTH_AUDIT_HMAC_KEY');
  }

  async record(
    transaction: Prisma.TransactionClient,
    event: RbacAuditEvent,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<void> {
    const partition = 'RBAC';
    await transaction.$executeRawUnsafe('SELECT pg_advisory_xact_lock(hashtext($1))', partition);
    const previous = await transaction.$queryRawUnsafe<
      Array<{ entry_hash: string; chain_sequence: bigint }>
    >(
      'SELECT entry_hash, chain_sequence FROM audit_logs WHERE chain_partition=$1 ORDER BY chain_sequence DESC LIMIT 1',
      partition,
    );
    const prior = previous[0];
    const sequence = (prior?.chain_sequence ?? 0n) + 1n;
    const correlationId = /^[0-9a-f-]{36}$/iu.test(context.correlationId)
      ? context.correlationId
      : randomUUID();
    const details = { before: event.before, after: event.after } as Prisma.InputJsonValue;
    const canonical = JSON.stringify({
      action: event.action,
      actorUserId: principal.userId.toString(),
      correlationId,
      details,
      objectId: event.objectId,
      objectType: event.objectType,
      previousHash: prior?.entry_hash ?? null,
      sequence: sequence.toString(),
    });
    const entryHash = createHmac('sha256', this.hmacKey).update(canonical).digest('hex');
    await transaction.auditLog.create({
      data: {
        actor_user_id: principal.userId,
        actor_username: principal.username,
        action: event.action,
        object_type: event.objectType,
        object_id: event.objectId,
        outcome: 'SUCCESS',
        ip_address: context.ip,
        user_agent: context.userAgent ?? null,
        correlation_id: correlationId,
        details,
        previous_hash: prior?.entry_hash ?? null,
        entry_hash: entryHash,
        chain_partition: partition,
        chain_sequence: sequence,
        hmac_key_version: 1,
      },
    });
  }
}

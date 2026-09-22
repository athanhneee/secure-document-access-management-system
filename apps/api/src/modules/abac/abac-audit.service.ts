import { createHmac, randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import type { Prisma } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
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
    this.hmacKey = config.get('AUTH_AUDIT_HMAC_KEY');
  }

  async record(
    transaction: Prisma.TransactionClient,
    event: AbacAuditEvent,
    principal: AuthPrincipal,
    context: RequestContext,
  ): Promise<void> {
    const partition = 'ABAC';
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
    const details = event.details as Prisma.InputJsonValue;
    const canonical = JSON.stringify({
      action: event.action,
      actorUserId: principal.userId.toString(),
      correlationId,
      details,
      documentId: event.documentId ?? null,
      objectId: event.objectId,
      objectType: event.objectType,
      outcome: event.outcome,
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
        document_id: event.documentId ?? null,
        outcome: event.outcome,
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

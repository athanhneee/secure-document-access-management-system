import { createHmac, randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import type { RequestContext } from './auth.types.js';

interface AuditEvent {
  action: string;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  actorUserId?: bigint | undefined;
  actorUsername?: string | undefined;
  objectId?: string | undefined;
  sessionId?: string | undefined;
  reasonCode?: string | undefined;
  details?: Record<string, string | number | boolean | null> | undefined;
}

@Injectable()
export class AuthAuditService {
  private readonly hmacKey: string;
  private readonly database = getDatabaseClient();

  constructor(config: AppConfigService) {
    this.hmacKey = config.get('AUTH_AUDIT_HMAC_KEY');
  }

  async record(event: AuditEvent, context: RequestContext): Promise<void> {
    await this.database.$transaction(async (transaction) => {
      const partition = 'AUTH';
      await transaction.$executeRawUnsafe('SELECT pg_advisory_xact_lock(hashtext($1))', partition);
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
      const canonical = JSON.stringify({
        action: event.action,
        actorUserId: event.actorUserId?.toString() ?? null,
        actorUsername: event.actorUsername ?? null,
        correlationId,
        details: event.details ?? {},
        objectId: event.objectId ?? null,
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
          object_type: 'AUTHENTICATION',
          object_id: event.objectId ?? null,
          outcome: event.outcome,
          reason_code: event.reasonCode ?? null,
          ip_address: context.ip,
          user_agent: context.userAgent ?? null,
          correlation_id: correlationId,
          details: event.details ?? {},
          previous_hash: prior?.entry_hash ?? null,
          entry_hash: entryHash,
          chain_partition: partition,
          chain_sequence: sequence,
          hmac_key_version: 1,
        },
      });
    });
  }
}

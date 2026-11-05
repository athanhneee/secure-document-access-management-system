import { Injectable } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppConfigService } from '../../config/config.service.js';
import { appendChainedAuditLog, resolveActiveAuditKey } from '../audit/audit-chain-helper.js';
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
  private readonly keyVersion: number;
  private readonly database = getDatabaseClient();

  constructor(config: AppConfigService) {
    // CONFLICT-RESOLVED: Trích xuất đồng thời khóa HMAC đang kích hoạt và hmac_key_version từ vòng khóa xoay vòng thay vì mặc định gắn cứng phiên bản 1.
    const active = resolveActiveAuditKey(config);
    this.hmacKey = active.hmacKey;
    this.keyVersion = active.keyVersion;
  }

  async record(event: AuditEvent, context: RequestContext): Promise<void> {
    await this.database.$transaction(async (transaction) => {
      await appendChainedAuditLog(transaction, {
        partition: 'AUTH',
        hmacKey: this.hmacKey,
        keyVersion: this.keyVersion,
        action: event.action,
        outcome: event.outcome,
        objectType: 'AUTHENTICATION',
        objectId: event.objectId ?? null,
        actorUserId: event.actorUserId ?? null,
        actorUsername: event.actorUsername ?? null,
        accessSessionId: event.sessionId ?? null,
        reasonCode: event.reasonCode ?? null,
        details: event.details ?? {},
        context,
      });
    });
  }
}

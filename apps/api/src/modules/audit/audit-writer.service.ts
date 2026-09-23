import { createHmac, randomUUID } from 'node:crypto';
import { Injectable, Logger, Optional } from '@nestjs/common';
import { getDatabaseClient, type Prisma } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import { AppConfigService } from '../../config/config.service.js';
import type { RequestContext } from '../auth/auth.types.js';
import { AuditRedactionService } from './audit-redaction.service.js';
import { canonicalizeJson } from './audit-canonicalizer.js';

export interface AuditWriteEvent {
  action: string;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  objectType: string;
  objectId?: string | null;
  actorUserId?: bigint | null;
  actorUsername?: string | null;
  documentId?: string | null;
  accessSessionId?: string | null;
  reasonCode?: string | null;
  details?: Record<string, unknown> | null;
  chainPartition?: string;
  occurredAt?: Date;
}

export class AuditWriteException extends Error {
  readonly code = AppErrorCode.AUDIT_WRITE_FAILED;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'AuditWriteException';
    if (cause) {
      this.cause = cause;
    }
  }
}

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class AuditWriterService {
  private readonly logger = new Logger(AuditWriterService.name);
  private readonly defaultHmacKey: string;
  private readonly keyRotationMap = new Map<number, string>();
  private readonly database: PrismaClient;

  constructor(
    private readonly config: AppConfigService,
    private readonly redactionService: AuditRedactionService,
    @Optional() databaseClient?: PrismaClient,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
    const primaryKey =
      this.config.get('AUDIT_INTEGRITY_KEY') ||
      this.config.get('DOCUMENT_AUDIT_HMAC_KEY') ||
      'local-only-audit-integrity-hmac-key-0000000000000000';
    this.defaultHmacKey = primaryKey;
    this.keyRotationMap.set(1, primaryKey);

    const rotationJson = this.config.get('AUDIT_KEY_ROTATION_JSON');
    if (rotationJson) {
      try {
        const parsed = JSON.parse(rotationJson) as Record<string, string>;
        for (const [ver, key] of Object.entries(parsed)) {
          const vNum = Number(ver);
          if (Number.isInteger(vNum) && vNum > 0 && typeof key === 'string' && key.length >= 32) {
            this.keyRotationMap.set(vNum, key);
          }
        }
      } catch (err) {
        this.logger.warn(`Failed to parse AUDIT_KEY_ROTATION_JSON: ${String(err)}`);
      }
    }
  }

  /**
   * Retrieves the HMAC integrity key for a specific key version.
   */
  getHmacKey(version = 1): string {
    return this.keyRotationMap.get(version) ?? this.defaultHmacKey;
  }

  /**
   * Gets the active key version for writing new audit entries.
   */
  getActiveKeyVersion(): number {
    let maxVersion = 1;
    for (const v of this.keyRotationMap.keys()) {
      if (v > maxVersion) maxVersion = v;
    }
    return maxVersion;
  }

  /**
   * Convenience wrapper to record an audit log with optional default context.
   */
  async writeLog(
    event: AuditWriteEvent,
    context?: Partial<RequestContext>,
    externalTx?: Prisma.TransactionClient,
  ): Promise<{
    id: bigint;
    entry_hash: string;
    chain_partition: string;
    chain_sequence: bigint;
  }> {
    const ctx: RequestContext = {
      ip: context?.ip ?? '127.0.0.1',
      userAgent: context?.userAgent,
      correlationId: context?.correlationId ?? randomUUID(),
    };
    return this.record(event, ctx, externalTx);
  }

  /**
   * Records a tamper-evident audit event.
   *
   * May be executed within an existing Prisma transaction client or standalone.
   * Never swallows audit errors; if logging fails, throws AuditWriteException.
   */
  async record(
    event: AuditWriteEvent,
    context: RequestContext,
    externalTx?: Prisma.TransactionClient,
  ): Promise<{
    id: bigint;
    entry_hash: string;
    chain_partition: string;
    chain_sequence: bigint;
  }> {
    const partition = event.chainPartition || 'GLOBAL';

    const executeOperation = async (tx: Prisma.TransactionClient) => {
      // 1. Acquire transaction advisory lock isolated to this specific chain partition
      await tx.$executeRawUnsafe('SELECT pg_advisory_xact_lock(hashtext($1))', partition);

      // 2. Fetch the latest record in this partition
      const previous = await tx.$queryRawUnsafe<
        Array<{ entry_hash: string; chain_sequence: bigint }>
      >(
        'SELECT entry_hash, chain_sequence FROM audit_logs WHERE chain_partition=$1 ORDER BY chain_sequence DESC LIMIT 1',
        partition,
      );

      const prior = previous[0];
      const sequence = (prior?.chain_sequence ?? 0n) + 1n;
      const previousHash = prior?.entry_hash ?? null;

      // 3. Normalize correlation ID and timestamps
      const correlationId =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
          context.correlationId,
        )
          ? context.correlationId
          : randomUUID();

      const occurredAt = event.occurredAt ?? new Date();

      // 4. Redact sensitive data from details, reason, user agent, IP
      const sanitizedDetails = this.redactionService.sanitizeDetails(event.details);
      const sanitizedReason = this.redactionService.sanitizeReason(event.reasonCode);
      const sanitizedUserAgent = this.redactionService.sanitizeUserAgent(context.userAgent);
      const sanitizedIp = this.redactionService.sanitizeIp(context.ip);
      const keyVersion = this.getActiveKeyVersion();
      const activeKey = this.getHmacKey(keyVersion);

      const actorUsername = event.actorUsername ?? (event.actorUserId ? null : 'anonymous');

      // 5. Build canonical payload for deterministic HMAC-SHA-256 calculation (RFC 8785)
      const canonicalPayload = {
        action: event.action,
        actorUserId: event.actorUserId ? event.actorUserId.toString() : null,
        actorUsername,
        chainAlgorithm: 'HMAC-SHA-256',
        chainPartition: partition,
        chainSequence: sequence.toString(),
        correlationId,
        details: sanitizedDetails,
        documentId: event.documentId ?? null,
        accessSessionId: event.accessSessionId ?? null,
        ipAddress: sanitizedIp,
        objectType: event.objectType,
        objectId: event.objectId ?? null,
        occurredAt: occurredAt.toISOString(),
        outcome: event.outcome,
        previousHash,
        reasonCode: sanitizedReason,
        userAgent: sanitizedUserAgent,
      };

      const canonicalString = canonicalizeJson(canonicalPayload);
      const entryHash = createHmac('sha256', activeKey)
        .update(canonicalString, 'utf8')
        .digest('hex');

      // 6. Append audit log row
      const created = await tx.auditLog.create({
        data: {
          occurred_at: occurredAt,
          actor_user_id: event.actorUserId ?? null,
          actor_username: actorUsername,
          action: event.action,
          object_type: event.objectType,
          object_id: event.objectId ?? null,
          document_id: event.documentId ?? null,
          access_session_id: event.accessSessionId ?? null,
          outcome: event.outcome,
          reason_code: sanitizedReason,
          ip_address: sanitizedIp,
          user_agent: sanitizedUserAgent,
          correlation_id: correlationId,
          details: sanitizedDetails as Prisma.InputJsonValue,
          previous_hash: previousHash,
          entry_hash: entryHash,
          chain_partition: partition,
          chain_sequence: sequence,
          hmac_key_version: keyVersion,
          chain_algorithm: 'HMAC-SHA-256',
        },
        select: {
          id: true,
          entry_hash: true,
          chain_partition: true,
          chain_sequence: true,
        },
      });

      return created;
    };

    try {
      if (externalTx) {
        return await executeOperation(externalTx);
      }
      return await this.database.$transaction(executeOperation);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(
        `Critical: Audit logging failed: ${msg}`,
        err instanceof Error ? err.stack : undefined,
      );
      throw new AuditWriteException(`Failed to reliably record audit event: ${msg}`, err);
    }
  }
}

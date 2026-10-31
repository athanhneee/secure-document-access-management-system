import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import type { Prisma } from '@sda/database';
import type { AppConfigService } from '../../config/config.service.js';
import type { RequestContext } from '../auth/auth.types.js';
import { canonicalizeJson } from './audit-canonicalizer.js';
import { AuditRedactionService } from './audit-redaction.service.js';

const sharedRedactor = new AuditRedactionService();
const UUID_V1_TO_V5_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function safeConfigKey(
  config: AppConfigService,
  key: 'AUDIT_INTEGRITY_KEY' | 'DOCUMENT_AUDIT_HMAC_KEY' | 'AUTH_AUDIT_HMAC_KEY',
): string | undefined {
  try {
    const val = config.get(key);
    return typeof val === 'string' && val.length > 0 ? val : undefined;
  } catch {
    return undefined;
  }
}

export function resolveAuditHmacKey(config: AppConfigService): string {
  return (
    safeConfigKey(config, 'AUDIT_INTEGRITY_KEY') ||
    safeConfigKey(config, 'DOCUMENT_AUDIT_HMAC_KEY') ||
    safeConfigKey(config, 'AUTH_AUDIT_HMAC_KEY') ||
    'local-only-audit-integrity-hmac-key-0000000000000000'
  );
}

export function safeTimingEqualString(
  left: string | null | undefined,
  right: string | null | undefined,
): boolean {
  if (typeof left !== 'string' || typeof right !== 'string') {
    return false;
  }
  const leftBuf = Buffer.from(left, 'utf8');
  const rightBuf = Buffer.from(right, 'utf8');
  if (leftBuf.length !== rightBuf.length) {
    return false;
  }
  return timingSafeEqual(leftBuf, rightBuf);
}

export interface ChainedAuditAppendInput {
  partition: string;
  hmacKey: string;
  keyVersion?: number;
  action: string;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  objectType: string;
  objectId?: string | null | undefined;
  actorUserId?: bigint | null | undefined;
  actorUsername?: string | null | undefined;
  documentId?: string | null | undefined;
  accessSessionId?: string | null | undefined;
  reasonCode?: string | null | undefined;
  details?: Record<string, unknown> | null | undefined;
  occurredAt?: Date | undefined;
  context: RequestContext;
}

export async function appendChainedAuditLog(
  tx: Prisma.TransactionClient,
  input: ChainedAuditAppendInput,
): Promise<{
  id: bigint;
  entry_hash: string;
  chain_partition: string;
  chain_sequence: bigint;
}> {
  const partition = input.partition || 'GLOBAL';
  await tx.$executeRawUnsafe('SELECT pg_advisory_xact_lock(hashtext($1))', partition);

  const previous = await tx.$queryRawUnsafe<Array<{ entry_hash: string; chain_sequence: bigint }>>(
    'SELECT entry_hash, chain_sequence FROM audit_logs WHERE chain_partition=$1 ORDER BY chain_sequence DESC LIMIT 1',
    partition,
  );

  const prior = previous[0];
  const sequence = (prior?.chain_sequence ?? 0n) + 1n;
  const previousHash = prior?.entry_hash ?? null;

  const correlationId = UUID_V1_TO_V5_RE.test(input.context.correlationId)
    ? input.context.correlationId
    : randomUUID();

  const occurredAt = input.occurredAt ?? new Date();
  const sanitizedDetails = sharedRedactor.sanitizeDetails(input.details ?? {});
  const sanitizedReason = sharedRedactor.sanitizeReason(input.reasonCode ?? null);
  const sanitizedUserAgent = sharedRedactor.sanitizeUserAgent(input.context.userAgent ?? null);
  const sanitizedIp = sharedRedactor.sanitizeIp(input.context.ip ?? null);
  const keyVersion = input.keyVersion ?? 1;
  const actorUsername = input.actorUsername ?? (input.actorUserId ? null : 'anonymous');

  const canonicalPayload = {
    action: input.action,
    actorUserId: input.actorUserId ? input.actorUserId.toString() : null,
    actorUsername,
    chainAlgorithm: 'HMAC-SHA-256',
    chainPartition: partition,
    chainSequence: sequence.toString(),
    correlationId,
    details: sanitizedDetails,
    documentId: input.documentId ?? null,
    accessSessionId: input.accessSessionId ?? null,
    ipAddress: sanitizedIp,
    objectType: input.objectType,
    objectId: input.objectId ?? null,
    occurredAt: occurredAt.toISOString(),
    outcome: input.outcome,
    previousHash,
    reasonCode: sanitizedReason,
    userAgent: sanitizedUserAgent,
  };

  const canonicalString = canonicalizeJson(canonicalPayload);
  const entryHash = createHmac('sha256', input.hmacKey)
    .update(canonicalString, 'utf8')
    .digest('hex');

  return tx.auditLog.create({
    data: {
      occurred_at: occurredAt,
      actor_user_id: input.actorUserId ?? null,
      actor_username: actorUsername,
      action: input.action,
      object_type: input.objectType,
      object_id: input.objectId ?? null,
      document_id: input.documentId ?? null,
      access_session_id: input.accessSessionId ?? null,
      outcome: input.outcome,
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
}

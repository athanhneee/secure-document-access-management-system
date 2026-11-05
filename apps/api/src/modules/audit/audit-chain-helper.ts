/**
 * @module AuditChainHelper
 * Trợ giúp nối chuỗi băm kiểm toán chống giả mạo theo phân vùng (Partitioned Tamper-Evident Hash Chain).
 * Kết hợp khóa tư vấn mức giao dịch PostgreSQL (`pg_advisory_xact_lock`), chuẩn hóa JSON tất định RFC 8785 (JCS)
 * và chữ ký thông điệp HMAC-SHA256.
 */
import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { buildAuditKeyRing, type AuditKeyRing } from '@sda/contracts';
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
  key:
    | 'AUDIT_INTEGRITY_KEY'
    | 'DOCUMENT_AUDIT_HMAC_KEY'
    | 'AUTH_AUDIT_HMAC_KEY'
    | 'AUDIT_KEY_ROTATION_JSON',
): string | undefined {
  try {
    const val = config.get(key);
    return typeof val === 'string' && val.length > 0 ? val : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Thuật toán: Phân giải thứ tự ưu tiên khóa gốc HMAC kiểm toán (Hierarchical Primary Key Resolution).
 */
export function resolvePrimaryAuditHmacKey(config: AppConfigService): string {
  const configured =
    safeConfigKey(config, 'AUDIT_INTEGRITY_KEY') ||
    safeConfigKey(config, 'DOCUMENT_AUDIT_HMAC_KEY') ||
    safeConfigKey(config, 'AUTH_AUDIT_HMAC_KEY');
  if (configured) return configured;

  // CONFLICT-RESOLVED: Tuyệt đối từ chối khóa HMAC kiểm toán mặc định gắn cứng khi chạy ở môi trường Production (HIGH-09).
  let nodeEnv: string | undefined;
  try {
    nodeEnv = config.get('NODE_ENV');
  } catch {
    nodeEnv = process.env['NODE_ENV'];
  }
  if (nodeEnv === 'production') {
    throw new Error(
      'AUDIT_INTEGRITY_KEY (or DOCUMENT_AUDIT_HMAC_KEY / AUTH_AUDIT_HMAC_KEY) must be configured in production.',
    );
  }
  return 'local-only-audit-integrity-hmac-key-0000000000000000';
}

/**
 * Thuật toán: Khởi tạo vòng khóa xoay vòng HMAC kiểm toán (Versioned Audit Key-Ring Resolution).
 * Kết hợp khóa gốc phiên bản 1 với bản đồ xoay vòng `AUDIT_KEY_ROTATION_JSON` từ `@sda/contracts`.
 */
export function resolveAuditKeyRing(
  config: AppConfigService,
  onParseWarning?: (error: unknown) => void,
): AuditKeyRing {
  // CONFLICT-RESOLVED: Bổ sung hỗ trợ xoay vòng khóa AUDIT_KEY_ROTATION_JSON vào audit-chain-helper.ts đồng bộ với AuditWriterService thay vì chỉ đọc khóa tĩnh phiên bản 1.
  const primaryKey = resolvePrimaryAuditHmacKey(config);
  const rotationJson = safeConfigKey(config, 'AUDIT_KEY_ROTATION_JSON');
  return buildAuditKeyRing(primaryKey, rotationJson, onParseWarning);
}

/**
 * Thuật toán: Trích xuất cặp khóa HMAC và số phiên bản khóa đang kích hoạt (`activeKey`, `activeVersion`).
 */
export function resolveActiveAuditKey(config: AppConfigService): {
  hmacKey: string;
  keyVersion: number;
} {
  const ring = resolveAuditKeyRing(config);
  return { hmacKey: ring.activeKey, keyVersion: ring.activeVersion };
}

/**
 * Thuật toán: Phân giải khóa HMAC kiểm toán đang kích hoạt (Active Rotated Key Resolution).
 */
export function resolveAuditHmacKey(config: AppConfigService): string {
  return resolveAuditKeyRing(config).activeKey;
}

/**
 * Thuật toán: So sánh chuỗi thời gian hằng số chống tấn công kênh kề (Constant-Time String Equality).
 * Cơ chế hoạt động: Chuyển hai chuỗi sang bộ đệm UTF-8, đối chiếu chiều dài byte và gọi `timingSafeEqual`
 * để ngăn kẻ tấn công suy đoán từng ký tự mã băm HMAC qua độ trễ phản hồi.
 */
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
  redactor?: AuditRedactionService | undefined;
}

/**
 * Thuật toán: Ghi nối tiếp nhật ký kiểm toán chuỗi băm tuần tự hóa theo phân vùng (`pg_advisory_xact_lock` + RFC 8785 HMAC-SHA256).
 * Cơ chế hoạt động:
 *   1. Chiếm khóa tư vấn mức giao dịch `pg_advisory_xact_lock(hashtext(partition))` để tuần tự hóa tuyệt đối
 *      mọi thao tác chèn đồng thời trên cùng một phân vùng chuỗi mà không chặn các phân vùng khác.
 *   2. Đọc bản ghi đỉnh chuỗi (`ORDER BY chain_sequence DESC LIMIT 1`) để xác định `sequence = prior + 1` và `previousHash`.
 *   3. Làm sạch & che dấu dữ liệu nhạy cảm trên `details`, `reasonCode`, `userAgent` và `ip`.
 *   4. Chuẩn hóa payload theo RFC 8785 (JSON Canonicalization Scheme) và tính `entryHash = HMAC-SHA256(hmacKey, canonicalString)`.
 *   5. Ghi bản ghi bất biến kèm liên kết ngược `previous_hash` xuống bảng `audit_logs`.
 */
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
  // CONFLICT-RESOLVED: Dùng hashtextextended($1, 0) 64-bit thay cho hashtext($1) 32-bit để triệt tiêu nguy cơ xung đột khóa tư vấn giữa các phân vùng.
  await tx.$executeRawUnsafe('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', partition);

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
  const activeRedactor = input.redactor ?? sharedRedactor;
  const sanitizedDetails = activeRedactor.sanitizeDetails(input.details ?? {});
  const sanitizedReason = activeRedactor.sanitizeReason(input.reasonCode ?? null);
  const sanitizedUserAgent = activeRedactor.sanitizeUserAgent(input.context.userAgent ?? null);
  const sanitizedIp = activeRedactor.sanitizeIp(input.context.ip ?? null);
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

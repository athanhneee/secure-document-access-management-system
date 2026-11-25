/**
 * @module AuditVerifierBatchHelper
 * Thuật toán: Tái tính mã băm chuẩn tắc RFC 8785 HMAC-SHA256 cho từng dòng nhật ký kiểm toán,
 * kiểm tra liên kết mắt xích/khoảng trống số thứ tự và xác minh điểm neo hợp lệ gần nhất để nối tiếp kiểm chứng.
 */
import { createHmac } from 'node:crypto';
import { AppErrorCode, parseSignerKeyVersion } from '@sda/contracts';
import type { getDatabaseClient } from '@sda/database';
import { canonicalizeJson } from './audit-canonicalizer.js';
import { safeTimingEqualString } from './audit-chain-helper.js';
import type { AuditAnchorRow } from './audit-anchor-verifier.js';
import type { AuditViolation } from './audit-verifier.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface VerifiableAuditLogRow {
  id: bigint;
  action: string;
  actor_user_id: bigint | null;
  actor_username: string | null;
  chain_algorithm: string;
  chain_partition: string;
  chain_sequence: bigint;
  correlation_id: string;
  details: unknown;
  document_id: string | null;
  access_session_id: string | null;
  ip_address: string | null;
  object_type: string;
  object_id: string | null;
  occurred_at: Date;
  outcome: string;
  previous_hash: string | null;
  reason_code: string | null;
  user_agent: string | null;
  hmac_key_version: number;
  entry_hash: string;
}

/**
 * Thuật toán: Tái tạo chuỗi chuẩn tắc RFC 8785 (JCS) và tính mã băm `HMAC-SHA256` theo phiên bản khóa `hmac_key_version`.
 */
export function computeAuditLogHmac(
  log: VerifiableAuditLogRow,
  getHmacKey: (version: number) => string | Buffer,
): string {
  const hmacKey = getHmacKey(log.hmac_key_version);
  const canonicalString = canonicalizeJson({
    action: log.action,
    actorUserId: log.actor_user_id ? log.actor_user_id.toString() : null,
    actorUsername: log.actor_username,
    chainAlgorithm: log.chain_algorithm,
    chainPartition: log.chain_partition,
    chainSequence: log.chain_sequence.toString(),
    correlationId: log.correlation_id,
    details: log.details as Record<string, unknown>,
    documentId: log.document_id,
    accessSessionId: log.access_session_id,
    ipAddress: log.ip_address,
    objectType: log.object_type,
    objectId: log.object_id,
    occurredAt: log.occurred_at.toISOString(),
    outcome: log.outcome,
    previousHash: log.previous_hash,
    reasonCode: log.reason_code,
    userAgent: log.user_agent,
  });
  return createHmac('sha256', hmacKey).update(canonicalString, 'utf8').digest('hex');
}

/**
 * Thuật toán: Xác minh điểm neo `VALID` mới nhất của phân vùng (cả chữ ký điểm neo lẫn bản ghi nhật ký gốc được neo)
 * để cho phép nối tiếp kiểm chứng từ `anchor_sequence + 1` khi người gọi không chỉ định `fromSequence`.
 * Nếu chữ ký điểm neo hoặc mắt xích neo không khớp, tự động lùi về quét toàn phần từ `sequence = 1` để bắt lỗi đầy đủ.
 */
export async function resolveVerifiedAnchorCheckpoint(params: {
  database: PrismaClient;
  partition: string;
  preloadedAnchors: readonly AuditAnchorRow[];
  getHmacKey: (version: number) => string | Buffer;
  toSequence?: bigint | undefined;
}): Promise<{
  anchor: AuditAnchorRow;
  logId: bigint;
  entryHash: string;
} | null> {
  const { database, partition, preloadedAnchors, getHmacKey, toSequence } = params;
  if (typeof database.auditLog?.findFirst !== 'function') return null;

  const validCandidates = preloadedAnchors.filter(
    (a) =>
      (a.status === undefined || a.status === null || a.status === 'VALID') &&
      (toSequence === undefined || a.anchor_sequence <= toSequence),
  );
  const latest = validCandidates[validCandidates.length - 1];
  if (!latest) return null;

  // Thuật toán: Xác minh chữ ký toàn bộ điểm neo lịch sử (< latest) và đếm số bản ghi [1..K] trước khi cho phép nối tiếp.
  // Nếu có điểm neo lịch sử bị giả mạo hoặc thiếu bản ghi trước điểm neo, tự động lùi về quét toàn phần từ sequence = 1.
  for (const priorAnchor of preloadedAnchors) {
    if (priorAnchor.anchor_sequence > latest.anchor_sequence) continue;
    if (priorAnchor.status === 'INVALID') {
      return null;
    }
    const priorKey = getHmacKey(parseSignerKeyVersion(priorAnchor.signer_key_id));
    const expectedPriorSig = createHmac('sha256', priorKey)
      .update(
        `${priorAnchor.chain_partition}:${priorAnchor.anchor_sequence}:${priorAnchor.entry_hash}`,
      )
      .digest('hex');
    if (!safeTimingEqualString(priorAnchor.signature, expectedPriorSig)) {
      return null;
    }
  }

  if (typeof database.auditLog?.count === 'function') {
    const priorLogCount = await database.auditLog.count({
      where: {
        chain_partition: partition,
        chain_sequence: { lte: latest.anchor_sequence },
      },
    });
    if (BigInt(priorLogCount) !== latest.anchor_sequence) {
      return null;
    }
  }

  const anchoredLog = (await database.auditLog.findFirst({
    where: { chain_partition: partition, chain_sequence: latest.anchor_sequence },
  })) as VerifiableAuditLogRow | null;
  if (!anchoredLog || !safeTimingEqualString(anchoredLog.entry_hash, latest.entry_hash)) {
    return null;
  }

  const recomputed = computeAuditLogHmac(anchoredLog, getHmacKey);
  if (!safeTimingEqualString(recomputed, anchoredLog.entry_hash)) {
    return null;
  }

  return {
    anchor: latest,
    logId: anchoredLog.id,
    entryHash: anchoredLog.entry_hash,
  };
}

/**
 * Thuật toán: Kiểm chứng liên kết mắt xích (`previous_hash`), tính liên tục số thứ tự (`expectedSequence`)
 * và toàn vẹn chữ ký HMAC trên một dòng nhật ký trong lô duyệt con trỏ.
 */
export function verifyAuditLogRow(params: {
  log: VerifiableAuditLogRow;
  partition: string;
  expectedSequence: bigint;
  previousHash: string | null;
  resumedOrExplicitStart: boolean;
  getHmacKey: (version: number) => string | Buffer;
  violations: AuditViolation[];
}): void {
  const {
    log,
    partition,
    expectedSequence,
    previousHash,
    resumedOrExplicitStart,
    getHmacKey,
    violations,
  } = params;

  if (log.chain_sequence !== expectedSequence) {
    violations.push({
      code: AppErrorCode.AUDIT_SEQUENCE_GAP,
      partition,
      sequence: log.chain_sequence,
      logId: log.id,
      expected: expectedSequence.toString(),
      actual: log.chain_sequence.toString(),
      message: `Sequence gap detected in partition ${partition}: expected ${expectedSequence}, found ${log.chain_sequence}`,
    });
  }

  if (log.chain_sequence === 1n) {
    if (log.previous_hash !== null) {
      violations.push({
        code: AppErrorCode.AUDIT_CHAIN_BROKEN,
        partition,
        sequence: log.chain_sequence,
        logId: log.id,
        expected: 'null',
        actual: log.previous_hash,
        message: `First entry in partition ${partition} must have null previous_hash`,
      });
    }
  } else if (previousHash === null) {
    if (!resumedOrExplicitStart) {
      violations.push({
        code: AppErrorCode.AUDIT_CHAIN_BROKEN,
        partition,
        sequence: log.chain_sequence,
        logId: log.id,
        expected: 'GENESIS_SEQUENCE_1',
        actual: log.previous_hash ?? 'null',
        message: `Missing genesis head before sequence ${log.chain_sequence} in partition ${partition}`,
      });
    }
  } else if (!safeTimingEqualString(log.previous_hash, previousHash)) {
    violations.push({
      code: AppErrorCode.AUDIT_CHAIN_BROKEN,
      partition,
      sequence: log.chain_sequence,
      logId: log.id,
      expected: previousHash,
      actual: log.previous_hash ?? 'null',
      message: `Hash chain broken in partition ${partition} at sequence ${log.chain_sequence}`,
    });
  }

  const computedHash = computeAuditLogHmac(log, getHmacKey);
  if (!safeTimingEqualString(computedHash, log.entry_hash)) {
    // CONFLICT-RESOLVED: Tuyệt đối không trả về computedHash để triệt tiêu HMAC Signing Oracle (CRIT-02).
    violations.push({
      code: AppErrorCode.AUDIT_LOG_TAMPERED,
      partition,
      sequence: log.chain_sequence,
      logId: log.id,
      expected: '[REDACTED_HMAC]',
      actual: '[TAMPERED_ENTRY_HASH]',
      message: `HMAC verification failed for partition ${partition} at sequence ${log.chain_sequence}: data was tampered`,
    });
  }
}

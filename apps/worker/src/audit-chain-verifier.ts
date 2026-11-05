import { createHmac, timingSafeEqual } from 'node:crypto';
import { canonicalizeJson, parseSignerKeyVersion, type AuditKeyRing } from '@sda/contracts';

export { canonicalizeJson };

export interface AuditChainViolation {
  code: string;
  sequence: bigint;
  logId?: bigint;
  message: string;
}

export interface VerifiableAuditLogRow {
  id: bigint;
  occurred_at: Date;
  actor_user_id: bigint | null;
  actor_username: string | null;
  action: string;
  object_type: string;
  object_id: string | null;
  document_id: string | null;
  access_session_id: string | null;
  outcome: string;
  reason_code: string | null;
  ip_address: string | null;
  user_agent: string | null;
  correlation_id: string;
  details: unknown;
  previous_hash: string | null;
  entry_hash: string;
  chain_partition: string;
  chain_sequence: bigint;
  chain_algorithm: string;
  hmac_key_version?: number | null;
}

export interface VerifiableAuditAnchorRow {
  chain_partition: string;
  anchor_sequence: bigint;
  entry_hash: string;
  signature: string;
  signer_key_id?: string | null;
}

/**
 * Algorithm / Thuật toán: So sánh hai chuỗi mã băm/chữ ký trong thời gian hằng số (Constant-Time Comparison)
 * Mục đích: Chuyển hai chuỗi sang `Buffer` UTF-8 và gọi `crypto.timingSafeEqual` để ngăn chặn tấn công kênh kề thời gian.
 */
export function safeTimingEqual(
  left: string | null | undefined,
  right: string | null | undefined,
): boolean {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const bufLeft = Buffer.from(left, 'utf8');
  const bufRight = Buffer.from(right, 'utf8');
  if (bufLeft.byteLength !== bufRight.byteLength) return false;
  return timingSafeEqual(bufLeft, bufRight);
}

function resolveKeyFromSource(keySource: string | AuditKeyRing, version?: number | null): string {
  return typeof keySource === 'string' ? keySource : keySource.getKey(version);
}

/**
 * Algorithm / Thuật toán: Xác Thực Mắt Xích Chuỗi Băm Kiểm Toán Đơn Lẻ Hỗ Trợ Vòng Khóa Xoay Vòng (Single-Entry Hash Chain & Versioned HMAC-SHA256 Verifier)
 */
export function verifyAuditChainEntry(
  log: VerifiableAuditLogRow,
  partition: string,
  expectedSequence: bigint,
  previousHash: string | null,
  keySource: string | AuditKeyRing,
  violations: AuditChainViolation[],
): { nextExpectedSequence: bigint; nextPreviousHash: string } {
  if (log.chain_sequence !== expectedSequence) {
    violations.push({
      code: 'AUDIT_SEQUENCE_GAP',
      sequence: log.chain_sequence,
      logId: log.id,
      message: `Sequence gap in partition ${partition}: expected ${expectedSequence}, found ${log.chain_sequence}`,
    });
  }

  if (log.chain_sequence === 1n) {
    if (log.previous_hash !== null) {
      violations.push({
        code: 'AUDIT_CHAIN_BROKEN',
        sequence: log.chain_sequence,
        logId: log.id,
        message: `First entry in partition ${partition} must have null previous_hash`,
      });
    }
  } else if (previousHash !== null && !safeTimingEqual(log.previous_hash, previousHash)) {
    violations.push({
      code: 'AUDIT_CHAIN_BROKEN',
      sequence: log.chain_sequence,
      logId: log.id,
      message: `Hash link broken in partition ${partition} at sequence ${log.chain_sequence}`,
    });
  }

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

  const hmacKey = resolveKeyFromSource(keySource, log.hmac_key_version);
  const computedHash = createHmac('sha256', hmacKey).update(canonicalString, 'utf8').digest('hex');

  if (!safeTimingEqual(computedHash, log.entry_hash)) {
    violations.push({
      code: 'AUDIT_LOG_TAMPERED',
      sequence: log.chain_sequence,
      logId: log.id,
      message: `HMAC verification failed in partition ${partition} at sequence ${log.chain_sequence}`,
    });
  }

  return {
    nextExpectedSequence: log.chain_sequence + 1n,
    nextPreviousHash: log.entry_hash,
  };
}

/**
 * Algorithm / Thuật toán: Xác Thực Chéo Điểm Neo Độc Lập Theo Phiên Bản Khóa `signer_key_id` (Checkpoint Anchor Verification)
 */
export function verifyPartitionAnchors(
  anchors: readonly VerifiableAuditAnchorRow[],
  partition: string,
  logHashBySequence: ReadonlyMap<bigint, { id: bigint; entry_hash: string }>,
  keySource: string | AuditKeyRing,
  violations: AuditChainViolation[],
): void {
  for (const anchor of anchors) {
    const targetLog = logHashBySequence.get(anchor.anchor_sequence);
    if (!targetLog) {
      violations.push({
        code: 'AUDIT_ANCHOR_MISMATCH',
        sequence: anchor.anchor_sequence,
        message: `Anchor at sequence ${anchor.anchor_sequence} points to missing log in partition ${partition}`,
      });
      continue;
    }

    if (!safeTimingEqual(targetLog.entry_hash, anchor.entry_hash)) {
      violations.push({
        code: 'AUDIT_ANCHOR_MISMATCH',
        sequence: anchor.anchor_sequence,
        logId: targetLog.id,
        message: `Anchor entry_hash mismatch for partition ${partition} at sequence ${anchor.anchor_sequence}`,
      });
    }

    // CONFLICT-RESOLVED: Trích xuất phiên bản khóa từ signer_key_id qua parseSignerKeyVersion đồng bộ với AuditAnchorVerifier phía API.
    const anchorKey = resolveKeyFromSource(keySource, parseSignerKeyVersion(anchor.signer_key_id));
    const expectedSignature = createHmac('sha256', anchorKey)
      .update(`${anchor.chain_partition}:${anchor.anchor_sequence}:${anchor.entry_hash}`)
      .digest('hex');

    if (!safeTimingEqual(anchor.signature, expectedSignature)) {
      violations.push({
        code: 'AUDIT_ANCHOR_MISMATCH',
        sequence: anchor.anchor_sequence,
        logId: targetLog.id,
        message: `Anchor signature mismatch for partition ${partition} at sequence ${anchor.anchor_sequence}`,
      });
    }
  }
}

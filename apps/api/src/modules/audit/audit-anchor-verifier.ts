/**
 * @module AuditAnchorVerifier
 * Algorithm: Cryptographic Audit Checkpoint Anchor & HMAC Signature Verification.
 * Đối chiếu chéo điểm neo độc lập `audit_anchors` với chuỗi băm `audit_logs` chống tấn công cắt đuôi chuỗi.
 */
import { createHmac } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode, parseSignerKeyVersion } from '@sda/contracts';
import { safeTimingEqualString } from './audit-chain-helper.js';
import type { AuditViolation } from './audit-verifier.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface AuditAnchorRow {
  chain_partition: string;
  anchor_sequence: bigint;
  entry_hash: string;
  signature: string;
  signer_key_id?: string | null;
}

/**
 * Algorithm / Thuật toán: Tải trước danh sách điểm neo `audit_anchors` của phân vùng để chỉ giữ trong RAM các mắt xích cần đối chiếu ($O(|\text{anchors}|)$ thay vì $O(N)$).
 */
export async function fetchPartitionAnchors(
  database: PrismaClient,
  partition: string,
  options?: { fromSequence?: bigint; toSequence?: bigint },
): Promise<AuditAnchorRow[]> {
  const anchorWhere: {
    chain_partition: string;
    anchor_sequence?: { gte?: bigint; lte?: bigint };
  } = {
    chain_partition: partition,
  };
  if (options?.fromSequence !== undefined || options?.toSequence !== undefined) {
    anchorWhere.anchor_sequence = {};
    if (options.fromSequence !== undefined) {
      anchorWhere.anchor_sequence.gte = options.fromSequence;
    }
    if (options.toSequence !== undefined) {
      anchorWhere.anchor_sequence.lte = options.toSequence;
    }
  }

  return database.auditAnchor.findMany({
    where: anchorWhere,
    orderBy: {
      anchor_sequence: 'asc',
    },
  });
}

/**
 * Algorithm / Thuật toán: Đối chiếu điểm neo chữ ký HMAC độc lập (Checkpoint Anchor Cross-Verification).
 * Cơ chế hoạt động:
 *   1. Sử dụng danh sách `preloadedAnchors` (hoặc truy vấn `audit_anchors`) thuộc phân vùng và khoảng `sequence` kiểm tra.
 *   2. Xác minh bản ghi nhật ký tương ứng tồn tại trong `logHashBySequence` và khớp `entry_hash` theo thời gian hằng số.
 *   3. Tính lại chữ ký `HMAC-SHA256(key_vN, partition:sequence:entry_hash)` theo phiên bản `signer_key_id` để phát hiện giả mạo điểm neo.
 */
export async function verifyPartitionAnchors(
  database: PrismaClient,
  partition: string,
  logHashBySequence: ReadonlyMap<bigint, { id: bigint; entry_hash: string }>,
  getHmacKey: (version: number) => string | Buffer,
  options?: { fromSequence?: bigint; toSequence?: bigint },
  preloadedAnchors?: readonly AuditAnchorRow[],
): Promise<{ anchorsChecked: number; violations: AuditViolation[] }> {
  const violations: AuditViolation[] = [];
  const anchors = preloadedAnchors ?? (await fetchPartitionAnchors(database, partition, options));

  for (const anchor of anchors) {
    const targetLog = logHashBySequence.get(anchor.anchor_sequence);
    if (!targetLog) {
      violations.push({
        code: AppErrorCode.AUDIT_ANCHOR_MISMATCH,
        partition,
        sequence: anchor.anchor_sequence,
        expected: anchor.entry_hash,
        actual: 'LOG_RECORD_MISSING',
        message: `Anchor at sequence ${anchor.anchor_sequence} references non-existent log record`,
      });
      continue;
    }

    if (!safeTimingEqualString(targetLog.entry_hash, anchor.entry_hash)) {
      violations.push({
        code: AppErrorCode.AUDIT_ANCHOR_MISMATCH,
        partition,
        sequence: anchor.anchor_sequence,
        logId: targetLog.id,
        expected: anchor.entry_hash,
        actual: targetLog.entry_hash,
        message: `Anchor entry_hash mismatch at sequence ${anchor.anchor_sequence}`,
      });
    }

    // CONFLICT-RESOLVED: Xác minh chữ ký điểm neo audit_anchors theo đúng phiên bản khóa trích xuất từ signer_key_id thay vì gắn cứng phiên bản 1.
    const anchorKey = getHmacKey(parseSignerKeyVersion(anchor.signer_key_id));
    const expectedSignature = createHmac('sha256', anchorKey)
      .update(`${anchor.chain_partition}:${anchor.anchor_sequence}:${anchor.entry_hash}`)
      .digest('hex');

    if (!safeTimingEqualString(anchor.signature, expectedSignature)) {
      violations.push({
        code: AppErrorCode.AUDIT_ANCHOR_MISMATCH,
        partition,
        sequence: anchor.anchor_sequence,
        expected: expectedSignature,
        actual: anchor.signature,
        message: `Anchor signature verification failed for sequence ${anchor.anchor_sequence}`,
      });
    }
  }

  return { anchorsChecked: anchors.length, violations };
}

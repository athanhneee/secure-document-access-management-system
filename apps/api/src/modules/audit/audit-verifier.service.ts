/**
 * @module AuditVerifierService
 * Algorithm: Cursor-Batched RFC 8785 HMAC-SHA256 Hash-Chain & Checkpoint Anchor Verifier.
 */
import { createHmac } from 'node:crypto';
import { Injectable, Logger, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import { AuditWriterService } from './audit-writer.service.js';
import { canonicalizeJson } from './audit-canonicalizer.js';
import { safeTimingEqualString } from './audit-chain-helper.js';
import { fetchPartitionAnchors, verifyPartitionAnchors } from './audit-anchor-verifier.js';
import { raiseAuditIntegrityAlert } from './audit-alert-escalator.js';

export interface AuditViolation {
  code: string;
  partition: string;
  sequence: bigint;
  logId?: bigint;
  expected?: string;
  actual?: string;
  message: string;
}

export interface PartitionVerificationResult {
  partition: string;
  valid: boolean;
  totalChecked: number;
  anchorsChecked: number;
  violations: AuditViolation[];
  alertId?: string | undefined;
}

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class AuditVerifierService {
  private readonly logger = new Logger(AuditVerifierService.name);
  private readonly database: PrismaClient;

  constructor(
    private readonly writerService: AuditWriterService,
    @Optional() databaseClient?: PrismaClient,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Algorithm / Thuật toán: Thẩm định toàn vẹn chuỗi băm phân lô con trỏ & đối chiếu điểm neo chữ ký (Cursor-Batched Hash-Chain & Anchor Verification).
   * Cơ chế hoạt động:
   *   1. Duyệt tuần tự theo lô 1.000 bản ghi bằng con trỏ `chain_sequence > cursorSequence` (bộ nhớ lô cố định).
   *   2. Kiểm tra tính liên tục số thứ tự (`AUDIT_SEQUENCE_GAP`) và liên kết mắt xích `previous_hash === prior.entry_hash` (`AUDIT_CHAIN_BROKEN`).
   *   3. Tái tạo JSON chuẩn tắc RFC 8785 theo `hmac_key_version`, tính lại `HMAC-SHA256` phát hiện sửa đổi (`AUDIT_LOG_TAMPERED`).
   *   4. Đối chiếu chéo với bảng điểm neo `audit_anchors` và phát cảnh báo `CRITICAL` nếu phát hiện vi phạm.
   */
  async verifyPartition(
    partition: string,
    options?: { fromSequence?: bigint; toSequence?: bigint },
  ): Promise<PartitionVerificationResult> {
    const violations: AuditViolation[] = [];
    const VERIFY_BATCH_SIZE = 1000;
    // Pre-fetch checkpoint anchors first so we retain ONLY anchored sequences in RAM (O(|anchors|) instead of O(N_logs) OOM).
    const preloadedAnchors = await fetchPartitionAnchors(this.database, partition, options);
    const anchorSequences = new Set<bigint>(preloadedAnchors.map((a) => a.anchor_sequence));
    const logHashBySequence = new Map<bigint, { id: bigint; entry_hash: string }>();
    let totalChecked = 0;

    let previousHash: string | null = null;
    // CONFLICT-RESOLVED: Khởi tạo expectedSequence = 1n mặc định thay vì null để chặn tấn công cắt cụt đầu chuỗi (Head-Truncation 1..K).
    let expectedSequence: bigint =
      options?.fromSequence !== undefined && options.fromSequence >= 1n ? options.fromSequence : 1n;

    if (options?.fromSequence && options.fromSequence > 1n) {
      const priorSequence = options.fromSequence - 1n;
      const priorLog = await this.database.auditLog.findFirst({
        where: {
          chain_partition: partition,
          chain_sequence: priorSequence,
        },
      });
      if (priorLog) {
        previousHash = priorLog.entry_hash;
      } else {
        violations.push({
          code: AppErrorCode.AUDIT_CHAIN_BROKEN,
          partition,
          sequence: options.fromSequence,
          expected: `sequence:${priorSequence.toString()}`,
          actual: 'PRIOR_LOG_MISSING',
          message: `Prior link at sequence ${priorSequence} is missing in partition ${partition}`,
        });
      }
    }

    let cursorSequence: bigint | undefined =
      options?.fromSequence !== undefined && options.fromSequence >= 1n
        ? options.fromSequence - 1n
        : undefined;

    while (true) {
      const batchWhere: {
        chain_partition: string;
        chain_sequence?: { gt?: bigint; gte?: bigint; lte?: bigint };
      } = { chain_partition: partition };
      if (cursorSequence !== undefined || options?.toSequence !== undefined) {
        batchWhere.chain_sequence = {};
        if (cursorSequence !== undefined) batchWhere.chain_sequence.gt = cursorSequence;
        if (options?.toSequence !== undefined) batchWhere.chain_sequence.lte = options.toSequence;
      }

      const logs = await this.database.auditLog.findMany({
        where: batchWhere,
        orderBy: { chain_sequence: 'asc' },
        take: VERIFY_BATCH_SIZE,
      });

      if (logs.length === 0) break;

      for (const log of logs) {
        totalChecked += 1;
        if (anchorSequences.has(log.chain_sequence)) {
          logHashBySequence.set(log.chain_sequence, { id: log.id, entry_hash: log.entry_hash });
        }

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
          if (!options?.fromSequence || options.fromSequence <= 1n) {
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

        const hmacKey = this.writerService.getHmacKey(log.hmac_key_version);
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
        const computedHash = createHmac('sha256', hmacKey)
          .update(canonicalString, 'utf8')
          .digest('hex');

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

        previousHash = log.entry_hash;
        expectedSequence = log.chain_sequence + 1n;
        cursorSequence = log.chain_sequence;
      }

      if (logs.length < VERIFY_BATCH_SIZE) break;
    }

    const anchorCheck = await verifyPartitionAnchors(
      this.database,
      partition,
      logHashBySequence,
      (v) => this.writerService.getHmacKey(v),
      options,
      preloadedAnchors,
    );
    violations.push(...anchorCheck.violations);

    const alertId =
      violations.length > 0
        ? await raiseAuditIntegrityAlert(this.database, this.logger, partition, violations)
        : undefined;

    return {
      partition,
      valid: violations.length === 0,
      totalChecked,
      anchorsChecked: anchorCheck.anchorsChecked,
      violations,
      alertId,
    };
  }

  /**
   * Algorithm / Thuật toán: Quét kiểm chứng tuần tự hợp nhất danh sách phân vùng từ cả `audit_logs` và `audit_anchors`
   * nhằm phát hiện cả kịch bản xóa trắng toàn bộ nhật ký của một phân vùng đã có điểm neo.
   */
  async verifyAllPartitions(): Promise<Record<string, PartitionVerificationResult>> {
    const distinctLogPartitions = await this.database.auditLog.findMany({
      select: { chain_partition: true },
      distinct: ['chain_partition'],
    });
    const distinctAnchorPartitions =
      typeof this.database.auditAnchor?.findMany === 'function'
        ? await this.database.auditAnchor.findMany({
            select: { chain_partition: true },
            distinct: ['chain_partition'],
          })
        : [];

    const partitionNames = new Set<string>();
    for (const p of distinctLogPartitions) partitionNames.add(p.chain_partition);
    for (const a of distinctAnchorPartitions) {
      if (a?.chain_partition) partitionNames.add(a.chain_partition);
    }

    const results: Record<string, PartitionVerificationResult> = {};
    for (const partition of partitionNames) {
      results[partition] = await this.verifyPartition(partition);
    }
    return results;
  }
}

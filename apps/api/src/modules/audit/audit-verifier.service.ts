/**
 * @module AuditVerifierService
 * Thuật toán: Thẩm định toàn vẹn chuỗi băm RFC 8785 HMAC-SHA256 theo lô con trỏ có giới hạn (`take: 1000`),
 * tự động nối tiếp từ điểm neo `AuditAnchor` hợp lệ gần nhất khi không truyền `fromSequence` và nhường vòng lặp
 * sự kiện (`setImmediate`) giữa các lô để không bao giờ làm nghẽn luồng HTTP.
 */
import { Injectable, Logger, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import { AuditWriterService } from './audit-writer.service.js';
import { fetchPartitionAnchors, verifyPartitionAnchors } from './audit-anchor-verifier.js';
import { raiseAuditIntegrityAlert } from './audit-alert-escalator.js';
import {
  resolveVerifiedAnchorCheckpoint,
  verifyAuditLogRow,
  type VerifiableAuditLogRow,
} from './audit-verifier-batch.helper.js';

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
   * Thuật toán: Thẩm định chuỗi băm phân lô con trỏ (`take: 1000`) kết hợp nối tiếp từ điểm neo `VALID` mới nhất
   * và nhường vòng lặp sự kiện `setImmediate` giữa các lô.
   */
  async verifyPartition(
    partition: string,
    options?: { fromSequence?: bigint; toSequence?: bigint },
  ): Promise<PartitionVerificationResult> {
    const violations: AuditViolation[] = [];
    const VERIFY_BATCH_SIZE = 1000;
    const getKey = (version: number) => this.writerService.getHmacKey(version);
    const preloadedAnchors = await fetchPartitionAnchors(this.database, partition, options);
    const logHashBySequence = new Map<bigint, { id: bigint; entry_hash: string }>();
    let totalChecked = 0;

    let previousHash: string | null = null;
    // CONFLICT-RESOLVED: Khởi tạo expectedSequence = 1n mặc định thay vì null để chặn tấn công cắt cụt đầu chuỗi (Head-Truncation 1..K).
    let expectedSequence: bigint =
      options?.fromSequence !== undefined && options.fromSequence >= 1n ? options.fromSequence : 1n;
    let cursorSequence: bigint | undefined =
      options?.fromSequence !== undefined && options.fromSequence >= 1n
        ? options.fromSequence - 1n
        : undefined;
    let anchorsToVerify = preloadedAnchors;
    let resumedFromCheckpoint = false;

    if (options?.fromSequence === undefined && preloadedAnchors.length > 0) {
      const checkpoint = await resolveVerifiedAnchorCheckpoint({
        database: this.database,
        partition,
        preloadedAnchors,
        getHmacKey: getKey,
        toSequence: options?.toSequence,
      });
      if (checkpoint) {
        resumedFromCheckpoint = true;
        totalChecked = Number(checkpoint.anchor.anchor_sequence);
        previousHash = checkpoint.entryHash;
        expectedSequence = checkpoint.anchor.anchor_sequence + 1n;
        cursorSequence = checkpoint.anchor.anchor_sequence;
        logHashBySequence.set(checkpoint.anchor.anchor_sequence, {
          id: checkpoint.logId,
          entry_hash: checkpoint.entryHash,
        });
        anchorsToVerify = preloadedAnchors.filter(
          (a) => a.anchor_sequence >= checkpoint.anchor.anchor_sequence,
        );
      }
    } else if (options?.fromSequence && options.fromSequence > 1n) {
      const priorSequence = options.fromSequence - 1n;
      const priorLog = await this.database.auditLog.findFirst({
        where: { chain_partition: partition, chain_sequence: priorSequence },
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

    const anchorSequences = new Set<bigint>(anchorsToVerify.map((a) => a.anchor_sequence));
    const resumedOrExplicitStart =
      resumedFromCheckpoint || Boolean(options?.fromSequence && options.fromSequence > 1n);

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

      const logs = (await this.database.auditLog.findMany({
        where: batchWhere,
        orderBy: { chain_sequence: 'asc' },
        take: VERIFY_BATCH_SIZE,
      })) as VerifiableAuditLogRow[];

      if (logs.length === 0) break;

      for (const log of logs) {
        totalChecked += 1;
        if (anchorSequences.has(log.chain_sequence)) {
          logHashBySequence.set(log.chain_sequence, { id: log.id, entry_hash: log.entry_hash });
        }
        verifyAuditLogRow({
          log,
          partition,
          expectedSequence,
          previousHash,
          resumedOrExplicitStart,
          getHmacKey: getKey,
          violations,
        });
        previousHash = log.entry_hash;
        expectedSequence = log.chain_sequence + 1n;
        cursorSequence = log.chain_sequence;
      }

      if (logs.length < VERIFY_BATCH_SIZE) break;
      await new Promise<void>((resolve) => setImmediate(resolve));
    }

    const anchorCheck = await verifyPartitionAnchors(
      this.database,
      partition,
      logHashBySequence,
      getKey,
      options,
      anchorsToVerify,
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
   * Thuật toán: Quét kiểm chứng tuần tự hợp nhất danh sách phân vùng từ cả `audit_logs` và `audit_anchors`.
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

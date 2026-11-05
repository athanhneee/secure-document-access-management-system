import { getDatabaseClient } from '@sda/database';
import { buildAuditKeyRing } from '@sda/contracts';
import { randomUUID } from 'node:crypto';
import {
  verifyAuditChainEntry,
  verifyPartitionAnchors,
  type AuditChainViolation,
} from './audit-chain-verifier.js';

export interface VerificationSweepSummary {
  partitionsChecked: number;
  totalLogsChecked: number;
  totalViolations: number;
  alertsCreated: number;
}

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface AuditSweepOptions {
  keyRotationJson?: string | undefined;
  databaseClient?: PrismaClient | undefined;
}

/**
 * Algorithm / Thuật toán: Đối soát chuỗi băm kiểm toán đa phân vùng với bộ nhớ hằng số theo số điểm neo ($O(|\text{anchors}|)$).
 * - Pha 1: Tải trước các điểm neo `audit_anchors` của phân vùng vào tập `anchorSequences` để KHÔNG giữ toàn bộ `audit_logs` trong RAM (triệt tiêu lỗi OOM $O(N)$).
 * - Pha 2: Quét từng lô 1.000 dòng theo con trỏ `chain_sequence > cursorSequence`, kiểm tra chuỗi băm với vòng khóa xoay vòng `AuditKeyRing` và chỉ lưu `entry_hash` tại đúng các mốc thuộc `anchorSequences`.
 * - Pha 3: Đối chiếu điểm neo qua `verifyPartitionAnchors` và phát cảnh báo `AUDIT_INTEGRITY_COMPROMISED` mức `CRITICAL` khử trùng lặp.
 */
export async function runAuditVerificationSweep(
  integrityKey: string,
  optionsOrRotationJson?: AuditSweepOptions | string,
): Promise<VerificationSweepSummary> {
  const options: AuditSweepOptions =
    typeof optionsOrRotationJson === 'string'
      ? { keyRotationJson: optionsOrRotationJson }
      : (optionsOrRotationJson ?? {});

  const database = options.databaseClient ?? getDatabaseClient();
  const keyRing = buildAuditKeyRing(integrityKey, options.keyRotationJson, (err) => {
    console.warn(`[AUDIT_VERIFICATION_JOB] Invalid AUDIT_KEY_ROTATION_JSON: ${String(err)}`);
  });

  const summary: VerificationSweepSummary = {
    partitionsChecked: 0,
    totalLogsChecked: 0,
    totalViolations: 0,
    alertsCreated: 0,
  };

  const partitions = await database.auditLog.findMany({
    select: { chain_partition: true },
    distinct: ['chain_partition'],
  });

  const VERIFY_BATCH_SIZE = 1000;

  for (const { chain_partition: partition } of partitions) {
    summary.partitionsChecked++;

    const violations: AuditChainViolation[] = [];
    // Pre-fetch anchors first so logHashBySequence only stores anchored sequence numbers (O(|anchors|) memory).
    const anchors = await database.auditAnchor.findMany({
      where: { chain_partition: partition },
      orderBy: { anchor_sequence: 'asc' },
    });
    const anchorSequences = new Set<bigint>(anchors.map((a) => a.anchor_sequence));
    const logHashBySequence = new Map<bigint, { id: bigint; entry_hash: string }>();

    let previousHash: string | null = null;
    let expectedSequence: bigint = 1n;
    let cursorSequence: bigint | undefined = undefined;

    while (true) {
      const batchWhere: {
        chain_partition: string;
        chain_sequence?: { gt: bigint };
      } = { chain_partition: partition };
      if (cursorSequence !== undefined) {
        batchWhere.chain_sequence = { gt: cursorSequence };
      }

      const logs = await database.auditLog.findMany({
        where: batchWhere,
        orderBy: { chain_sequence: 'asc' },
        take: VERIFY_BATCH_SIZE,
      });

      if (logs.length === 0) break;

      for (const log of logs) {
        summary.totalLogsChecked++;
        if (anchorSequences.has(log.chain_sequence)) {
          logHashBySequence.set(log.chain_sequence, { id: log.id, entry_hash: log.entry_hash });
        }

        const step = verifyAuditChainEntry(
          log,
          partition,
          expectedSequence,
          previousHash,
          keyRing,
          violations,
        );
        previousHash = step.nextPreviousHash;
        expectedSequence = step.nextExpectedSequence;
        cursorSequence = log.chain_sequence;
      }

      if (logs.length < VERIFY_BATCH_SIZE) break;
    }

    verifyPartitionAnchors(anchors, partition, logHashBySequence, keyRing, violations);

    summary.totalViolations += violations.length;

    if (violations.length > 0) {
      const alertId = randomUUID();
      const primary = violations[0]!;
      console.error(
        `[AUDIT_VERIFICATION_JOB] CRITICAL: ${violations.length} violations in partition ${partition}!`,
      );

      let createdNewAlert = false;
      await database.$transaction(async (tx) => {
        const existingOpen = await tx.securityAlert.findFirst({
          where: {
            alert_type: 'AUDIT_INTEGRITY_COMPROMISED',
            status: 'OPEN',
            title: { contains: `partition ${partition} ` },
          },
          select: { id: true },
        });
        if (existingOpen) return;

        await tx.securityAlert.create({
          data: {
            id: alertId,
            alert_type: 'AUDIT_INTEGRITY_COMPROMISED',
            severity: 'CRITICAL',
            status: 'OPEN',
            title: `CRITICAL: Audit integrity compromised in partition ${partition} (${primary.code})`,
            description: JSON.stringify({
              partition,
              violationCount: violations.length,
              violations: violations.slice(0, 10).map((v) => ({
                code: v.code,
                sequence: v.sequence.toString(),
                logId: v.logId?.toString(),
                message: v.message,
              })),
              detectedAt: new Date().toISOString(),
            }),
          },
        });
        createdNewAlert = true;

        if (primary.logId) {
          await tx.alertAuditLink.create({
            data: { alert_id: alertId, audit_log_id: primary.logId },
          });
        }
      });

      if (createdNewAlert) {
        summary.alertsCreated++;
      }
    }
  }

  return summary;
}

/**
 * Algorithm / Thuật toán: Bộ lập lịch định kỳ chống chồng lấn chu kỳ (Non-Overlapping Interval Scheduler)
 * sử dụng khóa cờ `isRunning` và hủy sạch bộ đếm khi nhận tín hiệu `AbortSignal`.
 */
export function startAuditVerificationJob(
  intervalMs: number,
  integrityKey: string,
  signal: AbortSignal,
  keyRotationJson?: string,
): void {
  if (signal.aborted) return;

  let isRunning = false;
  const run = async (): Promise<void> => {
    if (isRunning || signal.aborted) return;
    isRunning = true;
    try {
      const summary = await runAuditVerificationSweep(integrityKey, { keyRotationJson });
      if (summary.totalViolations > 0) {
        console.warn(
          `[AUDIT_VERIFICATION_JOB] Completed sweep with ${summary.totalViolations} violations across ${summary.partitionsChecked} partitions. Created ${summary.alertsCreated} critical alerts.`,
        );
      }
    } catch (err: unknown) {
      console.error(`[AUDIT_VERIFICATION_JOB] Error during audit sweep:`, err);
    } finally {
      isRunning = false;
    }
  };

  const timer = setInterval(() => {
    if (signal.aborted) {
      clearInterval(timer);
      return;
    }
    void run();
  }, intervalMs);

  signal.addEventListener('abort', () => clearInterval(timer), { once: true });
  console.info(`Audit verification worker started (interval: ${intervalMs}ms).`);
}

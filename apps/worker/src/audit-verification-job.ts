import { getDatabaseClient } from '@sda/database';
import { buildAuditKeyRing } from '@sda/contracts';
import { randomUUID } from 'node:crypto';
import {
  isAnchorCryptographicallyAuthentic,
  safeTimingEqual,
  verifyAuditChainEntry,
  verifyPartitionAnchors,
  type AuditChainViolation,
  type VerifiableAuditAnchorRow,
} from './audit-chain-verifier.js';
import { incrementAuditIntegrityCompromised, recordWorkerJobRun } from './worker-metrics.js';

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
 * Thuật toán: Ghi nhận cảnh báo `CRITICAL` khử trùng lặp vào `security_alerts` khi phát hiện chuỗi băm bị can thiệp.
 */
async function persistPartitionIntegrityAlert(
  database: PrismaClient,
  partition: string,
  violations: readonly AuditChainViolation[],
): Promise<boolean> {
  const alertId = randomUUID();
  const primary = violations[0]!;
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
      await tx.alertAuditLink.create({ data: { alert_id: alertId, audit_log_id: primary.logId } });
    }
  });
  return createdNewAlert;
}

/**
 * Thuật toán: Đối soát chuỗi băm kiểm toán nối tiếp từ điểm neo `VALID` gần nhất theo lô `1.000` dòng và tăng `sda_audit_integrity_compromised_total` khi vi phạm.
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

  const logPartitions = await database.auditLog.findMany({
    select: { chain_partition: true },
    distinct: ['chain_partition'],
  });
  const anchorPartitions =
    typeof database.auditAnchor?.findMany === 'function'
      ? await database.auditAnchor.findMany({
          select: { chain_partition: true },
          distinct: ['chain_partition'],
        })
      : [];
  const partitionSet = new Set<string>(logPartitions.map((r) => r.chain_partition));
  for (const row of anchorPartitions)
    if (row?.chain_partition) partitionSet.add(row.chain_partition);

  const VERIFY_BATCH_SIZE = 1000;
  for (const partition of partitionSet) {
    summary.partitionsChecked++;
    const violations: AuditChainViolation[] = [];
    const anchors = (await database.auditAnchor.findMany({
      where: { chain_partition: partition },
      orderBy: { anchor_sequence: 'asc' },
    })) as VerifiableAuditAnchorRow[];

    let resumeAnchor: VerifiableAuditAnchorRow | undefined;
    for (let idx = anchors.length - 1; idx >= 0; idx--) {
      const candidate = anchors[idx]!;
      if (candidate.status === 'VALID') {
        if (isAnchorCryptographicallyAuthentic(candidate, keyRing)) resumeAnchor = candidate;
        else {
          violations.push({
            code: 'AUDIT_ANCHOR_MISMATCH',
            sequence: candidate.anchor_sequence,
            message: `VALID anchor signature mismatch for partition ${partition} at sequence ${candidate.anchor_sequence}`,
          });
        }
        break;
      }
    }

    if (resumeAnchor && typeof database.auditLog.findFirst === 'function') {
      const anchoredRow = await database.auditLog.findFirst({
        where: { chain_partition: partition, chain_sequence: resumeAnchor.anchor_sequence },
        select: { id: true, entry_hash: true },
      });
      if (!anchoredRow || !safeTimingEqual(anchoredRow.entry_hash, resumeAnchor.entry_hash)) {
        violations.push({
          code: 'AUDIT_ANCHOR_MISMATCH',
          sequence: resumeAnchor.anchor_sequence,
          ...(anchoredRow?.id !== undefined ? { logId: anchoredRow.id } : {}),
          message: `Anchored log missing or modified at sequence ${resumeAnchor.anchor_sequence} in partition ${partition}`,
        });
        resumeAnchor = undefined;
      }
    }

    const unverifiedAnchors = resumeAnchor
      ? anchors.filter((a) => a.anchor_sequence > resumeAnchor.anchor_sequence)
      : anchors;
    const anchorSequences = new Set<bigint>(unverifiedAnchors.map((a) => a.anchor_sequence));
    const logHashBySequence = new Map<bigint, { id: bigint; entry_hash: string }>();
    let previousHash: string | null = resumeAnchor ? resumeAnchor.entry_hash : null;
    let expectedSequence: bigint = resumeAnchor ? resumeAnchor.anchor_sequence + 1n : 1n;
    let cursorSequence: bigint | undefined = resumeAnchor?.anchor_sequence;

    while (true) {
      const where =
        cursorSequence !== undefined
          ? { chain_partition: partition, chain_sequence: { gt: cursorSequence } }
          : { chain_partition: partition };
      const logs = await database.auditLog.findMany({
        where,
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

    verifyPartitionAnchors(unverifiedAnchors, partition, logHashBySequence, keyRing, violations);
    summary.totalViolations += violations.length;
    if (violations.length > 0) {
      incrementAuditIntegrityCompromised(partition, violations.length);
      console.error(
        `[AUDIT_VERIFICATION_JOB] CRITICAL: ${violations.length} violations in partition ${partition}!`,
      );
      if (await persistPartitionIntegrityAlert(database, partition, violations))
        summary.alertsCreated++;
    }
  }

  return summary;
}

/**
 * Thuật toán: Bộ lập lịch định kỳ chống chồng lấn chu kỳ (Non-Overlapping Interval Scheduler) cho `AuditVerificationJob`.
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
      recordWorkerJobRun('audit_verification', 'success');
      if (summary.totalViolations > 0) {
        console.warn(
          `[AUDIT_VERIFICATION_JOB] Completed sweep with ${summary.totalViolations} violations across ${summary.partitionsChecked} partitions. Created ${summary.alertsCreated} critical alerts.`,
        );
      }
    } catch (err: unknown) {
      recordWorkerJobRun('audit_verification', 'error');
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

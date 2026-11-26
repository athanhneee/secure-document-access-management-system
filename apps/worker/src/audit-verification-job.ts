import { getDatabaseClient } from '@sda/database';
import { buildAuditKeyRing } from '@sda/contracts';
import { randomUUID } from 'node:crypto';
import {
  computeAuditEntryHash,
  isAnchorCryptographicallyAuthentic,
  safeTimingEqual,
  verifyAuditChainEntry,
  verifyPartitionAnchors,
  type AuditChainViolation,
  type VerifiableAuditAnchorRow,
  type VerifiableAuditLogRow,
} from './audit-chain-verifier.js';
import { incrementAuditIntegrityCompromised, recordWorkerJobRun } from './worker-metrics.js';
import { publishWorkerRealtimeEvent } from './realtime-redis-publisher.js';

export interface VerificationSweepSummary {
  partitionsChecked: number;
  totalLogsChecked: number;
  totalLogsSkippedByAnchor: number;
  fullScan: boolean;
  totalViolations: number;
  alertsCreated: number;
}

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface AuditSweepOptions {
  keyRotationJson?: string | undefined;
  databaseClient?: PrismaClient | undefined;
  fullScan?: boolean | undefined;
}

/**
 * Thuật toán: Khử trùng lặp danh sách vi phạm chuỗi kiểm toán theo khóa `(code, sequence)` khi lùi từ điểm neo checkpoint về quét toàn phần (`fullScan` fallback),
 * ưu tiên giữ bản ghi có `logId` để liên kết chính xác `alert_audit_links` (BUG-111).
 */
export function deduplicateAuditViolations(
  violations: readonly AuditChainViolation[],
): AuditChainViolation[] {
  const byKey = new Map<string, AuditChainViolation>();
  for (const violation of violations) {
    const key = `${violation.code}:${violation.sequence.toString()}`;
    const existing = byKey.get(key);
    if (!existing || (existing.logId === undefined && violation.logId !== undefined)) {
      byKey.set(key, violation);
    }
  }
  return [...byKey.values()];
}

/**
 * Thuật toán: Ghi nhận cảnh báo `CRITICAL` khử trùng lặp vào `security_alerts` khi phát hiện chuỗi băm bị can thiệp và đẩy sự kiện SSE thời gian thực qua Redis.
 */
async function persistPartitionIntegrityAlert(
  database: PrismaClient,
  partition: string,
  violations: readonly AuditChainViolation[],
): Promise<boolean> {
  const alertId = randomUUID();
  const primary = violations[0]!;
  let createdNewAlert = false;
  let persistedSeverity = 'CRITICAL';

  await database.$transaction(async (tx) => {
    // CONFLICT-RESOLVED: Đọc severity và cooldown_minutes của Quy tắc #6 AUDIT_INTEGRITY_COMPROMISED từ detection_rule_configs (N04).
    const ruleCfg =
      typeof tx.detectionRuleConfig?.findUnique === 'function'
        ? await tx.detectionRuleConfig
            .findUnique({ where: { rule_code: 'AUDIT_INTEGRITY_COMPROMISED' } })
            .catch(() => null)
        : null;
    const effectiveSeverity = ruleCfg?.severity ?? 'CRITICAL';
    persistedSeverity = effectiveSeverity;
    const cooldownMinutes = ruleCfg?.cooldown_minutes ?? 15;
    const cooldownStart = new Date(Date.now() - cooldownMinutes * 60_000);

    const existingOpen = await tx.securityAlert.findFirst({
      where: {
        alert_type: 'AUDIT_INTEGRITY_COMPROMISED',
        status: { in: ['OPEN', 'INVESTIGATING'] },
        title: { contains: `partition ${partition} ` },
        detected_at: { gte: cooldownStart },
      },
      select: { id: true },
    });
    if (existingOpen) return;

    await tx.securityAlert.create({
      data: {
        id: alertId,
        alert_type: 'AUDIT_INTEGRITY_COMPROMISED',
        severity: effectiveSeverity,
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

  if (createdNewAlert) {
    await publishWorkerRealtimeEvent({
      type: 'SECURITY_ALERT_UPDATED',
      targetRoles: ['SECURITY_OFFICER', 'AUDITOR'],
      payload: {
        id: alertId,
        alertId,
        alertType: 'AUDIT_INTEGRITY_COMPROMISED',
        severity: persistedSeverity,
        partition,
        violationCount: violations.length,
        status: 'OPEN',
        action: 'CREATED',
      },
    });
  }

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
  const fullScan = options.fullScan === true;
  const summary: VerificationSweepSummary = {
    partitionsChecked: 0,
    totalLogsChecked: 0,
    totalLogsSkippedByAnchor: 0,
    fullScan,
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
    if (!fullScan) {
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
    }

    if (resumeAnchor && typeof database.auditLog.findFirst === 'function') {
      // Thuật toán: Trước khi nối tiếp từ điểm neo K, xác minh toàn bộ điểm neo trước K, đếm số bản ghi [1..K]
      // và tái tính HMAC của chính bản ghi được neo để chống giả mạo hoặc xóa bản ghi trước điểm neo.
      const hasTamperedPriorAnchor = anchors.some(
        (a) =>
          a.anchor_sequence < resumeAnchor!.anchor_sequence &&
          (a.status === 'INVALID' || !isAnchorCryptographicallyAuthentic(a, keyRing)),
      );
      if (hasTamperedPriorAnchor) {
        resumeAnchor = undefined;
      }
    }

    if (resumeAnchor && typeof database.auditLog?.count === 'function') {
      const priorLogCount = await database.auditLog.count({
        where: {
          chain_partition: partition,
          chain_sequence: { lte: resumeAnchor.anchor_sequence },
        },
      });
      if (BigInt(priorLogCount) !== resumeAnchor.anchor_sequence) {
        resumeAnchor = undefined;
      }
    }

    if (resumeAnchor && typeof database.auditLog.findFirst === 'function') {
      const anchoredRow = (await database.auditLog.findFirst({
        where: { chain_partition: partition, chain_sequence: resumeAnchor.anchor_sequence },
      })) as Partial<VerifiableAuditLogRow> | null;
      const hashMatches =
        Boolean(anchoredRow?.entry_hash) &&
        safeTimingEqual(anchoredRow?.entry_hash, resumeAnchor.entry_hash);
      const hasFullRowFields = Boolean(
        anchoredRow &&
        typeof anchoredRow.action === 'string' &&
        anchoredRow.occurred_at instanceof Date &&
        typeof anchoredRow.chain_algorithm === 'string',
      );
      const hmacAuthentic =
        hashMatches &&
        (!hasFullRowFields ||
          safeTimingEqual(
            computeAuditEntryHash(anchoredRow as VerifiableAuditLogRow, keyRing),
            anchoredRow!.entry_hash,
          ));
      if (!anchoredRow || !hmacAuthentic) {
        violations.push({
          code: !hashMatches ? 'AUDIT_ANCHOR_MISMATCH' : 'AUDIT_LOG_TAMPERED',
          sequence: resumeAnchor.anchor_sequence,
          ...(anchoredRow?.id !== undefined ? { logId: anchoredRow.id } : {}),
          message: !hashMatches
            ? `Anchored log missing or modified at sequence ${resumeAnchor.anchor_sequence} in partition ${partition}`
            : `Anchored log HMAC verification failed at sequence ${resumeAnchor.anchor_sequence} in partition ${partition}`,
        });
        resumeAnchor = undefined;
      } else if (hasFullRowFields) {
        // Chỉ đếm đúng 1 bản ghi điểm neo K đã được tái tính HMAC thực tế; ghi nhận riêng số bản ghi [1..K-1] bỏ qua.
        summary.totalLogsChecked++;
        summary.totalLogsSkippedByAnchor += Number(resumeAnchor.anchor_sequence - 1n);
      } else {
        summary.totalLogsSkippedByAnchor += Number(resumeAnchor.anchor_sequence);
      }
    } else if (resumeAnchor) {
      // Nếu client DB không hỗ trợ findFirst để kiểm chứng bản ghi neo, bắt buộc lùi về quét toàn phần từ sequence = 1.
      resumeAnchor = undefined;
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
    const uniqueViolations = deduplicateAuditViolations(violations);
    summary.totalViolations += uniqueViolations.length;
    if (uniqueViolations.length > 0) {
      incrementAuditIntegrityCompromised(partition, uniqueViolations.length);
      console.error(
        `[AUDIT_VERIFICATION_JOB] CRITICAL: ${uniqueViolations.length} violations in partition ${partition}!`,
      );
      if (await persistPartitionIntegrityAlert(database, partition, uniqueViolations))
        summary.alertsCreated++;
    }
  }

  return summary;
}

/**
 * Thuật toán: Bộ lập lịch định kỳ chống chồng lấn chu kỳ (Non-Overlapping Interval Scheduler) cho `AuditVerificationJob`.
 * Tự động chạy chế độ kiểm chứng toàn chuỗi từ `sequence = 1` (`fullScan: true`) theo chu kỳ định kỳ (`fullScanEveryNSweeps`, mặc định 12 chu kỳ và ngay chu kỳ đầu tiên).
 */
export function startAuditVerificationJob(
  intervalMs: number,
  integrityKey: string,
  signal: AbortSignal,
  keyRotationJson?: string,
  options?: { fullScanEveryNSweeps?: number | undefined },
): void {
  if (signal.aborted) return;

  const fullScanEvery = Math.max(1, Math.floor(options?.fullScanEveryNSweeps ?? 12));
  let sweepCount = 0;
  let isRunning = false;
  const run = async (): Promise<void> => {
    if (isRunning || signal.aborted) return;
    isRunning = true;
    try {
      sweepCount += 1;
      const fullScan = fullScanEvery <= 1 || (sweepCount - 1) % fullScanEvery === 0;
      const summary = await runAuditVerificationSweep(integrityKey, {
        keyRotationJson,
        fullScan,
      });
      recordWorkerJobRun('audit_verification', 'success');
      if (summary.totalViolations > 0) {
        console.warn(
          `[AUDIT_VERIFICATION_JOB] Completed ${fullScan ? 'FULL' : 'INCREMENTAL'} sweep with ${summary.totalViolations} violations across ${summary.partitionsChecked} partitions. Created ${summary.alertsCreated} critical alerts.`,
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
  console.info(
    `Audit verification worker started (interval: ${intervalMs}ms, fullScanEvery: ${fullScanEvery} sweeps).`,
  );
}

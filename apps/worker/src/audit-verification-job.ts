import { getDatabaseClient } from '@sda/database';
import { createHmac, randomUUID } from 'node:crypto';

/**
 * RFC 8785 Canonical JSON Serialization for worker integrity checking.
 */
function canonicalizeJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return 'null';
    return JSON.stringify(value);
  }
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (typeof value === 'string') return JSON.stringify(value);
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) {
    const serialized = value.map((el) => {
      if (typeof el === 'undefined' || typeof el === 'symbol' || typeof el === 'function') {
        return 'null';
      }
      return canonicalizeJson(el);
    });
    return `[${serialized.join(',')}]`;
  }
  if (typeof value === 'object') {
    if (typeof (value as { toJSON?: () => unknown }).toJSON === 'function') {
      return canonicalizeJson((value as { toJSON: () => unknown }).toJSON());
    }
    const obj = value as Record<string, unknown>;
    const sortedKeys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const key of sortedKeys) {
      const val = obj[key];
      if (typeof val === 'undefined' || typeof val === 'symbol' || typeof val === 'function') {
        continue;
      }
      parts.push(`${JSON.stringify(key)}:${canonicalizeJson(val)}`);
    }
    return `{${parts.join(',')}}`;
  }
  return 'null';
}

export interface VerificationSweepSummary {
  partitionsChecked: number;
  totalLogsChecked: number;
  totalViolations: number;
  alertsCreated: number;
}

/**
 * Sweeps all audit partitions to verify hash chain continuity, HMAC signatures,
 * sequence gaps, and anchor checkpoints. Creates CRITICAL alerts on any mismatch.
 */
export async function runAuditVerificationSweep(
  integrityKey: string,
): Promise<VerificationSweepSummary> {
  const database = getDatabaseClient();
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

  for (const { chain_partition: partition } of partitions) {
    summary.partitionsChecked++;

    const logs = await database.auditLog.findMany({
      where: { chain_partition: partition },
      orderBy: { chain_sequence: 'asc' },
    });

    const violations: Array<{
      code: string;
      sequence: bigint;
      logId?: bigint;
      message: string;
    }> = [];

    let previousHash: string | null = null;
    let expectedSequence: bigint = 1n;

    for (let i = 0; i < logs.length; i++) {
      const log = logs[i]!;
      summary.totalLogsChecked++;

      // 1. Sequence gap check
      if (log.chain_sequence !== expectedSequence) {
        violations.push({
          code: 'AUDIT_SEQUENCE_GAP',
          sequence: log.chain_sequence,
          logId: log.id,
          message: `Sequence gap in partition ${partition}: expected ${expectedSequence}, found ${log.chain_sequence}`,
        });
        expectedSequence = log.chain_sequence;
      }

      // 2. Hash chain continuity check
      if (log.chain_sequence === 1n) {
        if (log.previous_hash !== null) {
          violations.push({
            code: 'AUDIT_CHAIN_BROKEN',
            sequence: log.chain_sequence,
            logId: log.id,
            message: `First entry in partition ${partition} must have null previous_hash`,
          });
        }
      } else if (previousHash !== null && log.previous_hash !== previousHash) {
        violations.push({
          code: 'AUDIT_CHAIN_BROKEN',
          sequence: log.chain_sequence,
          logId: log.id,
          message: `Hash link broken in partition ${partition} at sequence ${log.chain_sequence}`,
        });
      }

      // 3. HMAC-SHA-256 data integrity check
      const canonicalPayload = {
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
      };

      const canonicalString = canonicalizeJson(canonicalPayload);
      const computedHash = createHmac('sha256', integrityKey)
        .update(canonicalString, 'utf8')
        .digest('hex');

      if (computedHash !== log.entry_hash) {
        violations.push({
          code: 'AUDIT_LOG_TAMPERED',
          sequence: log.chain_sequence,
          logId: log.id,
          message: `HMAC verification failed in partition ${partition} at sequence ${log.chain_sequence}`,
        });
      }

      previousHash = log.entry_hash;
      expectedSequence = log.chain_sequence + 1n;
    }

    // 4. Verify against audit_anchors
    const anchors = await database.auditAnchor.findMany({
      where: { chain_partition: partition },
      orderBy: { anchor_sequence: 'asc' },
    });

    for (const anchor of anchors) {
      const targetLog = logs.find((l) => l.chain_sequence === anchor.anchor_sequence);
      if (!targetLog) {
        violations.push({
          code: 'AUDIT_ANCHOR_MISMATCH',
          sequence: anchor.anchor_sequence,
          message: `Anchor at sequence ${anchor.anchor_sequence} points to missing log in partition ${partition}`,
        });
        continue;
      }

      if (targetLog.entry_hash !== anchor.entry_hash) {
        violations.push({
          code: 'AUDIT_ANCHOR_MISMATCH',
          sequence: anchor.anchor_sequence,
          logId: targetLog.id,
          message: `Anchor entry_hash mismatch for partition ${partition} at sequence ${anchor.anchor_sequence}`,
        });
      }
    }

    summary.totalViolations += violations.length;

    // 5. Raise CRITICAL SecurityAlert on any violation
    if (violations.length > 0) {
      const alertId = randomUUID();
      const primary = violations[0]!;

      console.error(
        `[AUDIT_VERIFICATION_JOB] CRITICAL: ${violations.length} violations in partition ${partition}!`,
      );

      await database.$transaction(async (tx) => {
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
              violations: violations.slice(0, 10),
              detectedAt: new Date().toISOString(),
            }),
          },
        });

        if (primary.logId) {
          await tx.alertAuditLink.create({
            data: {
              alert_id: alertId,
              audit_log_id: primary.logId,
            },
          });
        }
      });

      summary.alertsCreated++;
    }
  }

  return summary;
}

/**
 * Starts the background audit verification job loop.
 */
export function startAuditVerificationJob(
  intervalMs: number,
  integrityKey: string,
  signal: AbortSignal,
): void {
  if (signal.aborted) return;

  const run = async (): Promise<void> => {
    try {
      const summary = await runAuditVerificationSweep(integrityKey);
      if (summary.totalViolations > 0) {
        console.warn(
          `[AUDIT_VERIFICATION_JOB] Completed sweep with ${summary.totalViolations} violations across ${summary.partitionsChecked} partitions. Created ${summary.alertsCreated} critical alerts.`,
        );
      }
    } catch (err: unknown) {
      console.error(`[AUDIT_VERIFICATION_JOB] Error during audit sweep:`, err);
    }
  };

  const timer = setInterval(() => {
    if (signal.aborted) {
      clearInterval(timer);
      return;
    }
    void run();
  }, intervalMs);

  signal.addEventListener(
    'abort',
    () => {
      clearInterval(timer);
    },
    { once: true },
  );

  console.info(`Audit verification worker started (interval: ${intervalMs}ms).`);
}

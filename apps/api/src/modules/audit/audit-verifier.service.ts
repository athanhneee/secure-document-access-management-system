import { createHmac, randomUUID } from 'node:crypto';
import { Injectable, Logger, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import { AuditWriterService } from './audit-writer.service.js';
import { canonicalizeJson } from './audit-canonicalizer.js';

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
   * Verifies the cryptographic integrity of an entire partition or range.
   */
  async verifyPartition(
    partition: string,
    options?: { fromSequence?: bigint; toSequence?: bigint },
  ): Promise<PartitionVerificationResult> {
    const violations: AuditViolation[] = [];

    // Query audit logs in ascending sequence order
    const where: {
      chain_partition: string;
      chain_sequence?: { gte?: bigint; lte?: bigint };
    } = {
      chain_partition: partition,
    };
    if (options?.fromSequence !== undefined || options?.toSequence !== undefined) {
      where.chain_sequence = {};
      if (options.fromSequence !== undefined) where.chain_sequence.gte = options.fromSequence;
      if (options.toSequence !== undefined) where.chain_sequence.lte = options.toSequence;
    }

    const logs = await this.database.auditLog.findMany({
      where,
      orderBy: {
        chain_sequence: 'asc',
      },
    });

    let previousHash: string | null = null;
    let expectedSequence: bigint | null = options?.fromSequence ?? null;

    // If starting from a specific sequence > 1, fetch prior entry for hash continuity
    if (options?.fromSequence && options.fromSequence > 1n) {
      const priorLog = await this.database.auditLog.findFirst({
        where: {
          chain_partition: partition,
          chain_sequence: options.fromSequence - 1n,
        },
      });
      if (priorLog) {
        previousHash = priorLog.entry_hash;
      }
    }

    for (let i = 0; i < logs.length; i++) {
      const log = logs[i]!;

      // 1. Check sequence gap
      if (expectedSequence === null) {
        expectedSequence = log.chain_sequence;
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
        expectedSequence = log.chain_sequence;
      }

      // 2. Check previous hash continuity
      if (log.chain_sequence === 1n && !options?.fromSequence) {
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
      } else if (previousHash !== null && log.previous_hash !== previousHash) {
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

      // 3. Recalculate HMAC-SHA-256 over canonicalized payload
      const hmacKey = this.writerService.getHmacKey(log.hmac_key_version);
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
      const computedHash = createHmac('sha256', hmacKey)
        .update(canonicalString, 'utf8')
        .digest('hex');

      if (computedHash !== log.entry_hash) {
        violations.push({
          code: AppErrorCode.AUDIT_LOG_TAMPERED,
          partition,
          sequence: log.chain_sequence,
          logId: log.id,
          expected: computedHash,
          actual: log.entry_hash,
          message: `HMAC verification failed for partition ${partition} at sequence ${log.chain_sequence}: data was tampered`,
        });
      }

      previousHash = log.entry_hash;
      expectedSequence = log.chain_sequence + 1n;
    }

    // 4. Verify against audit_anchors
    const anchorWhere: {
      chain_partition: string;
      anchor_sequence?: { gte?: bigint; lte?: bigint };
    } = {
      chain_partition: partition,
    };
    if (options?.fromSequence !== undefined || options?.toSequence !== undefined) {
      anchorWhere.anchor_sequence = {};
      if (options.fromSequence !== undefined)
        anchorWhere.anchor_sequence.gte = options.fromSequence;
      if (options.toSequence !== undefined) anchorWhere.anchor_sequence.lte = options.toSequence;
    }

    const anchors = await this.database.auditAnchor.findMany({
      where: anchorWhere,
      orderBy: {
        anchor_sequence: 'asc',
      },
    });

    for (const anchor of anchors) {
      // Find matching log
      const targetLog = logs.find((l) => l.chain_sequence === anchor.anchor_sequence);
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

      if (targetLog.entry_hash !== anchor.entry_hash) {
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

      // Verify anchor signature
      const anchorKey = this.writerService.getHmacKey(1);
      const expectedSignature = createHmac('sha256', anchorKey)
        .update(`${anchor.chain_partition}:${anchor.anchor_sequence}:${anchor.entry_hash}`)
        .digest('hex');

      if (anchor.signature !== expectedSignature) {
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

    let alertId: string | undefined;

    // 5. If violations found: create a CRITICAL SecurityAlert
    if (violations.length > 0) {
      alertId = await this.raiseCriticalAlert(partition, violations);
    }

    return {
      partition,
      valid: violations.length === 0,
      totalChecked: logs.length,
      anchorsChecked: anchors.length,
      violations,
      alertId,
    };
  }

  /**
   * Verifies all active partitions in the database.
   */
  async verifyAllPartitions(): Promise<Record<string, PartitionVerificationResult>> {
    // Distinct partitions in audit_logs
    const distinctPartitions = await this.database.auditLog.findMany({
      select: {
        chain_partition: true,
      },
      distinct: ['chain_partition'],
    });

    const results: Record<string, PartitionVerificationResult> = {};
    for (const p of distinctPartitions) {
      results[p.chain_partition] = await this.verifyPartition(p.chain_partition);
    }

    return results;
  }

  private async raiseCriticalAlert(
    partition: string,
    violations: AuditViolation[],
  ): Promise<string> {
    const alertId = randomUUID();
    const primaryViolation = violations[0]!;

    this.logger.error(
      `CRITICAL SECURITY ALERT: Audit trail integrity compromised in partition ${partition}! Total violations: ${violations.length}`,
    );

    try {
      const { MetricsService } = await import('../system-health/metrics.service.js');
      MetricsService.getInstance().recordAuditVerifyFailure(partition);
      MetricsService.getInstance().recordSecurityAlert('CRITICAL', 'audit_integrity');
    } catch {
      // Fallback
    }

    await this.database.$transaction(async (tx) => {
      await tx.securityAlert.create({
        data: {
          id: alertId,
          alert_type: 'AUDIT_INTEGRITY_COMPROMISED',
          severity: 'CRITICAL',
          status: 'OPEN',
          title: `CRITICAL: Audit integrity compromised in partition ${partition} (${primaryViolation.code})`,
          description: JSON.stringify({
            partition,
            violations: violations.slice(0, 10).map((v) => ({
              code: v.code,
              partition: v.partition,
              sequence: v.sequence.toString(),
              logId: v.logId?.toString(),
              expected: v.expected,
              actual: v.actual,
              message: v.message,
            })),
            detectedAt: new Date().toISOString(),
          }),
        },
      });

      // Link alert to the first affected audit log if available
      if (primaryViolation.logId) {
        await tx.alertAuditLink.create({
          data: {
            alert_id: alertId,
            audit_log_id: primaryViolation.logId,
          },
        });
      }
    });

    return alertId;
  }
}

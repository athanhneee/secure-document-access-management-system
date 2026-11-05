/**
 * @module AuditAlertEscalator
 * Algorithm: Idempotent Partition-Scoped Critical Security Alert Escalation.
 * Phát cảnh báo an ninh khẩn cấp `CRITICAL` khử trùng lặp theo phân vùng khi phát hiện xâm phạm chuỗi kiểm toán.
 */
import { randomUUID } from 'node:crypto';
import type { Logger } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import type { AuditViolation } from './audit-verifier.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm / Thuật toán: Leo thang cảnh báo an ninh khẩn cấp khử trùng lặp (Deduplicated Critical Alert Escalation).
 * Cơ chế hoạt động:
 *   1. Ghi nhận chỉ số lỗi kiểm chứng vào Prometheus (`MetricsService`) nếu khả dụng.
 *   2. Trong một giao dịch cơ sở dữ liệu, kiểm tra cảnh báo `OPEN` hiện hữu của cùng phân vùng để tránh bão cảnh báo.
 *   3. Nếu chưa có, khởi tạo `SecurityAlert` mức `CRITICAL` (kèm tối đa 10 vi phạm đầu tiên) và liên kết `AlertAuditLink`.
 */
export async function raiseAuditIntegrityAlert(
  database: PrismaClient,
  logger: Logger,
  partition: string,
  violations: AuditViolation[],
): Promise<string> {
  const alertId = randomUUID();
  const primaryViolation = violations[0]!;

  logger.error(
    `CRITICAL SECURITY ALERT: Audit trail integrity compromised in partition ${partition}! Total violations: ${violations.length}`,
  );

  try {
    const { MetricsService } = await import('../system-health/metrics.service.js');
    MetricsService.getInstance().recordAuditVerifyFailure(partition);
    MetricsService.getInstance().recordSecurityAlert('CRITICAL', 'audit_integrity');
  } catch {
    // Metrics service optional in isolated unit tests
  }

  let resolvedAlertId: string = alertId;
  await database.$transaction(async (tx) => {
    if (typeof tx.securityAlert?.findFirst === 'function') {
      const existingOpen = await tx.securityAlert.findFirst({
        where: {
          alert_type: 'AUDIT_INTEGRITY_COMPROMISED',
          status: 'OPEN',
          title: { contains: `partition ${partition} ` },
        },
        select: { id: true },
      });
      if (existingOpen) {
        resolvedAlertId = existingOpen.id;
        return;
      }
    }

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

    if (primaryViolation.logId) {
      await tx.alertAuditLink.create({
        data: {
          alert_id: alertId,
          audit_log_id: primaryViolation.logId,
        },
      });
    }
  });

  return resolvedAlertId;
}

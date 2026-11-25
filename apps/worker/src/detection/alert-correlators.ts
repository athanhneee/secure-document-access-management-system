import { groupAuditLogsByActor } from '@sda/contracts';
import { type Prisma, type alert_status } from '@sda/database';
import { randomUUID } from 'node:crypto';
import type { DetectionRuleConfig, PrismaClient } from './rule-defaults.js';

export interface MinimalAuditLog {
  id: bigint;
  actor_user_id: bigint | null;
  document_id?: string | null | undefined;
  occurred_at: Date;
}

async function linkNewEvidenceToExistingAlert(
  database: PrismaClient,
  alertId: string,
  logs: readonly MinimalAuditLog[],
): Promise<void> {
  if (logs.length === 0 || typeof database.alertAuditLink?.createMany !== 'function') return;
  await database.alertAuditLink.createMany({
    data: logs.map((l) => ({ alert_id: alertId, audit_log_id: l.id })),
    skipDuplicates: true,
  });
}

/**
 * Algorithm / Thuật toán: Gom Nhóm Tần Suất Theo Chủ Thể & Luồng Ẩn Danh Kèm Giảm Chấn Cooldown Độc Lập Đồng Bộ API
 * (Per-User & Unattributed Sliding-Window Correlation with Active-Status Cooldown & Incremental Evidence Linking — N09)
 */
export async function emitPerUserThresholdAlerts(
  database: PrismaClient,
  rule: DetectionRuleConfig,
  logs: MinimalAuditLog[],
  now: Date,
  cooldownStart: Date,
  formatAlert: (count: number, actorUserId: bigint) => { title: string; description: string },
  formatAnonymousAlert?: (count: number) => { title: string; description: string },
): Promise<number> {
  // CONFLICT-RESOLVED: Đồng bộ chặt với API — chỉ suppress cooldown trên cảnh báo còn OPEN/INVESTIGATING, luôn gắn thêm alert_audit_links và lưu document_id (N09).
  const userGroups = groupAuditLogsByActor(logs);
  let created = 0;

  for (const [userIdStr, userLogs] of userGroups.entries()) {
    if (userLogs.length < rule.threshold) continue;
    const actorUserId = BigInt(userIdStr);
    const existingAlert = await database.securityAlert.findFirst({
      where: {
        alert_type: rule.ruleCode,
        detected_user_id: actorUserId,
        status: { in: ['OPEN', 'INVESTIGATING'] },
        detected_at: { gte: cooldownStart },
      },
      orderBy: { detected_at: 'desc' },
    });
    if (existingAlert) {
      await linkNewEvidenceToExistingAlert(database, existingAlert.id, userLogs);
      continue;
    }

    const alertId = randomUUID();
    const { title, description } = formatAlert(userLogs.length, actorUserId);
    const primaryDocumentId = userLogs.find((l) => Boolean(l.document_id))?.document_id ?? null;
    await database.$transaction(async (tx: Prisma.TransactionClient) => {
      await tx.securityAlert.create({
        data: {
          id: alertId,
          alert_type: rule.ruleCode,
          severity: rule.severity,
          status: 'OPEN' as alert_status,
          title,
          description,
          detected_user_id: actorUserId,
          document_id: primaryDocumentId,
          detected_at: now,
        },
      });
      await tx.alertAuditLink.createMany({
        data: userLogs.map((l) => ({ alert_id: alertId, audit_log_id: l.id })),
        skipDuplicates: true,
      });
    });
    created++;
  }

  if (formatAnonymousAlert) {
    const unattributedLogs = logs.filter((l) => l.actor_user_id == null);
    if (unattributedLogs.length >= rule.threshold) {
      const existingAnonymousAlert = await database.securityAlert.findFirst({
        where: {
          alert_type: rule.ruleCode,
          detected_user_id: null,
          status: { in: ['OPEN', 'INVESTIGATING'] },
          detected_at: { gte: cooldownStart },
        },
        orderBy: { detected_at: 'desc' },
      });
      if (existingAnonymousAlert) {
        await linkNewEvidenceToExistingAlert(database, existingAnonymousAlert.id, unattributedLogs);
      } else {
        const alertId = randomUUID();
        const { title, description } = formatAnonymousAlert(unattributedLogs.length);
        await database.$transaction(async (tx: Prisma.TransactionClient) => {
          await tx.securityAlert.create({
            data: {
              id: alertId,
              alert_type: rule.ruleCode,
              severity: rule.severity,
              status: 'OPEN' as alert_status,
              title,
              description,
              detected_user_id: null,
              detected_at: now,
            },
          });
          await tx.alertAuditLink.createMany({
            data: unattributedLogs.map((l) => ({ alert_id: alertId, audit_log_id: l.id })),
            skipDuplicates: true,
          });
        });
        created++;
      }
    }
  }

  return created;
}

/**
 * Algorithm / Thuật toán: Tương Quan Sự Kiện Cấp Hệ Thống Có Giảm Chấn Cooldown (`detected_user_id: null`)
 * Mục đích: Phát cảnh báo nghiêm trọng phạm vi toàn hệ thống (như `AUDIT_INTEGRITY_COMPROMISED`) khi đạt ngưỡng mà chưa có cảnh báo `OPEN`/`INVESTIGATING` trong khoảng `cooldownStart`.
 */
export async function emitAggregateThresholdAlert(
  database: PrismaClient,
  rule: DetectionRuleConfig,
  logs: MinimalAuditLog[],
  now: Date,
  cooldownStart: Date,
  title: string,
  description: string,
): Promise<number> {
  if (logs.length < rule.threshold) return 0;

  const existingAlert = await database.securityAlert.findFirst({
    where: {
      alert_type: rule.ruleCode,
      detected_user_id: null,
      status: { in: ['OPEN', 'INVESTIGATING'] },
      detected_at: { gte: cooldownStart },
    },
    orderBy: { detected_at: 'desc' },
  });
  if (existingAlert) {
    await linkNewEvidenceToExistingAlert(database, existingAlert.id, logs);
    return 0;
  }

  const alertId = randomUUID();
  await database.$transaction(async (tx: Prisma.TransactionClient) => {
    await tx.securityAlert.create({
      data: {
        id: alertId,
        alert_type: rule.ruleCode,
        severity: rule.severity,
        status: 'OPEN' as alert_status,
        title,
        description,
        detected_user_id: null,
        detected_at: now,
      },
    });
    await tx.alertAuditLink.createMany({
      data: logs.map((l) => ({ alert_id: alertId, audit_log_id: l.id })),
      skipDuplicates: true,
    });
  });
  return 1;
}

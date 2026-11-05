import { groupAuditLogsByActor } from '@sda/contracts';
import { type Prisma, type alert_status } from '@sda/database';
import { randomUUID } from 'node:crypto';
import type { DetectionRuleConfig, PrismaClient } from './rule-defaults.js';

export interface MinimalAuditLog {
  id: bigint;
  actor_user_id: bigint | null;
  occurred_at: Date;
}

/**
 * Algorithm / Thuật toán: Gom Nhóm Tần Suất Theo Chủ Thể & Luồng Ẩn Danh Kèm Giảm Chấn Cooldown Độc Lập
 * (Per-User & Unattributed Sliding-Window Correlation with Isolated Cooldown Suppression)
 * Mục đích: Phân hoạch danh sách sự kiện kiểm toán theo `actor_user_id` bằng `groupAuditLogsByActor` trong `O(N)`
 *   (và tách riêng nhóm `actor_user_id == null` khi có `formatAnonymousAlert`) để cooldown của một người dùng
 *   không bao giờ che khuất cảnh báo xâm nhập trên người dùng khác hoặc luồng ẩn danh.
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
  // CONFLICT-RESOLVED: Đánh giá ngưỡng và giảm chấn cooldown độc lập cho từng actor_user_id (cùng nhánh ẩn danh detected_user_id: null) tránh triệt tiêu chéo cảnh báo giữa các tài khoản bị xâm nhập.
  const userGroups = groupAuditLogsByActor(logs);
  let created = 0;

  for (const [userIdStr, userLogs] of userGroups.entries()) {
    if (userLogs.length < rule.threshold) continue;
    const actorUserId = BigInt(userIdStr);
    const existingAlert = await database.securityAlert.findFirst({
      where: {
        alert_type: rule.ruleCode,
        detected_user_id: actorUserId,
        detected_at: { gte: cooldownStart },
      },
    });
    if (existingAlert) continue;

    const alertId = randomUUID();
    const { title, description } = formatAlert(userLogs.length, actorUserId);
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
          detected_at: { gte: cooldownStart },
        },
      });
      if (!existingAnonymousAlert) {
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
 * Mục đích: Phát cảnh báo nghiêm trọng phạm vi toàn hệ thống (như `AUDIT_INTEGRITY_COMPROMISED`) khi đạt ngưỡng mà chưa có cảnh báo trong khoảng `cooldownStart`.
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
      detected_at: { gte: cooldownStart },
    },
  });
  if (existingAlert) return 0;

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

import { type Prisma, type alert_status } from '@sda/database';
import { randomUUID } from 'node:crypto';
import type { DetectionRuleConfig, PrismaClient } from './rule-defaults.js';

export interface MinimalAuditLog {
  id: bigint;
  actor_user_id: bigint | null;
  occurred_at: Date;
}

/**
 * Algorithm / Thuật toán: Gom Nhóm Tần Suất Theo Chủ Thể & Giảm Chấn Cảnh Báo Cửa Sổ Trượt (Per-User Sliding-Window Correlation & Cooldown Suppression)
 * Mục đích: Phân hoạch danh sách sự kiện kiểm toán theo `actor_user_id` trong `O(N)`, kiểm tra ngưỡng `threshold` và triệt tiêu cảnh báo lặp trong cửa sổ `cooldownStart` trước khi tạo nguyên tử `security_alerts` + `alert_audit_links`.
 */
export async function emitPerUserThresholdAlerts(
  database: PrismaClient,
  rule: DetectionRuleConfig,
  logs: MinimalAuditLog[],
  now: Date,
  cooldownStart: Date,
  formatAlert: (count: number) => { title: string; description: string },
): Promise<number> {
  const userGroups = new Map<string, MinimalAuditLog[]>();
  for (const log of logs) {
    if (!log.actor_user_id) continue;
    const key = log.actor_user_id.toString();
    const list = userGroups.get(key) ?? [];
    list.push(log);
    userGroups.set(key, list);
  }

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
    const { title, description } = formatAlert(userLogs.length);
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
  return created;
}

/**
 * Algorithm / Thuật toán: Tương Quan Sự Kiện Toàn Cục Có Giảm Chấn Cooldown (Aggregate Event Correlation & Suppression)
 * Mục đích: Phát cảnh báo nghiêm trọng cho các sự kiện hệ thống/phiên (`UNTRUSTED_CONTEXT`, `REFRESH_TOKEN_REUSE`, `AUDIT_INTEGRITY_COMPROMISED`) khi đạt ngưỡng mà chưa có cảnh báo trong khoảng `cooldownStart`.
 */
export async function emitAggregateThresholdAlert(
  database: PrismaClient,
  rule: DetectionRuleConfig,
  logs: MinimalAuditLog[],
  now: Date,
  cooldownStart: Date,
  includeFirstActor: boolean,
  title: string,
  description: string,
): Promise<number> {
  if (logs.length < rule.threshold) return 0;
  const detectedUserId = includeFirstActor ? (logs[0]?.actor_user_id ?? null) : null;

  const existingAlert = await database.securityAlert.findFirst({
    where: {
      alert_type: rule.ruleCode,
      ...(includeFirstActor && detectedUserId ? { detected_user_id: detectedUserId } : {}),
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
        detected_user_id: detectedUserId,
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

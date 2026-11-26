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
  tx: Prisma.TransactionClient | PrismaClient,
  alertId: string,
  logs: readonly MinimalAuditLog[],
): Promise<void> {
  if (logs.length === 0 || typeof tx.alertAuditLink?.createMany !== 'function') return;
  await tx.alertAuditLink.createMany({
    data: logs.map((l) => ({ alert_id: alertId, audit_log_id: l.id })),
    skipDuplicates: true,
  });
}

/**
 * Thuật toán: Tạo cảnh báo hoặc giảm chấn Cooldown nguyên tử trong giao dịch có khóa tư vấn `pg_advisory_xact_lock` (`BUG-069`).
 * Ngăn hai tiến trình (API và Worker hoặc đa pod Worker) cùng đọc `findFirst === null` rồi chèn đúp hai cảnh báo `OPEN` trùng nhau.
 */
async function createOrLinkAlertAtomically(
  database: PrismaClient,
  params: {
    rule: DetectionRuleConfig;
    actorUserId: bigint | null;
    primaryDocumentId: string | null;
    logs: readonly MinimalAuditLog[];
    now: Date;
    cooldownStart: Date;
    title: string;
    description: string;
  },
): Promise<boolean> {
  const { rule, actorUserId, primaryDocumentId, logs, now, cooldownStart, title, description } =
    params;
  const lockSubjectKey = actorUserId !== null ? actorUserId.toString() : 'GLOBAL_SYSTEM';

  const runInScope = async (tx: Prisma.TransactionClient | PrismaClient): Promise<boolean> => {
    if (typeof tx.$executeRawUnsafe === 'function') {
      await tx.$executeRawUnsafe(
        'SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))',
        `soc-alert:${rule.ruleCode}`,
        lockSubjectKey,
      );
    }

    const findAlertClient =
      typeof tx.securityAlert?.findFirst === 'function' ? tx.securityAlert : database.securityAlert;
    const createAlertClient =
      typeof tx.securityAlert?.create === 'function' ? tx.securityAlert : database.securityAlert;
    const linkClient = typeof tx.alertAuditLink?.createMany === 'function' ? tx : database;

    const existingAlert = await findAlertClient.findFirst({
      where: {
        alert_type: rule.ruleCode,
        detected_user_id: actorUserId,
        status: { in: ['OPEN', 'INVESTIGATING'] },
        detected_at: { gte: cooldownStart },
      },
      orderBy: { detected_at: 'desc' },
    });
    if (existingAlert) {
      await linkNewEvidenceToExistingAlert(linkClient, existingAlert.id, logs);
      return false;
    }

    const alertId = randomUUID();
    await createAlertClient.create({
      data: {
        id: alertId,
        alert_type: rule.ruleCode,
        severity: rule.severity,
        status: 'OPEN' as alert_status,
        title,
        description,
        detected_user_id: actorUserId,
        ...(primaryDocumentId !== null ? { document_id: primaryDocumentId } : {}),
        detected_at: now,
      },
    });
    if (logs.length > 0 && typeof linkClient.alertAuditLink?.createMany === 'function') {
      await linkClient.alertAuditLink.createMany({
        data: logs.map((l) => ({ alert_id: alertId, audit_log_id: l.id })),
        skipDuplicates: true,
      });
    }
    return true;
  };

  if (typeof database.$transaction === 'function') {
    return database.$transaction((tx: Prisma.TransactionClient) => runInScope(tx));
  }
  return runInScope(database);
}

/**
 * Algorithm / Thuật toán: Gom Nhóm Tần Suất Theo Chủ Thể & Luồng Ẩn Danh Kèm Giảm Chấn Cooldown Nguyên Tử Đồng Bộ API
 * (Per-User & Unattributed Sliding-Window Correlation with Advisory-Locked Cooldown & Incremental Evidence Linking — BUG-069 / N09)
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
  // CONFLICT-RESOLVED: Bọc kiểm tra cooldown findFirst + create + link vào cùng $transaction dưới pg_advisory_xact_lock chống tạo đúp cảnh báo giữa API và Worker (BUG-069 / N09).
  const userGroups = groupAuditLogsByActor(logs);
  let created = 0;

  for (const [userIdStr, userLogs] of userGroups.entries()) {
    if (userLogs.length < rule.threshold) continue;
    const actorUserId = BigInt(userIdStr);
    const { title, description } = formatAlert(userLogs.length, actorUserId);
    const primaryDocumentId = userLogs.find((l) => Boolean(l.document_id))?.document_id ?? null;
    const wasCreated = await createOrLinkAlertAtomically(database, {
      rule,
      actorUserId,
      primaryDocumentId,
      logs: userLogs,
      now,
      cooldownStart,
      title,
      description,
    });
    if (wasCreated) {
      created++;
    }
  }

  if (formatAnonymousAlert) {
    const unattributedLogs = logs.filter((l) => l.actor_user_id == null);
    if (unattributedLogs.length >= rule.threshold) {
      const { title, description } = formatAnonymousAlert(unattributedLogs.length);
      const wasCreated = await createOrLinkAlertAtomically(database, {
        rule,
        actorUserId: null,
        primaryDocumentId: null,
        logs: unattributedLogs,
        now,
        cooldownStart,
        title,
        description,
      });
      if (wasCreated) {
        created++;
      }
    }
  }

  return created;
}

/**
 * Algorithm / Thuật toán: Tương Quan Sự Kiện Cấp Hệ Thống Có Giảm Chấn Cooldown Nguyên Tử (`detected_user_id: null` — `BUG-069`)
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

  const wasCreated = await createOrLinkAlertAtomically(database, {
    rule,
    actorUserId: null,
    primaryDocumentId: null,
    logs,
    now,
    cooldownStart,
    title,
    description,
  });
  return wasCreated ? 1 : 0;
}

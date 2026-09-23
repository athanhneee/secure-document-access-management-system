import {
  getDatabaseClient,
  type Prisma,
  type alert_status,
  type severity_level,
} from '@sda/database';
import { randomUUID } from 'node:crypto';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface DetectionRuleConfig {
  ruleCode: string;
  name: string;
  isEnabled: boolean;
  severity: severity_level;
  threshold: number;
  windowMinutes: number;
  cooldownMinutes: number;
  parameters: Record<string, unknown>;
}

const DEFAULT_DETECTION_RULES: DetectionRuleConfig[] = [
  {
    ruleCode: 'MASS_DOWNLOAD',
    name: 'Tải hàng loạt trong cửa sổ thời gian',
    isEnabled: true,
    severity: 'HIGH',
    threshold: 5,
    windowMinutes: 10,
    cooldownMinutes: 30,
    parameters: { maxDownloads: 5 },
  },
  {
    ruleCode: 'REPEATED_DENIED',
    name: 'Nhiều lần truy cập bị từ chối',
    isEnabled: true,
    severity: 'MEDIUM',
    threshold: 5,
    windowMinutes: 15,
    cooldownMinutes: 30,
    parameters: { maxDenied: 5 },
  },
  {
    ruleCode: 'OFF_HOURS_ACCESS',
    name: 'Truy cập ngoài giờ làm việc',
    isEnabled: true,
    severity: 'LOW',
    threshold: 1,
    windowMinutes: 60,
    cooldownMinutes: 60,
    parameters: { startHourUtc: 0, endHourUtc: 12 }, // e.g. 7h-19h VN (UTC+7)
  },
  {
    ruleCode: 'UNTRUSTED_CONTEXT',
    name: 'Truy cập từ thiết bị hoặc IP chưa tin cậy',
    isEnabled: true,
    severity: 'MEDIUM',
    threshold: 1,
    windowMinutes: 15,
    cooldownMinutes: 30,
    parameters: {},
  },
  {
    ruleCode: 'REFRESH_TOKEN_REUSE',
    name: 'Phát hiện tái sử dụng refresh token',
    isEnabled: true,
    severity: 'CRITICAL',
    threshold: 1,
    windowMinutes: 60,
    cooldownMinutes: 15,
    parameters: {},
  },
  {
    ruleCode: 'AUDIT_INTEGRITY_COMPROMISED',
    name: 'Phát hiện tính toàn vẹn audit bị vi phạm',
    isEnabled: true,
    severity: 'CRITICAL',
    threshold: 1,
    windowMinutes: 60,
    cooldownMinutes: 15,
    parameters: {},
  },
];

/**
 * Loads detection rule configurations from database with fallback to default rules.
 */
export async function loadDetectionRules(database: PrismaClient): Promise<DetectionRuleConfig[]> {
  try {
    const rows = await database.detectionRuleConfig.findMany();
    if (rows && rows.length > 0) {
      return rows.map((r) => ({
        ruleCode: r.rule_code,
        name: r.name,
        isEnabled: r.is_enabled,
        severity: r.severity,
        threshold: r.threshold,
        windowMinutes: r.window_minutes,
        cooldownMinutes: r.cooldown_minutes,
        parameters: (r.parameters as Record<string, unknown>) ?? {},
      }));
    }
  } catch {
    // Ignore if table not yet populated
  }
  return DEFAULT_DETECTION_RULES;
}

/**
 * Evaluates rules against audit logs and generates security alerts.
 */
export async function runDetectionCycle(options?: {
  databaseClient?: PrismaClient;
  now?: Date;
}): Promise<{ alertsCreated: number; rulesEvaluated: number }> {
  const database = options?.databaseClient ?? getDatabaseClient();
  const now = options?.now ?? new Date();
  const rules = await loadDetectionRules(database);

  let alertsCreated = 0;
  let rulesEvaluated = 0;

  for (const rule of rules) {
    if (!rule.isEnabled) continue;
    rulesEvaluated++;

    const windowStart = new Date(now.getTime() - rule.windowMinutes * 60 * 1000);
    const cooldownStart = new Date(now.getTime() - rule.cooldownMinutes * 60 * 1000);

    try {
      if (rule.ruleCode === 'MASS_DOWNLOAD') {
        // Find users exceeding download threshold within window
        const logs = await database.auditLog.findMany({
          where: {
            action: { in: ['DOCUMENT_DOWNLOADED', 'DOCUMENT_CONTENT_DOWNLOADED'] },
            outcome: 'SUCCESS',
            occurred_at: { gte: windowStart, lte: now },
            actor_user_id: { not: null },
          },
          select: { id: true, actor_user_id: true, document_id: true, occurred_at: true },
        });

        // Group by actor_user_id
        const userGroups = new Map<string, typeof logs>();
        for (const log of logs) {
          if (!log.actor_user_id) continue;
          const key = log.actor_user_id.toString();
          const list = userGroups.get(key) ?? [];
          list.push(log);
          userGroups.set(key, list);
        }

        for (const [userIdStr, userLogs] of userGroups.entries()) {
          if (userLogs.length >= rule.threshold) {
            const actorUserId = BigInt(userIdStr);
            // Check cooldown suppression
            const existingAlert = await database.securityAlert.findFirst({
              where: {
                alert_type: rule.ruleCode,
                detected_user_id: actorUserId,
                detected_at: { gte: cooldownStart },
              },
            });

            if (!existingAlert) {
              const alertId = randomUUID();
              await database.$transaction(async (tx: Prisma.TransactionClient) => {
                await tx.securityAlert.create({
                  data: {
                    id: alertId,
                    alert_type: rule.ruleCode,
                    severity: rule.severity,
                    status: 'OPEN' as alert_status,
                    title: `Cảnh báo: Tải hàng loạt (${userLogs.length} tài liệu)`,
                    description: `Người dùng đã tải ${userLogs.length} tài liệu trong ${rule.windowMinutes} phút (ngưỡng: ${rule.threshold}).`,
                    detected_user_id: actorUserId,
                    detected_at: now,
                  },
                });

                // Link matching audit logs
                if (userLogs.length > 0) {
                  await tx.alertAuditLink.createMany({
                    data: userLogs.map((l) => ({
                      alert_id: alertId,
                      audit_log_id: l.id,
                    })),
                    skipDuplicates: true,
                  });
                }
              });
              alertsCreated++;
            }
          }
        }
      } else if (rule.ruleCode === 'REPEATED_DENIED') {
        const logs = await database.auditLog.findMany({
          where: {
            outcome: 'DENIED',
            occurred_at: { gte: windowStart, lte: now },
            actor_user_id: { not: null },
          },
          select: { id: true, actor_user_id: true, occurred_at: true },
        });

        const userGroups = new Map<string, typeof logs>();
        for (const log of logs) {
          if (!log.actor_user_id) continue;
          const key = log.actor_user_id.toString();
          const list = userGroups.get(key) ?? [];
          list.push(log);
          userGroups.set(key, list);
        }

        for (const [userIdStr, userLogs] of userGroups.entries()) {
          if (userLogs.length >= rule.threshold) {
            const actorUserId = BigInt(userIdStr);
            const existingAlert = await database.securityAlert.findFirst({
              where: {
                alert_type: rule.ruleCode,
                detected_user_id: actorUserId,
                detected_at: { gte: cooldownStart },
              },
            });

            if (!existingAlert) {
              const alertId = randomUUID();
              await database.$transaction(async (tx: Prisma.TransactionClient) => {
                await tx.securityAlert.create({
                  data: {
                    id: alertId,
                    alert_type: rule.ruleCode,
                    severity: rule.severity,
                    status: 'OPEN' as alert_status,
                    title: `Cảnh báo: Từ chối truy cập liên tiếp (${userLogs.length} lần)`,
                    description: `Người dùng nhận ${userLogs.length} lần từ chối truy cập trong ${rule.windowMinutes} phút (ngưỡng: ${rule.threshold}).`,
                    detected_user_id: actorUserId,
                    detected_at: now,
                  },
                });

                await tx.alertAuditLink.createMany({
                  data: userLogs.map((l) => ({
                    alert_id: alertId,
                    audit_log_id: l.id,
                  })),
                  skipDuplicates: true,
                });
              });
              alertsCreated++;
            }
          }
        }
      } else if (rule.ruleCode === 'OFF_HOURS_ACCESS') {
        const startHour = (rule.parameters['startHourUtc'] as number) ?? 0;
        const endHour = (rule.parameters['endHourUtc'] as number) ?? 12;

        const logs = await database.auditLog.findMany({
          where: {
            occurred_at: { gte: windowStart, lte: now },
            actor_user_id: { not: null },
          },
          select: { id: true, actor_user_id: true, occurred_at: true },
        });

        const offHoursLogs = logs.filter((l) => {
          const hours = l.occurred_at.getUTCHours();
          return hours < startHour || hours >= endHour;
        });

        const userGroups = new Map<string, typeof offHoursLogs>();
        for (const log of offHoursLogs) {
          if (!log.actor_user_id) continue;
          const key = log.actor_user_id.toString();
          const list = userGroups.get(key) ?? [];
          list.push(log);
          userGroups.set(key, list);
        }

        for (const [userIdStr, userLogs] of userGroups.entries()) {
          if (userLogs.length >= rule.threshold) {
            const actorUserId = BigInt(userIdStr);
            const existingAlert = await database.securityAlert.findFirst({
              where: {
                alert_type: rule.ruleCode,
                detected_user_id: actorUserId,
                detected_at: { gte: cooldownStart },
              },
            });

            if (!existingAlert) {
              const alertId = randomUUID();
              await database.$transaction(async (tx: Prisma.TransactionClient) => {
                await tx.securityAlert.create({
                  data: {
                    id: alertId,
                    alert_type: rule.ruleCode,
                    severity: rule.severity,
                    status: 'OPEN' as alert_status,
                    title: `Cảnh báo: Truy cập ngoài giờ quy định`,
                    description: `Phát hiện ${userLogs.length} hành động ngoài khung giờ cho phép trong ${rule.windowMinutes} phút.`,
                    detected_user_id: actorUserId,
                    detected_at: now,
                  },
                });

                await tx.alertAuditLink.createMany({
                  data: userLogs.map((l) => ({
                    alert_id: alertId,
                    audit_log_id: l.id,
                  })),
                  skipDuplicates: true,
                });
              });
              alertsCreated++;
            }
          }
        }
      } else if (rule.ruleCode === 'UNTRUSTED_CONTEXT') {
        const logs = await database.auditLog.findMany({
          where: {
            action: {
              in: [
                'UNTRUSTED_CONTEXT_DETECTED',
                'LOGIN_UNTRUSTED_DEVICE',
                'ACCESS_DENIED_UNTRUSTED_IP',
              ],
            },
            occurred_at: { gte: windowStart, lte: now },
          },
          select: { id: true, actor_user_id: true, occurred_at: true },
        });

        if (logs.length >= rule.threshold) {
          const firstUserId = logs[0]?.actor_user_id ?? null;
          const existingAlert = await database.securityAlert.findFirst({
            where: {
              alert_type: rule.ruleCode,
              ...(firstUserId ? { detected_user_id: firstUserId } : {}),
              detected_at: { gte: cooldownStart },
            },
          });

          if (!existingAlert) {
            const alertId = randomUUID();
            await database.$transaction(async (tx: Prisma.TransactionClient) => {
              await tx.securityAlert.create({
                data: {
                  id: alertId,
                  alert_type: rule.ruleCode,
                  severity: rule.severity,
                  status: 'OPEN' as alert_status,
                  title: `Cảnh báo: Bối cảnh truy cập chưa tin cậy`,
                  description: `Phát hiện ${logs.length} truy cập từ IP hoặc thiết bị chưa tin cậy.`,
                  detected_user_id: firstUserId,
                  detected_at: now,
                },
              });

              await tx.alertAuditLink.createMany({
                data: logs.map((l) => ({
                  alert_id: alertId,
                  audit_log_id: l.id,
                })),
                skipDuplicates: true,
              });
            });
            alertsCreated++;
          }
        }
      } else if (rule.ruleCode === 'REFRESH_TOKEN_REUSE') {
        const logs = await database.auditLog.findMany({
          where: {
            action: { in: ['REFRESH_TOKEN_REUSED', 'TOKEN_REVOCATION_TRIGGERED'] },
            occurred_at: { gte: windowStart, lte: now },
          },
          select: { id: true, actor_user_id: true, occurred_at: true },
        });

        if (logs.length >= rule.threshold) {
          const firstUserId = logs[0]?.actor_user_id ?? null;
          const existingAlert = await database.securityAlert.findFirst({
            where: {
              alert_type: rule.ruleCode,
              ...(firstUserId ? { detected_user_id: firstUserId } : {}),
              detected_at: { gte: cooldownStart },
            },
          });

          if (!existingAlert) {
            const alertId = randomUUID();
            await database.$transaction(async (tx: Prisma.TransactionClient) => {
              await tx.securityAlert.create({
                data: {
                  id: alertId,
                  alert_type: rule.ruleCode,
                  severity: rule.severity,
                  status: 'OPEN' as alert_status,
                  title: `Cảnh báo nghiêm trọng: Tái sử dụng Refresh Token`,
                  description: `Phát hiện nỗ lực sử dụng lại Refresh Token đã thu hồi. Phiên làm việc bị vô hiệu hóa.`,
                  detected_user_id: firstUserId,
                  detected_at: now,
                },
              });

              await tx.alertAuditLink.createMany({
                data: logs.map((l) => ({
                  alert_id: alertId,
                  audit_log_id: l.id,
                })),
                skipDuplicates: true,
              });
            });
            alertsCreated++;
          }
        }
      } else if (rule.ruleCode === 'AUDIT_INTEGRITY_COMPROMISED') {
        const logs = await database.auditLog.findMany({
          where: {
            action: {
              in: [
                'AUDIT_INTEGRITY_VERIFICATION_FAILED',
                'AUDIT_CHAIN_BROKEN',
                'AUDIT_HMAC_MISMATCH',
              ],
            },
            occurred_at: { gte: windowStart, lte: now },
          },
          select: { id: true, actor_user_id: true, occurred_at: true },
        });

        if (logs.length >= rule.threshold) {
          const existingAlert = await database.securityAlert.findFirst({
            where: {
              alert_type: rule.ruleCode,
              detected_at: { gte: cooldownStart },
            },
          });

          if (!existingAlert) {
            const alertId = randomUUID();
            await database.$transaction(async (tx: Prisma.TransactionClient) => {
              await tx.securityAlert.create({
                data: {
                  id: alertId,
                  alert_type: rule.ruleCode,
                  severity: rule.severity,
                  status: 'OPEN' as alert_status,
                  title: `Cảnh báo khẩn cấp: Vi phạm tính toàn vẹn Audit Log`,
                  description: `Hệ thống xác minh phát hiện chuỗi băm audit log không khớp hoặc có dấu hiệu can thiệp trái phép.`,
                  detected_user_id: null,
                  detected_at: now,
                },
              });

              await tx.alertAuditLink.createMany({
                data: logs.map((l) => ({
                  alert_id: alertId,
                  audit_log_id: l.id,
                })),
                skipDuplicates: true,
              });
            });
            alertsCreated++;
          }
        }
      }
    } catch (err) {
      console.warn(`Error evaluating rule ${rule.ruleCode}:`, err);
    }
  }

  return { alertsCreated, rulesEvaluated };
}

/**
 * Starts the periodic security detection background runner.
 */
export function startSecurityDetectionJob(intervalMs: number, signal: AbortSignal): void {
  if (signal.aborted) return;

  const timer = setInterval(async () => {
    if (signal.aborted) {
      clearInterval(timer);
      return;
    }

    try {
      const result = await runDetectionCycle();
      if (result.alertsCreated > 0) {
        console.info(`Security detection job generated ${result.alertsCreated} alert(s).`);
      }
    } catch (err) {
      console.error(`Security detection cycle failed: ${err}`);
    }
  }, intervalMs);

  signal.addEventListener(
    'abort',
    () => {
      clearInterval(timer);
      console.info('Security detection job stopped cleanly.');
    },
    { once: true },
  );

  console.info(`Security detection worker started (interval: ${intervalMs}ms).`);
}

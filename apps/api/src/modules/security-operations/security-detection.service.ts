import { Injectable, Logger, Optional } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { getDatabaseClient } from '@sda/database';
import type { severity_level } from '@sda/database';
import { AuditWriterService } from '../audit/audit-writer.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface DetectionRule {
  ruleCode: string;
  name: string;
  description: string;
  isEnabled: boolean;
  severity: severity_level;
  threshold: number;
  windowMinutes: number;
  cooldownMinutes: number;
  parameters: Record<string, unknown>;
}

export interface DetectionResult {
  ruleCode: string;
  matched: boolean;
  alertId?: string | undefined;
  isNewAlert: boolean;
  suppressedByCooldown: boolean;
  linkedAuditLogIds: string[];
  userId?: string | undefined;
}

const DEFAULT_RULES: DetectionRule[] = [
  {
    ruleCode: 'MASS_DOWNLOAD',
    name: 'Phát hiện tải hàng loạt',
    description: 'Cảnh báo khi người dùng tải nhiều tài liệu trong khoảng thời gian ngắn',
    isEnabled: true,
    severity: 'HIGH',
    threshold: 5,
    windowMinutes: 10,
    cooldownMinutes: 30,
    parameters: { action: 'DOCUMENT_DOWNLOADED' },
  },
  {
    ruleCode: 'REPEATED_DENIED',
    name: 'Phát hiện từ chối truy cập liên tiếp',
    description: 'Cảnh báo khi có nhiều yêu cầu bị từ chối truy cập từ cùng một đối tượng',
    isEnabled: true,
    severity: 'MEDIUM',
    threshold: 5,
    windowMinutes: 10,
    cooldownMinutes: 15,
    parameters: { outcome: 'DENIED' },
  },
  {
    ruleCode: 'OFF_HOURS_ACCESS',
    name: 'Phát hiện truy cập ngoài giờ',
    description:
      'Cảnh báo khi có hoạt động truy cập tài liệu nhạy cảm ngoài giờ làm việc hoặc cuối tuần',
    isEnabled: true,
    severity: 'MEDIUM',
    threshold: 1,
    windowMinutes: 5,
    cooldownMinutes: 60,
    parameters: { startHourUtc: 0, endHourUtc: 11 },
  },
  {
    ruleCode: 'UNTRUSTED_CONTEXT',
    name: 'Phát hiện IP hoặc thiết bị chưa tin cậy',
    description: 'Cảnh báo khi truy cập từ thiết bị hoặc địa chỉ IP nằm ngoài danh sách tin cậy',
    isEnabled: true,
    severity: 'HIGH',
    threshold: 1,
    windowMinutes: 5,
    cooldownMinutes: 30,
    parameters: {},
  },
  {
    ruleCode: 'REFRESH_TOKEN_REUSE',
    name: 'Phát hiện tái sử dụng Refresh Token',
    description: 'Cảnh báo khi một refresh token đã xoay vòng hoặc thu hồi được sử dụng lại',
    isEnabled: true,
    severity: 'HIGH',
    threshold: 1,
    windowMinutes: 5,
    cooldownMinutes: 15,
    parameters: {},
  },
  {
    ruleCode: 'AUDIT_INTEGRITY_COMPROMISED',
    name: 'Phát hiện vi phạm toàn vẹn Audit',
    description: 'Cảnh báo nghiêm trọng khi phát hiện đứt gãy chuỗi HMAC hoặc sai lệch sequence',
    isEnabled: true,
    severity: 'CRITICAL',
    threshold: 1,
    windowMinutes: 5,
    cooldownMinutes: 15,
    parameters: {},
  },
];

@Injectable()
export class SecurityDetectionService {
  private readonly logger = new Logger(SecurityDetectionService.name);
  private readonly database: PrismaClient;

  constructor(
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly auditWriter?: AuditWriterService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Retrieves active detection rule configurations.
   */
  async getRules(): Promise<DetectionRule[]> {
    try {
      const dbConfigs = await this.database.detectionRuleConfig.findMany();
      if (dbConfigs && dbConfigs.length > 0) {
        return dbConfigs.map((cfg) => ({
          ruleCode: cfg.rule_code,
          name: cfg.name,
          description: cfg.description ?? '',
          isEnabled: cfg.is_enabled,
          severity: cfg.severity,
          threshold: cfg.threshold,
          windowMinutes: cfg.window_minutes,
          cooldownMinutes: cfg.cooldown_minutes,
          parameters: (cfg.parameters as Record<string, unknown>) ?? {},
        }));
      }
    } catch {
      // Fallback to in-memory defaults if table is not yet migrated/reachable
    }
    return DEFAULT_RULES;
  }

  /**
   * Updates an existing detection rule configuration.
   */
  async updateRule(
    ruleCode: string,
    updates: Partial<DetectionRule>,
    updatedByUserId?: bigint,
  ): Promise<DetectionRule> {
    const existing = (await this.getRules()).find((r) => r.ruleCode === ruleCode);
    if (!existing) {
      throw new Error(`Rule ${ruleCode} not found.`);
    }

    try {
      const updated = await this.database.detectionRuleConfig.upsert({
        where: { rule_code: ruleCode },
        update: {
          is_enabled: updates.isEnabled ?? existing.isEnabled,
          severity: updates.severity ?? existing.severity,
          threshold: updates.threshold ?? existing.threshold,
          window_minutes: updates.windowMinutes ?? existing.windowMinutes,
          cooldown_minutes: updates.cooldownMinutes ?? existing.cooldownMinutes,
          parameters: (updates.parameters ?? existing.parameters) as never,
          updated_at: new Date(),
          updated_by: updatedByUserId ?? null,
        },
        create: {
          rule_code: ruleCode,
          name: existing.name,
          description: existing.description,
          is_enabled: updates.isEnabled ?? existing.isEnabled,
          severity: updates.severity ?? existing.severity,
          threshold: updates.threshold ?? existing.threshold,
          window_minutes: updates.windowMinutes ?? existing.windowMinutes,
          cooldown_minutes: updates.cooldownMinutes ?? existing.cooldownMinutes,
          parameters: (updates.parameters ?? existing.parameters) as never,
          updated_by: updatedByUserId ?? null,
        },
      });

      if (this.auditWriter && updatedByUserId) {
        await this.auditWriter.writeLog({
          action: 'DETECTION_RULE_CONFIGURED',
          outcome: 'SUCCESS',
          actorUserId: updatedByUserId,
          objectType: 'DETECTION_RULE_CONFIG',
          objectId: ruleCode,
          chainPartition: 'SECURITY_OPERATIONS',
          details: { ruleCode, updates },
        });
      }

      return {
        ruleCode: updated.rule_code,
        name: updated.name,
        description: updated.description ?? '',
        isEnabled: updated.is_enabled,
        severity: updated.severity,
        threshold: updated.threshold,
        windowMinutes: updated.window_minutes,
        cooldownMinutes: updated.cooldown_minutes,
        parameters: (updated.parameters as Record<string, unknown>) ?? {},
      };
    } catch {
      Object.assign(existing, updates);
      return existing;
    }
  }

  /**
   * Evaluates all enabled detection rules against recent audit logs.
   */
  async runAllDetections(customWindowMinutes?: number): Promise<DetectionResult[]> {
    const rules = await this.getRules();
    const results: DetectionResult[] = [];

    for (const rule of rules) {
      if (!rule.isEnabled) continue;
      const window = customWindowMinutes ?? rule.windowMinutes;
      const ruleResults = await this.evaluateRule(rule, window);
      results.push(...ruleResults);
    }

    return results;
  }

  /**
   * Evaluates a single detection rule.
   */
  async evaluateRule(rule: DetectionRule, windowMinutes: number): Promise<DetectionResult[]> {
    const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000);
    const results: DetectionResult[] = [];

    switch (rule.ruleCode) {
      case 'MASS_DOWNLOAD': {
        // Find users with downloads >= threshold within window
        const logs = await this.database.auditLog.findMany({
          where: {
            action: { in: ['DOCUMENT_DOWNLOADED', 'DOCUMENT_DOWNLOAD'] },
            occurred_at: { gte: windowStart },
            actor_user_id: { not: null },
          },
          select: { id: true, actor_user_id: true, document_id: true, occurred_at: true },
          orderBy: { occurred_at: 'desc' },
        });

        const logsByUser = new Map<string, typeof logs>();
        for (const log of logs) {
          const uid = log.actor_user_id!.toString();
          const list = logsByUser.get(uid) ?? [];
          list.push(log);
          logsByUser.set(uid, list);
        }

        for (const [userIdStr, userLogs] of logsByUser.entries()) {
          if (userLogs.length >= rule.threshold) {
            const res = await this.processAlertOrSuppress({
              rule,
              userId: BigInt(userIdStr),
              documentId: userLogs[0]?.document_id ?? undefined,
              matchingLogIds: userLogs.map((l) => l.id),
              title: `Phát hiện tải hàng loạt: Người dùng #${userIdStr} đã tải ${userLogs.length} tài liệu trong ${windowMinutes} phút`,
              description: `Người dùng ID ${userIdStr} đã thực hiện ${userLogs.length} lần tải tài liệu trong cửa sổ ${windowMinutes} phút (ngưỡng: ${rule.threshold}).`,
            });
            results.push(res);
          }
        }
        break;
      }

      case 'REPEATED_DENIED': {
        // Find users with DENIED outcome >= threshold within window
        const logs = await this.database.auditLog.findMany({
          where: {
            outcome: 'DENIED',
            occurred_at: { gte: windowStart },
            actor_user_id: { not: null },
          },
          select: { id: true, actor_user_id: true, occurred_at: true },
          orderBy: { occurred_at: 'desc' },
        });

        const logsByUser = new Map<string, typeof logs>();
        for (const log of logs) {
          const uid = log.actor_user_id!.toString();
          const list = logsByUser.get(uid) ?? [];
          list.push(log);
          logsByUser.set(uid, list);
        }

        for (const [userIdStr, userLogs] of logsByUser.entries()) {
          if (userLogs.length >= rule.threshold) {
            const res = await this.processAlertOrSuppress({
              rule,
              userId: BigInt(userIdStr),
              matchingLogIds: userLogs.map((l) => l.id),
              title: `Nhiều lần bị từ chối truy cập: Người dùng #${userIdStr} bị từ chối ${userLogs.length} lần`,
              description: `Người dùng ID ${userIdStr} đã nhận ${userLogs.length} kết quả DENIED trong cửa sổ ${windowMinutes} phút (ngưỡng: ${rule.threshold}).`,
            });
            results.push(res);
          }
        }
        break;
      }

      case 'OFF_HOURS_ACCESS': {
        // Access attempted during off-hours (e.g., weekend or late night)
        const logs = await this.database.auditLog.findMany({
          where: {
            action: { in: ['DOCUMENT_DOWNLOADED', 'DOCUMENT_VIEWED', 'ACCESS_PERMITTED'] },
            occurred_at: { gte: windowStart },
            actor_user_id: { not: null },
          },
          select: { id: true, actor_user_id: true, document_id: true, occurred_at: true },
          orderBy: { occurred_at: 'desc' },
        });

        const offHoursLogs = logs.filter((log) => {
          const d = new Date(log.occurred_at);
          const day = d.getUTCDay(); // 0 = Sun, 6 = Sat
          const hour = d.getUTCHours();
          // Weekend OR outside 00:00 - 12:00 UTC (sample business day window)
          const isWeekend = day === 0 || day === 6;
          const isNight = hour < 0 || hour >= 12; // configurable
          return isWeekend || isNight;
        });

        const logsByUser = new Map<string, typeof logs>();
        for (const log of offHoursLogs) {
          const uid = log.actor_user_id!.toString();
          const list = logsByUser.get(uid) ?? [];
          list.push(log);
          logsByUser.set(uid, list);
        }

        for (const [userIdStr, userLogs] of logsByUser.entries()) {
          if (userLogs.length >= rule.threshold) {
            const res = await this.processAlertOrSuppress({
              rule,
              userId: BigInt(userIdStr),
              documentId: userLogs[0]?.document_id ?? undefined,
              matchingLogIds: userLogs.map((l) => l.id),
              title: `Truy cập ngoài giờ: Người dùng #${userIdStr} truy cập tài liệu mật ngoài khung giờ làm việc`,
              description: `Phát hiện ${userLogs.length} lượt truy cập tài liệu ngoài giờ làm việc bởi người dùng #${userIdStr}.`,
            });
            results.push(res);
          }
        }
        break;
      }

      case 'UNTRUSTED_CONTEXT': {
        // IP or device marked as untrusted
        const logs = await this.database.auditLog.findMany({
          where: {
            occurred_at: { gte: windowStart },
            actor_user_id: { not: null },
          },
          select: { id: true, actor_user_id: true, details: true, occurred_at: true },
          orderBy: { occurred_at: 'desc' },
        });

        const untrustedLogs = logs.filter((log) => {
          const d = log.details as Record<string, unknown> | null;
          return (
            d !== null &&
            (d['untrustedContext'] === true ||
              d['untrustedIp'] === true ||
              d['untrustedDevice'] === true)
          );
        });

        const logsByUser = new Map<string, typeof logs>();
        for (const log of untrustedLogs) {
          const uid = log.actor_user_id!.toString();
          const list = logsByUser.get(uid) ?? [];
          list.push(log);
          logsByUser.set(uid, list);
        }

        for (const [userIdStr, userLogs] of logsByUser.entries()) {
          if (userLogs.length >= rule.threshold) {
            const res = await this.processAlertOrSuppress({
              rule,
              userId: BigInt(userIdStr),
              matchingLogIds: userLogs.map((l) => l.id),
              title: `Ngữ cảnh chưa tin cậy: Người dùng #${userIdStr} truy cập từ IP/thiết bị lạ`,
              description: `Phát hiện truy cập từ thiết bị hoặc mạng chưa xác thực (${userLogs.length} lần) bởi người dùng #${userIdStr}.`,
            });
            results.push(res);
          }
        }
        break;
      }

      case 'REFRESH_TOKEN_REUSE': {
        const logs = await this.database.auditLog.findMany({
          where: {
            action: 'REFRESH_TOKEN_REUSE',
            occurred_at: { gte: windowStart },
            actor_user_id: { not: null },
          },
          select: { id: true, actor_user_id: true, occurred_at: true },
          orderBy: { occurred_at: 'desc' },
        });

        const logsByUser = new Map<string, typeof logs>();
        for (const log of logs) {
          const uid = log.actor_user_id!.toString();
          const list = logsByUser.get(uid) ?? [];
          list.push(log);
          logsByUser.set(uid, list);
        }

        for (const [userIdStr, userLogs] of logsByUser.entries()) {
          if (userLogs.length >= rule.threshold) {
            const res = await this.processAlertOrSuppress({
              rule,
              userId: BigInt(userIdStr),
              matchingLogIds: userLogs.map((l) => l.id),
              title: `Tái sử dụng Refresh Token: Người dùng #${userIdStr}`,
              description: `Phát hiện việc sử dụng lại refresh token đã bị thu hồi/rotate bởi người dùng #${userIdStr}.`,
            });
            results.push(res);
          }
        }
        break;
      }

      case 'AUDIT_INTEGRITY_COMPROMISED': {
        const logs = await this.database.auditLog.findMany({
          where: {
            action: {
              in: ['AUDIT_INTEGRITY_COMPROMISED', 'AUDIT_CHAIN_BROKEN', 'AUDIT_LOG_TAMPERED'],
            },
            occurred_at: { gte: windowStart },
          },
          select: { id: true, actor_user_id: true, occurred_at: true },
          orderBy: { occurred_at: 'desc' },
        });

        if (logs.length >= rule.threshold) {
          const res = await this.processAlertOrSuppress({
            rule,
            userId: logs[0]?.actor_user_id ?? undefined,
            matchingLogIds: logs.map((l) => l.id),
            title: `CRITICAL: Tính toàn vẹn của chuỗi kiểm toán bị xâm phạm`,
            description: `Hệ thống ghi nhận ${logs.length} sự kiện vi phạm hoặc chỉnh sửa trái phép chuỗi HMAC kiểm toán.`,
          });
          results.push(res);
        }
        break;
      }
    }

    return results;
  }

  /**
   * Processes alert creation with alert-storm suppression within cooldown window.
   * If an active alert already exists within the cooldown period:
   *  - Suppress creating a new alert.
   *  - Link newly matching audit logs into alert_audit_links.
   */
  private async processAlertOrSuppress(params: {
    rule: DetectionRule;
    userId?: bigint | null | undefined;
    documentId?: string | null | undefined;
    matchingLogIds: bigint[];
    title: string;
    description: string;
  }): Promise<DetectionResult> {
    const { rule, userId, documentId, matchingLogIds, title, description } = params;
    const cooldownBoundary = new Date(Date.now() - rule.cooldownMinutes * 60 * 1000);

    // Check for existing active alert within cooldown
    const existingAlert = await this.database.securityAlert.findFirst({
      where: {
        alert_type: rule.ruleCode,
        ...(userId ? { detected_user_id: userId } : {}),
        status: { in: ['OPEN', 'INVESTIGATING'] },
        detected_at: { gte: cooldownBoundary },
      },
      include: {
        alert_audit_links: true,
      },
      orderBy: { detected_at: 'desc' },
    });

    if (existingAlert) {
      // Alert storm suppression: Link new matching audit logs without creating a duplicate alert
      const existingLinkedLogIds = new Set(
        (existingAlert.alert_audit_links ?? []).map((link) => link.audit_log_id.toString()),
      );
      const newLogIdsToLink = matchingLogIds.filter(
        (logId) => !existingLinkedLogIds.has(logId.toString()),
      );

      if (newLogIdsToLink.length > 0) {
        await this.database.alertAuditLink.createMany({
          data: newLogIdsToLink.map((logId) => ({
            alert_id: existingAlert.id,
            audit_log_id: logId,
          })),
          skipDuplicates: true,
        });
      }

      this.logger.log(
        `Alert storm suppressed for rule ${rule.ruleCode} (user: ${userId?.toString() ?? 'system'}). ` +
          `Linked ${newLogIdsToLink.length} new audit logs to existing alert ${existingAlert.id}.`,
      );

      return {
        ruleCode: rule.ruleCode,
        matched: true,
        alertId: existingAlert.id,
        isNewAlert: false,
        suppressedByCooldown: true,
        linkedAuditLogIds: matchingLogIds.map((id) => id.toString()),
        userId: userId != null ? userId.toString() : undefined,
      };
    }

    // No existing alert in cooldown: create a brand new SecurityAlert
    const newAlertId = randomUUID();
    await this.database.$transaction(async (tx) => {
      await tx.securityAlert.create({
        data: {
          id: newAlertId,
          alert_type: rule.ruleCode,
          severity: rule.severity,
          status: 'OPEN',
          title,
          description,
          detected_user_id: userId ?? null,
          document_id: documentId ?? null,
          detected_at: new Date(),
        },
      });

      if (matchingLogIds.length > 0) {
        await tx.alertAuditLink.createMany({
          data: matchingLogIds.map((logId) => ({
            alert_id: newAlertId,
            audit_log_id: logId,
          })),
          skipDuplicates: true,
        });
      }
    });

    try {
      const { MetricsService } = await import('../system-health/metrics.service.js');
      MetricsService.getInstance().recordSecurityAlert(rule.severity, rule.ruleCode);
    } catch {
      // Fallback
    }

    this.logger.warn(
      `Created new SecurityAlert [${rule.severity}] ${rule.ruleCode} (id: ${newAlertId}) for user ${userId?.toString() ?? 'system'} with ${matchingLogIds.length} linked logs.`,
    );

    return {
      ruleCode: rule.ruleCode,
      matched: true,
      alertId: newAlertId,
      isNewAlert: true,
      suppressedByCooldown: false,
      linkedAuditLogIds: matchingLogIds.map((id) => id.toString()),
      userId: userId != null ? userId.toString() : undefined,
    };
  }
}

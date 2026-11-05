import { Injectable, Logger, NotFoundException, Optional } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { AppErrorCode } from '@sda/contracts';
import { getDatabaseClient } from '@sda/database';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import {
  resolveActiveDetectionRules,
  upsertDetectionRuleConfig,
  type DetectionResult,
  type DetectionRule,
} from './detection-rule-defaults.js';
import { evaluateSlidingWindowRule, type AlertMatchCandidate } from './detection-evaluators.js';

export type { DetectionResult, DetectionRule };

type PrismaClient = ReturnType<typeof getDatabaseClient>;

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

  async getRules(): Promise<DetectionRule[]> {
    return resolveActiveDetectionRules(this.database);
  }

  async updateRule(
    ruleCode: string,
    updates: Partial<DetectionRule>,
    updatedByUserId?: bigint,
  ): Promise<DetectionRule> {
    const existing = (await this.getRules()).find((r) => r.ruleCode === ruleCode);
    if (!existing) {
      // CONFLICT-RESOLVED: Ném NotFoundException chuẩn hóa thay vì Error thô gây HTTP 500 (HIGH-11)
      throw new NotFoundException({
        errorCode: AppErrorCode.RESOURCE_NOT_FOUND,
        message: `Rule ${ruleCode} not found.`,
      });
    }
    return upsertDetectionRuleConfig(
      this.database,
      this.auditWriter,
      existing,
      updates,
      updatedByUserId,
    );
  }

  /**
   * Algorithm: Sequential Enabled-Rule Sweep.
   * Iterates over all enabled SOC rules and aggregates per-rule sliding-window match outcomes.
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

  async evaluateRule(rule: DetectionRule, windowMinutes: number): Promise<DetectionResult[]> {
    return evaluateSlidingWindowRule(this.database, rule, windowMinutes, (candidate) =>
      this.processAlertOrSuppress(candidate),
    );
  }

  /**
   * Algorithm: Cooldown-Bounded Alert Deduplication & Evidence Linking.
   * Suppresses duplicate `OPEN`/`INVESTIGATING` alerts within `[now - cooldownMinutes, now]` while
   * incrementally linking newly discovered `audit_log_id` evidence rows into `alert_audit_links`.
   */
  private async processAlertOrSuppress(params: AlertMatchCandidate): Promise<DetectionResult> {
    const { rule, userId, documentId, matchingLogIds, title, description } = params;
    const cooldownBoundary = new Date(Date.now() - rule.cooldownMinutes * 60 * 1000);

    const existingAlert = await this.database.securityAlert.findFirst({
      where: {
        alert_type: rule.ruleCode,
        ...(userId ? { detected_user_id: userId } : {}),
        status: { in: ['OPEN', 'INVESTIGATING'] },
        detected_at: { gte: cooldownBoundary },
      },
      include: { alert_audit_links: true },
      orderBy: { detected_at: 'desc' },
    });

    if (existingAlert) {
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
      // Fallback when metrics registry is inactive in isolated unit tests
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

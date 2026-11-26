import { Injectable, Logger, NotFoundException, Optional } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { AppErrorCode } from '@sda/contracts';
import { getDatabaseClient } from '@sda/database';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import { RealtimeEventsService } from '../realtime/realtime-events.service.js';
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
    @Optional() private readonly realtime?: RealtimeEventsService,
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
    const saved = await upsertDetectionRuleConfig(
      this.database,
      this.auditWriter,
      existing,
      updates,
      updatedByUserId,
    );
    this.realtime?.publish({
      type: 'DETECTION_RULE_UPDATED',
      targetRoles: ['SECURITY_OFFICER'],
      payload: { ruleCode: saved.ruleCode, isEnabled: saved.isEnabled, severity: saved.severity },
    });
    return saved;
  }

  /**
   * Algorithm: Sequential Enabled-Rule Sweep with Optional Targeted `ruleCodes` Filtering (`runAllDetections`).
   * Iterates over all enabled SOC rules (or the requested `ruleCodes` subset) and aggregates per-rule sliding-window match outcomes (N08).
   */
  async runAllDetections(
    customWindowMinutes?: number,
    ruleCodes?: readonly string[],
  ): Promise<DetectionResult[]> {
    const rules = await this.getRules();
    const filterSet =
      Array.isArray(ruleCodes) && ruleCodes.length > 0
        ? new Set(ruleCodes.map((c) => c.trim().toUpperCase()).filter(Boolean))
        : null;
    const results: DetectionResult[] = [];

    for (const rule of rules) {
      if (!rule.isEnabled) continue;
      if (filterSet && !filterSet.has(rule.ruleCode.toUpperCase())) continue;
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
   * Algorithm: Advisory-Locked Cooldown-Bounded Alert Deduplication & Evidence Linking (`BUG-069`).
   * Acquires a transaction-scoped `pg_advisory_xact_lock` keyed by `(ruleCode, userId)` so concurrent
   * API and Worker sweeps never create duplicate `OPEN` alerts within `[now - cooldownMinutes, now]`.
   */
  private async processAlertOrSuppress(params: AlertMatchCandidate): Promise<DetectionResult> {
    const { rule, userId, documentId, matchingLogIds, title, description } = params;
    const cooldownBoundary = new Date(Date.now() - rule.cooldownMinutes * 60 * 1000);
    const lockSubjectKey = userId != null ? userId.toString() : 'GLOBAL_SYSTEM';

    const executeAtomicCorrelation = async (
      tx: Parameters<Parameters<PrismaClient['$transaction']>[0]>[0] | PrismaClient,
    ): Promise<
      | { kind: 'suppressed'; alertId: string; newLinkedCount: number }
      | { kind: 'created'; alertId: string }
    > => {
      if (typeof tx.$executeRawUnsafe === 'function') {
        await tx.$executeRawUnsafe(
          'SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))',
          `soc-alert:${rule.ruleCode}`,
          lockSubjectKey,
        );
      }

      const existingAlert = await tx.securityAlert.findFirst({
        where: {
          alert_type: rule.ruleCode,
          // CONFLICT-RESOLVED: Luôn khóa rõ detected_user_id (kể cả null cho sự kiện ẩn danh/toàn hệ thống) bên trong $transaction có khóa tư vấn (BUG-069 / N09).
          detected_user_id: userId ?? null,
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
          await tx.alertAuditLink.createMany({
            data: newLogIdsToLink.map((logId) => ({
              alert_id: existingAlert.id,
              audit_log_id: logId,
            })),
            skipDuplicates: true,
          });
        }

        return {
          kind: 'suppressed',
          alertId: existingAlert.id,
          newLinkedCount: newLogIdsToLink.length,
        };
      }

      const newAlertId = randomUUID();
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

      return { kind: 'created', alertId: newAlertId };
    };

    const outcome =
      typeof this.database.$transaction === 'function'
        ? await this.database.$transaction((tx) => executeAtomicCorrelation(tx))
        : await executeAtomicCorrelation(this.database);

    if (outcome.kind === 'suppressed') {
      this.logger.log(
        `Alert storm suppressed for rule ${rule.ruleCode} (user: ${userId?.toString() ?? 'system'}). ` +
          `Linked ${outcome.newLinkedCount} new audit logs to existing alert ${outcome.alertId}.`,
      );

      return {
        ruleCode: rule.ruleCode,
        matched: true,
        alertId: outcome.alertId,
        isNewAlert: false,
        suppressedByCooldown: true,
        linkedAuditLogIds: matchingLogIds.map((id) => id.toString()),
        userId: userId != null ? userId.toString() : undefined,
      };
    }

    const newAlertId = outcome.alertId;
    try {
      const { MetricsService } = await import('../system-health/metrics.service.js');
      MetricsService.getInstance().recordSecurityAlert(rule.severity, rule.ruleCode);
    } catch {
      // Fallback when metrics registry is inactive in isolated unit tests
    }

    let targetDepartmentId: string | null = null;
    if (documentId && typeof this.database?.document?.findUnique === 'function') {
      const doc = await this.database.document
        .findUnique({ where: { id: documentId }, select: { department_id: true } })
        .catch(() => null);
      if (doc?.department_id != null) {
        targetDepartmentId = doc.department_id.toString();
      }
    }
    if (
      !targetDepartmentId &&
      userId != null &&
      typeof this.database?.user?.findUnique === 'function'
    ) {
      const usr = await this.database.user
        .findUnique({ where: { id: userId }, select: { department_id: true } })
        .catch(() => null);
      if (usr?.department_id != null) {
        targetDepartmentId = usr.department_id.toString();
      }
    }

    this.logger.warn(
      `Created new SecurityAlert [${rule.severity}] ${rule.ruleCode} (id: ${newAlertId}) for user ${userId?.toString() ?? 'system'} with ${matchingLogIds.length} linked logs.`,
    );
    this.realtime?.publish({
      type: 'SECURITY_ALERT_UPDATED',
      targetRoles: ['SECURITY_OFFICER'],
      ...(targetDepartmentId ? { targetDepartmentId } : {}),
      payload: {
        id: newAlertId,
        alertType: rule.ruleCode,
        severity: rule.severity,
        status: 'OPEN',
        action: 'CREATED',
      },
    });

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

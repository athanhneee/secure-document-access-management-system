/**
 * Module: DetectionRuleDefaults — Phân giải cấu hình quy tắc SOC từ CSDL kèm dự phòng mặc định chuẩn hóa và cập nhật lũy đẳng `upsert`.
 */
import { cloneDefaultSecurityDetectionRules } from '@sda/contracts';
import type { getDatabaseClient, severity_level } from '@sda/database';
import type { AuditWriterService } from '../audit/audit-writer.service.js';

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

/**
 * Thuật toán: Phân giải cấu hình quy tắc ưu tiên CSDL kèm dự phòng chuẩn hóa (Database-First Rule Resolution with Baseline Fallback)
 * Mục đích: Đọc cấu hình quy tắc SOC động từ bảng `detection_rule_configs`, tự động lùi về bộ quy tắc chuẩn `@sda/contracts` nếu bảng trống hoặc lỗi kết nối.
 * Cơ chế hoạt động:
 *   - Truy vấn `detectionRuleConfig.findMany()`; nếu có dữ liệu thì ánh xạ sang `DetectionRule[]`, ngược lại trả về bản sao từ `cloneDefaultSecurityDetectionRules()`.
 *
 * Algorithm: Database-First Rule Resolution with Shared Baseline Fallback.
 * Queries `detection_rule_configs` and falls back to `@sda/contracts` canonical rule
 * definitions when the configuration table is empty or unreachable.
 */
export async function resolveActiveDetectionRules(
  database: PrismaClient,
): Promise<DetectionRule[]> {
  try {
    const dbConfigs = await database.detectionRuleConfig.findMany();
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
    // Fallback to canonical shared defaults if table is not yet migrated/reachable
  }
  // CONFLICT-RESOLVED: Dùng bộ quy tắc mặc định thống nhất từ @sda/contracts thay vì khai báo trùng lặp cục bộ lệch với Worker.
  return cloneDefaultSecurityDetectionRules() as DetectionRule[];
}

/**
 * Thuật toán: Cập nhật quy tắc lũy đẳng kèm ghi vết kiểm toán (Idempotent Rule Upsert with Tamper-Evident Audit Trail)
 * Mục đích: Hợp nhất các thay đổi cấu hình quy tắc SOC qua `upsert` và lưu bản ghi kiểm toán `DETECTION_RULE_CONFIGURED`.
 * Cơ chế hoạt động:
 *   - Kết hợp giá trị cập nhật với cấu hình hiện hành (`updates.field ?? existing.field`), thực thi `upsert` theo khóa `rule_code` và ghi vào phân vùng `SECURITY_OPERATIONS`.
 *
 * Algorithm: Idempotent Rule Upsert with Tamper-Evident Audit Trail.
 * Merges partial rule updates onto the active baseline via `upsert` and appends a
 * `SECURITY_OPERATIONS` audit record when an operator principal is supplied.
 */
export async function upsertDetectionRuleConfig(
  database: PrismaClient,
  auditWriter: AuditWriterService | undefined,
  existing: DetectionRule,
  updates: Partial<DetectionRule>,
  updatedByUserId?: bigint,
): Promise<DetectionRule> {
  const ruleCode = existing.ruleCode;
  try {
    const updated = await database.detectionRuleConfig.upsert({
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

    if (auditWriter && updatedByUserId) {
      await auditWriter.writeLog({
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

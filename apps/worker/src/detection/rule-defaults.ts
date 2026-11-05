import { cloneDefaultSecurityDetectionRules, type SecurityDetectionRuleSpec } from '@sda/contracts';
import { getDatabaseClient, type severity_level } from '@sda/database';

export type PrismaClient = ReturnType<typeof getDatabaseClient>;

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

function mapCanonicalRule(spec: SecurityDetectionRuleSpec): DetectionRuleConfig {
  return {
    ruleCode: spec.ruleCode,
    name: spec.name,
    isEnabled: spec.isEnabled,
    severity: spec.severity,
    threshold: spec.threshold,
    windowMinutes: spec.windowMinutes,
    cooldownMinutes: spec.cooldownMinutes,
    parameters: { ...spec.parameters },
  };
}

export const DEFAULT_DETECTION_RULES: DetectionRuleConfig[] =
  cloneDefaultSecurityDetectionRules().map(mapCanonicalRule);

/**
 * Algorithm / Thuật toán: Nạp cấu hình luật phát hiện có dự phòng an toàn (Database-First Configuration with Canonical Fallback)
 * Mục đích: Đọc danh sách luật từ bảng `detection_rule_configs` và ánh xạ sang mô hình bộ nhớ; nếu bảng rỗng hoặc gặp lỗi truy vấn,
 * tự động quay lui về bản sao phòng vệ từ `@sda/contracts` (`cloneDefaultSecurityDetectionRules`) đồng bộ 100% với API.
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
  return cloneDefaultSecurityDetectionRules().map(mapCanonicalRule);
}

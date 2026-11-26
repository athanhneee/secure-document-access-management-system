/**
 * Thuật toán / Tổng quan module:
 * Chuẩn hóa ánh xạ cấu hình luật phát hiện bất thường SOC cho `@sda/worker`, ưu tiên đọc cấu hình động từ bảng
 * `detection_rule_configs` và tự động dự phòng sang tập luật gốc bất biến từ `@sda/contracts`.
 */
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

/**
 * Thuật toán: Sao chép sâu tham số đặc tả luật chuẩn sang đối tượng cấu hình runtime độc lập để tránh đột biến trạng thái chia sẻ.
 */
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

/**
 * Thuật toán: Nạp cấu hình luật phát hiện bằng phép hợp nhất đè lên bộ luật gốc (Baseline-Merged Rule Resolution — `BUG-068`).
 * Mục đích: Khi `detection_rule_configs` chỉ lưu một số luật đã được quản trị viên tùy chỉnh, vẫn giữ nguyên toàn bộ các luật chuẩn còn lại
 * từ `@sda/contracts` thay vì vô hiệu hóa ngầm 5 luật mặc định khác; đồng thời luôn cưỡng chế `AUDIT_INTEGRITY_COMPROMISED.isEnabled = true`.
 */
export async function loadDetectionRules(database: PrismaClient): Promise<DetectionRuleConfig[]> {
  const baseline = cloneDefaultSecurityDetectionRules().map(mapCanonicalRule);
  try {
    const rows = await database.detectionRuleConfig.findMany();
    if (rows && rows.length > 0) {
      // CONFLICT-RESOLVED: Hợp nhất cấu hình DB đè lên tập luật chuẩn theo ruleCode đồng bộ 100% với API và cưỡng chế bật AUDIT_INTEGRITY_COMPROMISED (BUG-068).
      const overrides = new Map<string, DetectionRuleConfig>(
        rows.map((r) => [
          r.rule_code,
          {
            ruleCode: r.rule_code,
            name: r.name,
            isEnabled: r.rule_code === 'AUDIT_INTEGRITY_COMPROMISED' ? true : r.is_enabled,
            severity: r.severity,
            threshold: r.threshold,
            windowMinutes: r.window_minutes,
            cooldownMinutes: r.cooldown_minutes,
            parameters: (r.parameters as Record<string, unknown>) ?? {},
          },
        ]),
      );
      const merged = baseline.map((rule) => {
        const override = overrides.get(rule.ruleCode);
        if (override) {
          overrides.delete(rule.ruleCode);
          return override;
        }
        return rule.ruleCode === 'AUDIT_INTEGRITY_COMPROMISED'
          ? { ...rule, isEnabled: true }
          : rule;
      });
      return [...merged, ...overrides.values()];
    }
  } catch {
    // Ignore if table not yet populated
  }
  return baseline;
}

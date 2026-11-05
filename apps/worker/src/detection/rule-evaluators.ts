import {
  SECURITY_DETECTION_ACTIONS,
  isOffHoursTimestampUtc,
  isUntrustedAuditEvent,
} from '@sda/contracts';
import type { DetectionRuleConfig, PrismaClient } from './rule-defaults.js';
import { emitPerUserThresholdAlerts, emitAggregateThresholdAlert } from './alert-correlators.js';

/**
 * Algorithm / Thuật toán: Bộ Điều Phối Đánh Giá 6 Mẫu Bất Thường An Ninh Cửa Sổ Trượt (Sliding-Window Rule Evaluator Dispatch)
 * Mục đích: Truy vấn tập sự kiện kiểm toán trong khoảng `[windowStart, now]` theo danh mục hành động chuẩn `@sda/contracts`
 *   cho từng quy tắc (`MASS_DOWNLOAD`, `REPEATED_DENIED`, `OFF_HOURS_ACCESS`, `UNTRUSTED_CONTEXT`, `REFRESH_TOKEN_REUSE`,
 *   `AUDIT_INTEGRITY_COMPROMISED`), phân tách theo từng người dùng (`actor_user_id`) và nhánh ẩn danh (`detected_user_id: null`).
 */
export async function evaluateDetectionRule(
  database: PrismaClient,
  rule: DetectionRuleConfig,
  now: Date,
  windowStart: Date,
  cooldownStart: Date,
): Promise<number> {
  if (rule.ruleCode === 'MASS_DOWNLOAD') {
    const logs = await database.auditLog.findMany({
      where: {
        action: { in: [...SECURITY_DETECTION_ACTIONS.MASS_DOWNLOAD] },
        outcome: 'SUCCESS',
        occurred_at: { gte: windowStart, lte: now },
        actor_user_id: { not: null },
      },
      select: { id: true, actor_user_id: true, document_id: true, occurred_at: true },
    });
    return emitPerUserThresholdAlerts(database, rule, logs, now, cooldownStart, (count) => ({
      title: `Cảnh báo: Tải hàng loạt (${count} tài liệu)`,
      description: `Người dùng đã tải ${count} tài liệu trong ${rule.windowMinutes} phút (ngưỡng: ${rule.threshold}).`,
    }));
  }

  if (rule.ruleCode === 'REPEATED_DENIED') {
    const logs = await database.auditLog.findMany({
      where: {
        outcome: 'DENIED',
        occurred_at: { gte: windowStart, lte: now },
        actor_user_id: { not: null },
      },
      select: { id: true, actor_user_id: true, occurred_at: true },
    });
    return emitPerUserThresholdAlerts(database, rule, logs, now, cooldownStart, (count) => ({
      title: `Cảnh báo: Từ chối truy cập liên tiếp (${count} lần)`,
      description: `Người dùng nhận ${count} lần từ chối truy cập trong ${rule.windowMinutes} phút (ngưỡng: ${rule.threshold}).`,
    }));
  }

  if (rule.ruleCode === 'OFF_HOURS_ACCESS') {
    const logs = await database.auditLog.findMany({
      where: {
        action: { in: [...SECURITY_DETECTION_ACTIONS.OFF_HOURS_ACCESS] },
        occurred_at: { gte: windowStart, lte: now },
        actor_user_id: { not: null },
      },
      select: { id: true, actor_user_id: true, occurred_at: true },
    });
    const offHoursLogs = logs.filter((l) => isOffHoursTimestampUtc(l.occurred_at, rule.parameters));
    return emitPerUserThresholdAlerts(
      database,
      rule,
      offHoursLogs,
      now,
      cooldownStart,
      (count) => ({
        title: 'Cảnh báo: Truy cập ngoài giờ quy định',
        description: `Phát hiện ${count} hành động ngoài khung giờ cho phép trong ${rule.windowMinutes} phút.`,
      }),
    );
  }

  if (rule.ruleCode === 'UNTRUSTED_CONTEXT') {
    // CONFLICT-RESOLVED: Kết hợp kiểm tra cờ telemetry (isUntrustedAuditEvent) và đánh giá độc lập theo từng người dùng + luồng ẩn danh đồng bộ với API.
    const candidateLogs = await database.auditLog.findMany({
      where: {
        occurred_at: { gte: windowStart, lte: now },
        OR: [
          { action: { in: [...SECURITY_DETECTION_ACTIONS.UNTRUSTED_CONTEXT] } },
          { details: { path: ['untrustedContext'], equals: true } },
          { details: { path: ['untrustedIp'], equals: true } },
          { details: { path: ['untrustedDevice'], equals: true } },
        ],
      },
      select: { id: true, actor_user_id: true, action: true, details: true, occurred_at: true },
    });
    const untrustedLogs = candidateLogs.filter((l) => isUntrustedAuditEvent(l.action, l.details));
    return emitPerUserThresholdAlerts(
      database,
      rule,
      untrustedLogs,
      now,
      cooldownStart,
      (count, uid) => ({
        title: `Cảnh báo: Bối cảnh truy cập chưa tin cậy (Người dùng #${uid.toString()})`,
        description: `Phát hiện ${count} truy cập từ IP hoặc thiết bị chưa tin cậy bởi người dùng #${uid.toString()}.`,
      }),
      (count) => ({
        title: 'Cảnh báo: Bối cảnh truy cập ẩn danh chưa tin cậy',
        description: `Phát hiện ${count} truy cập chưa định danh từ IP hoặc thiết bị chưa tin cậy.`,
      }),
    );
  }

  if (rule.ruleCode === 'REFRESH_TOKEN_REUSE') {
    const logs = await database.auditLog.findMany({
      where: {
        action: { in: [...SECURITY_DETECTION_ACTIONS.REFRESH_TOKEN_REUSE] },
        occurred_at: { gte: windowStart, lte: now },
      },
      select: { id: true, actor_user_id: true, occurred_at: true },
    });
    return emitPerUserThresholdAlerts(
      database,
      rule,
      logs,
      now,
      cooldownStart,
      (_count, uid) => ({
        title: `Cảnh báo nghiêm trọng: Tái sử dụng Refresh Token (Người dùng #${uid.toString()})`,
        description: `Phát hiện nỗ lực sử dụng lại Refresh Token đã thu hồi trên tài khoản #${uid.toString()}. Phiên làm việc bị vô hiệu hóa.`,
      }),
      (count) => ({
        title: 'Cảnh báo nghiêm trọng: Tái sử dụng Refresh Token',
        description: `Phát hiện ${count} nỗ lực sử dụng lại Refresh Token đã thu hồi.`,
      }),
    );
  }

  if (rule.ruleCode === 'AUDIT_INTEGRITY_COMPROMISED') {
    const logs = await database.auditLog.findMany({
      where: {
        action: { in: [...SECURITY_DETECTION_ACTIONS.AUDIT_INTEGRITY_COMPROMISED] },
        occurred_at: { gte: windowStart, lte: now },
      },
      select: { id: true, actor_user_id: true, occurred_at: true },
    });
    return emitAggregateThresholdAlert(
      database,
      rule,
      logs,
      now,
      cooldownStart,
      'Cảnh báo khẩn cấp: Vi phạm tính toàn vẹn Audit Log',
      'Hệ thống xác minh phát hiện chuỗi băm audit log không khớp hoặc có dấu hiệu can thiệp trái phép.',
    );
  }

  return 0;
}

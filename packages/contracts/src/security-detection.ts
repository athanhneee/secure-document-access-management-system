// CONFLICT-RESOLVED: Hợp nhất đặc tả 6 quy tắc phát hiện xâm nhập SOC (ngưỡng, cửa sổ thời gian, mức nghiêm trọng, giảm chấn cooldown và danh sách tên sự kiện audit_logs.action) làm nguồn chân lý duy nhất dùng chung cho cả API (security-detection.service.ts) và Worker (security-detection-job.ts), khớp với seed CSDL detection_rule_configs.

export type SecurityDetectionSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type SecurityDetectionRuleCode =
  | 'MASS_DOWNLOAD'
  | 'REPEATED_DENIED'
  | 'OFF_HOURS_ACCESS'
  | 'UNTRUSTED_CONTEXT'
  | 'REFRESH_TOKEN_REUSE'
  | 'AUDIT_INTEGRITY_COMPROMISED';

export interface SecurityDetectionRuleSpec {
  ruleCode: SecurityDetectionRuleCode | string;
  name: string;
  description: string;
  isEnabled: boolean;
  severity: SecurityDetectionSeverity;
  threshold: number;
  windowMinutes: number;
  cooldownMinutes: number;
  parameters: Record<string, unknown>;
}

// CONFLICT-RESOLVED: Chuẩn hóa danh mục tên sự kiện audit_logs.action bao phủ cả các mã phát sinh thực tế tại AuthService/DocumentService/AuditVerifier (như REFRESH_REUSE, DOCUMENT_CONTENT_DOWNLOADED, AUDIT_HMAC_MISMATCH) lẫn các biến thể tương thích ngược giữa API và Worker.
export const SECURITY_DETECTION_ACTIONS = {
  MASS_DOWNLOAD: [
    'DOCUMENT_DOWNLOADED',
    'DOCUMENT_CONTENT_DOWNLOADED',
    'DOCUMENT_DOWNLOAD',
  ] as const,
  OFF_HOURS_ACCESS: [
    'DOCUMENT_DOWNLOADED',
    'DOCUMENT_CONTENT_DOWNLOADED',
    'DOCUMENT_VIEWED',
    'DOCUMENT_PREVIEWED',
    'ACCESS_PERMITTED',
  ] as const,
  UNTRUSTED_CONTEXT: [
    'UNTRUSTED_CONTEXT_DETECTED',
    'LOGIN_UNTRUSTED_DEVICE',
    'ACCESS_DENIED_UNTRUSTED_IP',
  ] as const,
  REFRESH_TOKEN_REUSE: [
    'REFRESH_REUSE',
    'REFRESH_TOKEN_REUSE',
    'REFRESH_TOKEN_REUSED',
    'TOKEN_REVOCATION_TRIGGERED',
  ] as const,
  AUDIT_INTEGRITY_COMPROMISED: [
    'AUDIT_INTEGRITY_COMPROMISED',
    'AUDIT_INTEGRITY_VERIFICATION_FAILED',
    'AUDIT_CHAIN_BROKEN',
    'AUDIT_LOG_TAMPERED',
    'AUDIT_HMAC_MISMATCH',
  ] as const,
} as const;

// CONFLICT-RESOLVED: Thống nhất ngưỡng đếm, độ rộng cửa sổ quan sát (windowMinutes), thời gian giảm chấn (cooldownMinutes) và mức độ nghiêm trọng mặc định giữa API và Worker theo chuẩn migration CSDL detection_rule_configs.
export const DEFAULT_SECURITY_DETECTION_RULES: readonly SecurityDetectionRuleSpec[] = [
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
] as const;

/**
 * Algorithm: Defensive Deep-Copy of Baseline Detection Rules.
 * Clones each immutable rule specification and its `parameters` map so callers can safely
 * apply transient overrides without mutating the shared baseline singleton.
 */
export function cloneDefaultSecurityDetectionRules(): SecurityDetectionRuleSpec[] {
  return DEFAULT_SECURITY_DETECTION_RULES.map((rule) => ({
    ...rule,
    parameters: { ...rule.parameters },
  }));
}

/**
 * Algorithm: Bounded UTC Business-Hour Window Normalization.
 * Clamps arbitrary `startHourUtc` and `endHourUtc` rule parameters into valid `[0, 23]` hour
 * bounds, defaulting to `[0, 11]` UTC (`07:00`–`18:59` ICT / UTC+7).
 */
export function resolveBusinessHoursUtc(parameters?: Record<string, unknown> | null): {
  startHourUtc: number;
  endHourUtc: number;
} {
  const rawStart = Number(parameters?.['startHourUtc'] ?? 0);
  const rawEnd = Number(parameters?.['endHourUtc'] ?? 11);
  const startHourUtc = Number.isFinite(rawStart)
    ? Math.min(Math.max(Math.trunc(rawStart), 0), 23)
    : 0;
  const endHourUtc = Number.isFinite(rawEnd) ? Math.min(Math.max(Math.trunc(rawEnd), 0), 23) : 11;
  return { startHourUtc, endHourUtc };
}

/**
 * Algorithm: Wrap-Around UTC Off-Hours & Weekend Temporal Classifier.
 * Evaluates whether `occurredAt` falls on a UTC weekend (`Saturday`/`Sunday`) or outside the
 * inclusive `[startHourUtc, endHourUtc]` business interval (handling midnight-crossing windows).
 */
export function isOffHoursTimestampUtc(
  occurredAt: Date | string,
  parameters?: Record<string, unknown> | null,
): boolean {
  const timestamp = occurredAt instanceof Date ? occurredAt : new Date(occurredAt);
  const day = timestamp.getUTCDay();
  if (day === 0 || day === 6) {
    return true;
  }
  const hour = timestamp.getUTCHours();
  const { startHourUtc, endHourUtc } = resolveBusinessHoursUtc(parameters);
  return startHourUtc <= endHourUtc
    ? hour < startHourUtc || hour > endHourUtc
    : hour < startHourUtc && hour > endHourUtc;
}

const UNTRUSTED_ACTION_SET: ReadonlySet<string> = new Set(
  SECURITY_DETECTION_ACTIONS.UNTRUSTED_CONTEXT,
);

/**
 * Algorithm: Hybrid Action-and-Attribute Untrusted Context Predicate.
 * Detects untrusted access contexts either by explicit SOC audit action codes or by structured
 * boolean telemetry flags (`untrustedContext`, `untrustedIp`, `untrustedDevice`) inside `details`.
 */
export function isUntrustedAuditEvent(action?: string | null, details?: unknown): boolean {
  if (typeof action === 'string' && UNTRUSTED_ACTION_SET.has(action)) {
    return true;
  }
  if (details !== null && typeof details === 'object' && !Array.isArray(details)) {
    const record = details as Record<string, unknown>;
    return (
      record['untrustedContext'] === true ||
      record['untrustedIp'] === true ||
      record['untrustedDevice'] === true
    );
  }
  return false;
}

/**
 * Algorithm: Single-Pass Principal Frequency Bucketing.
 * Partitions audit log records by `actor_user_id` in O(N) time while discarding system rows
 * without an actor principal (`null`/`undefined`).
 */
export function groupAuditLogsByActor<T extends { actor_user_id?: bigint | null }>(
  logs: readonly T[],
): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const log of logs) {
    if (log.actor_user_id == null) continue;
    const key = log.actor_user_id.toString();
    const bucket = groups.get(key);
    if (bucket) {
      bucket.push(log);
    } else {
      groups.set(key, [log]);
    }
  }
  return groups;
}

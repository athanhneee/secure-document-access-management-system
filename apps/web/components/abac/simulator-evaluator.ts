import type {
  ExpectedValue,
  TargetAction,
  TimeWindow,
  VisualCondition,
  VisualObligation,
  VisualPolicyRule,
} from './abac-models';
import { canonicalizeIpAddress, simulatorCidrMatch } from './cidr-matcher';
import {
  buildSimulationPreset,
  type SimulationConditionResult,
  type SimulationEnvironment,
  type SimulationGroupEvaluation,
  type SimulationPresetName,
  type SimulationResource,
  type SimulationResult,
  type SimulationRuleEvaluation,
  type SimulationSubject,
} from './simulator-presets';

export {
  buildSimulationPreset,
  type SimulationConditionResult,
  type SimulationEnvironment,
  type SimulationGroupEvaluation,
  type SimulationPresetName,
  type SimulationResource,
  type SimulationResult,
  type SimulationRuleEvaluation,
  type SimulationSubject,
};

type RuntimeValue = string | number | boolean | string[] | null | undefined;

const OBLIGATION_ORDER: Readonly<Record<VisualObligation['type'], number>> = {
  REQUIRE_WATERMARK: 0,
  REQUIRE_MFA: 1,
  MAX_SESSION_MINUTES: 2,
  FORBID_DOWNLOAD: 3,
  NO_CACHE: 4,
};

export const STRICT_ISO_DATE_PATTERN =
  /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2}))?$/;

const CLOCK_ONLY_TIME_PATTERN = /^(\d{2}):(\d{2})(?::(\d{2}))?$/u;

function flattenSimulationContext(
  subject: SimulationSubject,
  resource: SimulationResource,
  environment: SimulationEnvironment,
): Record<string, RuntimeValue> {
  const resolvedCurrentTime =
    resolveSimulationDate(environment.currentTime)?.toISOString() ?? environment.currentTime;
  return {
    'subject.clearanceRank': subject.clearanceRank,
    'subject.departmentId': subject.departmentId,
    'subject.employmentStatus': subject.employmentStatus,
    'subject.projects': subject.projects,
    'resource.classificationRank': resource.classificationRank,
    'resource.departmentId': resource.departmentId,
    'resource.category': resource.category,
    'resource.status': resource.status,
    'resource.ownerId': resource.ownerId,
    'environment.currentTime': resolvedCurrentTime,
    'environment.ip': environment.ip,
    'environment.trustedNetwork': environment.trustedNetwork,
    'environment.deviceTrust': environment.deviceTrust,
    'environment.mfa': environment.mfa,
    'environment.riskScore': environment.riskScore,
  };
}

/**
 * Thuật toán: Kiểm tra thiếu vắng thuộc tính đồng bộ 1-1 với Backend (`isMissingAttribute`: `null`, `undefined`, hoặc mảng rỗng `[]`).
 */
export function isMissingAttribute(value: unknown): boolean {
  return value === null || value === undefined || (Array.isArray(value) && value.length === 0);
}

/**
 * Thuật toán: Phân tích chuỗi ngày giờ chuẩn ISO-8601 nghiêm ngặt có kiểm chứng lịch Gregorian thật chống cuộn ngày (VD: `2026-02-31`) (`MED-18`).
 */
export function parseStrictIsoTimestamp(value: string): number | null {
  if (!STRICT_ISO_DATE_PATTERN.test(value)) return null;
  const datePart = value.slice(0, 10);
  const [yStr, mStr, dStr] = datePart.split('-');
  const year = Number(yStr);
  const month = Number(mStr);
  const day = Number(dStr);
  const calendarCheck = new Date(Date.UTC(year, month - 1, day));
  if (
    calendarCheck.getUTCFullYear() !== year ||
    calendarCheck.getUTCMonth() !== month - 1 ||
    calendarCheck.getUTCDate() !== day
  ) {
    return null;
  }
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
}

/**
 * Thuật toán: Chuẩn hóa thời điểm giả lập từ chuỗi giờ `<input type="time">` (`HH:MM[:SS]`) hoặc chuỗi ISO-8601 đầy đủ sang đối tượng `Date`.
 * Ghép `HH:MM[:SS]` vào ngày hiện tại theo múi giờ máy trạm trước khi đối chiếu khung hiệu lực `[validFrom, validTo)` hoặc đổi sang `tw.timeZone` (BUG-039).
 */
export function resolveSimulationDate(raw: string): Date | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  const clockMatch = CLOCK_ONLY_TIME_PATTERN.exec(trimmed);
  if (clockMatch) {
    const hours = Number(clockMatch[1]);
    const minutes = Number(clockMatch[2]);
    const secs = Number(clockMatch[3] ?? '0');
    if (hours > 23 || minutes > 59 || secs > 59) return null;
    const now = new Date();
    return new Date(now.getFullYear(), now.getMonth(), now.getDate(), hours, minutes, secs, 0);
  }

  const strictIso = parseStrictIsoTimestamp(trimmed);
  if (strictIso !== null) {
    return new Date(strictIso);
  }

  const parsed = new Date(trimmed);
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

/**
 * Thuật toán: Kiểm tra khoảng hiệu lực thời gian nửa mở `[validFrom, validTo)` của quy tắc chính sách đồng bộ với `policy-engine.ts` (BUG-039).
 */
export function isRuleActiveAtTime(rule: VisualPolicyRule, nowMs: number): boolean {
  if (rule.validFrom !== undefined && rule.validFrom !== '') {
    const validFromMs = Date.parse(rule.validFrom);
    if (!Number.isFinite(validFromMs) || validFromMs > nowMs) {
      return false;
    }
  }
  if (rule.validTo !== null && rule.validTo !== undefined && rule.validTo !== '') {
    const validToMs = Date.parse(rule.validTo);
    if (!Number.isFinite(validToMs) || nowMs >= validToMs) {
      return false;
    }
  }
  return true;
}

/**
 * Thuật toán: Gộp Nghĩa Vụ Bảo Mật Theo Nguyên Lý Chặt Nhất Đồng Bộ Với PDP Máy Chủ (`mergeSimulationObligations`)
 * Khử trùng lặp bằng Set, lấy `Math.min` cho `MAX_SESSION_MINUTES` và sắp xếp thứ tự tất định.
 */
export function mergeSimulationObligations(
  obligations: readonly VisualObligation[],
): VisualObligation[] {
  const types = new Set(obligations.map((o) => o.type));
  const maxMinutes = obligations
    .filter(
      (o): o is Extract<VisualObligation, { type: 'MAX_SESSION_MINUTES' }> =>
        o.type === 'MAX_SESSION_MINUTES' && typeof o.minutes === 'number' && o.minutes > 0,
    )
    .map((o) => o.minutes);
  const merged: VisualObligation[] = [...types]
    .filter((type) => type !== 'MAX_SESSION_MINUTES')
    .map((type) => ({ type }) as VisualObligation);
  if (maxMinutes.length > 0) {
    merged.push({ type: 'MAX_SESSION_MINUTES', minutes: Math.min(...maxMinutes) });
  }
  return merged.sort((left, right) => OBLIGATION_ORDER[left.type] - OBLIGATION_ORDER[right.type]);
}

function evaluateRuleGroups(
  rule: VisualPolicyRule,
  flatAttributes: Record<string, RuntimeValue>,
): SimulationGroupEvaluation[] {
  return rule.groups.map((group) => {
    const conditionResults: SimulationConditionResult[] = group.conditions.map((cond) => {
      const actual = flatAttributes[cond.attribute];
      return {
        conditionId: cond.id,
        attribute: cond.attribute,
        operator: cond.operator,
        expected: cond.expected,
        actual,
        matched: evaluateCondition(cond, actual),
      };
    });
    return {
      groupId: group.id,
      satisfied: conditionResults.length > 0 && conditionResults.every((c) => c.matched),
      conditionResults,
    };
  });
}

function isRuleActionTargeted(ruleAction: TargetAction, requestedAction: TargetAction): boolean {
  return ruleAction === 'ALL' || requestedAction === 'ALL' || ruleAction === requestedAction;
}

function compareRuleIds(left: string, right: string): number {
  try {
    const a = BigInt(left);
    const b = BigInt(right);
    return a < b ? -1 : a > b ? 1 : 0;
  } catch {
    return left.localeCompare(right);
  }
}

/**
 * Thuật toán: Bộ Đánh Giá Quy Tắc Đơn Lẻ Có Bất Biến Bell-LaPadula, Khung Hiệu Lực `[validFrom, validTo)` & Step-Up MFA (`evaluatePolicySimulation`)
 */
export function evaluatePolicySimulation(
  activeRule: VisualPolicyRule,
  action: TargetAction,
  subject: SimulationSubject,
  resource: SimulationResource,
  environment: SimulationEnvironment,
): SimulationResult {
  if (subject.clearanceRank === null || resource.classificationRank === null) {
    return {
      decision: 'DENY',
      reasonCode: 'MISSING_REQUIRED_ATTRIBUTE',
      matchedRuleCodes: [],
      obligations: [],
      groupEvaluations: [],
    };
  }

  // Bắt buộc kiểm tra bất biến Bell-LaPadula Simple Security Property đồng bộ tuyệt đối với PDP máy chủ.
  if (subject.clearanceRank < resource.classificationRank) {
    return {
      decision: 'DENY',
      reasonCode: 'INSUFFICIENT_CLEARANCE',
      matchedRuleCodes: [],
      obligations: [],
      groupEvaluations: [],
      bellLaPadulaBlocked: true,
    };
  }

  const simDate = resolveSimulationDate(environment.currentTime);
  if (!simDate) {
    return {
      decision: 'DENY',
      reasonCode: 'MISSING_REQUIRED_ATTRIBUTE',
      matchedRuleCodes: [],
      obligations: [],
      groupEvaluations: [],
    };
  }

  if (
    activeRule.targetResource !== 'DOCUMENT' ||
    !isRuleActionTargeted(activeRule.targetAction, action)
  ) {
    return {
      decision: 'DENY',
      reasonCode: 'ACTION_NOT_TARGETED',
      matchedRuleCodes: [],
      obligations: [],
      groupEvaluations: [],
    };
  }

  if (!isRuleActiveAtTime(activeRule, simDate.getTime())) {
    return {
      decision: 'DENY',
      reasonCode: 'DEFAULT_DENY_NO_GROUP_MATCH',
      matchedRuleCodes: [],
      obligations: [],
      groupEvaluations: [],
    };
  }

  const flatAttributes = flattenSimulationContext(subject, resource, environment);
  const groupEvaluations = evaluateRuleGroups(activeRule, flatAttributes);

  if (!groupEvaluations.some((g) => g.satisfied)) {
    return {
      decision: 'DENY',
      reasonCode: 'DEFAULT_DENY_NO_GROUP_MATCH',
      matchedRuleCodes: [],
      obligations: [],
      groupEvaluations,
    };
  }

  if (activeRule.effect === 'PERMIT') {
    return {
      decision: 'PERMIT',
      reasonCode: 'RULE_PERMIT_MATCHED',
      matchedRuleCodes: [activeRule.code],
      obligations: mergeSimulationObligations(activeRule.obligations),
      groupEvaluations,
    };
  }

  const stepUpMfa =
    !environment.mfa && activeRule.obligations.some((ob) => ob.type === 'REQUIRE_MFA');
  return {
    decision: 'DENY',
    reasonCode: stepUpMfa ? 'STEP_UP_MFA_REQUIRED' : 'EXPLICIT_DENY_RULE_MATCHED',
    matchedRuleCodes: [activeRule.code],
    obligations: [],
    groupEvaluations,
  };
}

/**
 * Thuật toán: Bộ Đánh Giá Toàn Bộ Tập Chính Sách CSDL Theo Chuẩn PDP XACML `DENY_OVERRIDES` (`evaluatePolicySetSimulation`)
 */
export function evaluatePolicySetSimulation(
  rules: readonly VisualPolicyRule[],
  action: TargetAction,
  subject: SimulationSubject,
  resource: SimulationResource,
  environment: SimulationEnvironment,
): SimulationResult {
  if (subject.clearanceRank === null || resource.classificationRank === null) {
    return {
      decision: 'DENY',
      reasonCode: 'MISSING_REQUIRED_ATTRIBUTE',
      matchedRuleCodes: [],
      obligations: [],
      groupEvaluations: [],
      ruleEvaluations: [],
    };
  }

  if (subject.clearanceRank < resource.classificationRank) {
    return {
      decision: 'DENY',
      reasonCode: 'INSUFFICIENT_CLEARANCE',
      matchedRuleCodes: [],
      obligations: [],
      groupEvaluations: [],
      ruleEvaluations: [],
      bellLaPadulaBlocked: true,
    };
  }

  const simDate = resolveSimulationDate(environment.currentTime);
  if (!simDate) {
    return {
      decision: 'DENY',
      reasonCode: 'MISSING_REQUIRED_ATTRIBUTE',
      matchedRuleCodes: [],
      obligations: [],
      groupEvaluations: [],
      ruleEvaluations: [],
    };
  }
  const nowMs = simDate.getTime();

  const flatAttributes = flattenSimulationContext(subject, resource, environment);
  const sortedRules = [...rules].sort(
    (left, right) =>
      left.priority - right.priority ||
      compareRuleIds(left.id ?? left.code, right.id ?? right.code),
  );

  const ruleEvaluations: SimulationRuleEvaluation[] = sortedRules.map((rule) => {
    const actionTargeted =
      rule.targetResource === 'DOCUMENT' && isRuleActionTargeted(rule.targetAction, action);
    const temporallyActive = isRuleActiveAtTime(rule, nowMs);
    const groupEvaluations =
      actionTargeted && temporallyActive ? evaluateRuleGroups(rule, flatAttributes) : [];
    const matched = actionTargeted && temporallyActive && groupEvaluations.some((g) => g.satisfied);
    return {
      ruleId: rule.id ?? rule.code,
      ruleCode: rule.code,
      ruleName: rule.name,
      effect: rule.effect,
      priority: rule.priority,
      targetAction: rule.targetAction,
      actionTargeted,
      matched,
      groupEvaluations,
    };
  });

  const matchedPairs = sortedRules
    .map((rule, idx) => ({ rule, evalRow: ruleEvaluations[idx]! }))
    .filter((entry) => entry.evalRow.matched);
  const matchedRuleCodes = matchedPairs.map((entry) => entry.rule.code);
  const matchedDenyRules = matchedPairs.filter((entry) => entry.rule.effect === 'DENY');

  if (matchedDenyRules.length > 0) {
    const canResolveWithStepUpMfa =
      !environment.mfa &&
      matchedDenyRules.every((entry) =>
        entry.rule.obligations.some((ob) => ob.type === 'REQUIRE_MFA'),
      );
    return {
      decision: 'DENY',
      reasonCode: canResolveWithStepUpMfa ? 'STEP_UP_MFA_REQUIRED' : 'EXPLICIT_DENY',
      matchedRuleCodes,
      obligations: [],
      groupEvaluations: [],
      ruleEvaluations,
    };
  }

  const matchedPermitRules = matchedPairs.filter((entry) => entry.rule.effect === 'PERMIT');
  if (matchedPermitRules.length === 0) {
    return {
      decision: 'DENY',
      reasonCode: 'DEFAULT_DENY',
      matchedRuleCodes: [],
      obligations: [],
      groupEvaluations: [],
      ruleEvaluations,
    };
  }

  return {
    decision: 'PERMIT',
    reasonCode: 'POLICY_PERMIT',
    matchedRuleCodes,
    obligations: mergeSimulationObligations(
      matchedPermitRules.flatMap((entry) => entry.rule.obligations),
    ),
    groupEvaluations: [],
    ruleEvaluations,
  };
}

function equal(actual: unknown, expected: ExpectedValue): boolean {
  if (typeof actual === 'string' && typeof expected === 'string') {
    if (actual === expected) return true;
    const leftIp = canonicalizeIpAddress(actual);
    const rightIp = canonicalizeIpAddress(expected);
    if (leftIp !== null && rightIp !== null) {
      return leftIp === rightIp;
    }
    const leftTs = parseStrictIsoTimestamp(actual);
    const rightTs = parseStrictIsoTimestamp(expected);
    if (leftTs !== null && rightTs !== null) {
      return leftTs === rightTs;
    }
    return false;
  }
  return (typeof actual === 'number' || typeof actual === 'boolean') && actual === expected;
}

function comparable(value: unknown): string | number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value !== 'string') return null;
  const timestamp = parseStrictIsoTimestamp(value);
  return timestamp !== null ? timestamp : value;
}

function compare(actual: unknown, expected: unknown): number {
  const left = comparable(actual);
  const right = comparable(expected);
  if (left === null || right === null || typeof left !== typeof right) return Number.NaN;
  if (typeof left === 'number' && typeof right === 'number') return left - right;
  return String(left).localeCompare(String(right));
}

function matchArray(cond: VisualCondition, actual: unknown[]): boolean {
  if (cond.operator === 'EQ') return actual.some((item) => equal(item, cond.expected));
  if (cond.operator === 'NEQ') return actual.every((item) => !equal(item, cond.expected));
  const expected = cond.expected;
  if (cond.operator === 'IN' && Array.isArray(expected)) {
    return actual.some((item) => expected.some((candidate) => equal(item, candidate)));
  }
  if (cond.operator === 'NOT_IN' && Array.isArray(expected)) {
    return actual.every((item) => expected.every((candidate) => !equal(item, candidate)));
  }
  return false;
}

function seconds(value: string): number {
  const [hours = 0, minutes = 0, secs = 0] = value.split(':').map(Number);
  return hours * 3600 + minutes * 60 + secs;
}

function timeBetween(value: string, window: TimeWindow): boolean {
  const date = resolveSimulationDate(value);
  if (!date) return false;
  try {
    const formatter = new Intl.DateTimeFormat('en-GB', {
      timeZone: window.timeZone,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23',
    });
    const parts = Object.fromEntries(
      formatter
        .formatToParts(date)
        .filter((part) => part.type !== 'literal')
        .map((part) => [part.type, Number(part.value)]),
    );
    const current =
      (parts['hour'] ?? 0) * 3600 + (parts['minute'] ?? 0) * 60 + (parts['second'] ?? 0);
    const start = seconds(window.start);
    const end = seconds(window.end);
    return start <= end ? current >= start && current <= end : current >= start || current <= end;
  } catch {
    return false;
  }
}

function evaluateCondition(cond: VisualCondition, actual: unknown): boolean {
  const exists = !isMissingAttribute(actual);
  if (cond.operator === 'EXISTS') {
    return exists === Boolean(cond.expected);
  }
  if (!exists) return false;
  if (Array.isArray(actual)) return matchArray(cond, actual);

  switch (cond.operator) {
    case 'EQ':
      return equal(actual, cond.expected);
    case 'NEQ':
      return !equal(actual, cond.expected);
    case 'IN':
      return Array.isArray(cond.expected) && cond.expected.some((item) => equal(actual, item));
    case 'NOT_IN':
      return Array.isArray(cond.expected) && cond.expected.every((item) => !equal(actual, item));
    case 'GTE':
      return compare(actual, cond.expected) >= 0;
    case 'LTE':
      return compare(actual, cond.expected) <= 0;
    case 'BETWEEN':
      return (
        Array.isArray(cond.expected) &&
        cond.expected.length === 2 &&
        compare(actual, cond.expected[0]) >= 0 &&
        compare(actual, cond.expected[1]) <= 0
      );
    case 'TIME_BETWEEN':
      return (
        typeof actual === 'string' &&
        typeof cond.expected === 'object' &&
        cond.expected !== null &&
        !Array.isArray(cond.expected) &&
        timeBetween(actual, cond.expected as TimeWindow)
      );
    case 'CIDR_MATCH':
      if (typeof actual !== 'string') return false;
      if (typeof cond.expected === 'string') return simulatorCidrMatch(actual, cond.expected);
      if (Array.isArray(cond.expected)) {
        return cond.expected.some(
          (cidr) => typeof cidr === 'string' && simulatorCidrMatch(actual, cidr),
        );
      }
      return false;
    default:
      return false;
  }
}

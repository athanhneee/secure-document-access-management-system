import type {
  TargetAction,
  TimeWindow,
  VisualCondition,
  VisualObligation,
  VisualPolicyRule,
} from './abac-models';
import { simulatorCidrMatch } from './cidr-matcher';
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

const OBLIGATION_ORDER: Readonly<Record<VisualObligation['type'], number>> = {
  REQUIRE_WATERMARK: 0,
  REQUIRE_MFA: 1,
  MAX_SESSION_MINUTES: 2,
  FORBID_DOWNLOAD: 3,
  NO_CACHE: 4,
};

function flattenSimulationContext(
  subject: SimulationSubject,
  resource: SimulationResource,
  environment: SimulationEnvironment,
): Record<string, unknown> {
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
    'environment.currentTime': environment.currentTime,
    'environment.ip': environment.ip,
    'environment.trustedNetwork': environment.trustedNetwork,
    'environment.deviceTrust': environment.deviceTrust,
    'environment.mfa': environment.mfa,
    'environment.riskScore': environment.riskScore,
  };
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
  flatAttributes: Record<string, unknown>,
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

/**
 * Thuật toán: Bộ Đánh Giá Quy Tắc Đơn Lẻ Có Bất Biến Bell-LaPadula & Step-Up MFA (`evaluatePolicySimulation`)
 * Mục đích: Xác định quyết định cấp quyền (`PERMIT` / `DENY`), chặn cứng Bell-LaPadula (`clearanceRank < classificationRank`),
 * nhận diện `STEP_UP_MFA_REQUIRED` trên luật `DENY` mang nghĩa vụ `REQUIRE_MFA` và xuất vết từng nhánh DNF.
 */
export function evaluatePolicySimulation(
  activeRule: VisualPolicyRule,
  action: TargetAction,
  subject: SimulationSubject,
  resource: SimulationResource,
  environment: SimulationEnvironment,
): SimulationResult {
  // CONFLICT-RESOLVED: Bắt buộc kiểm tra bất biến Bell-LaPadula Simple Security Property đồng bộ tuyệt đối với PDP máy chủ.
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

  if (!isRuleActionTargeted(activeRule.targetAction, action)) {
    return {
      decision: 'DENY',
      reasonCode: 'ACTION_NOT_TARGETED',
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
 * Cơ chế hoạt động:
 *   1. Kiểm tra bất biến độ mật Bell-LaPadula (`subject.clearanceRank >= resource.classificationRank`).
 *   2. Sắp xếp tập luật đang kích hoạt theo `(priority ASC, code ASC)` và đánh giá DNF cho từng luật.
 *   3. Áp dụng `DENY_OVERRIDES`: mọi luật `DENY` khớp thắng tuyệt đối (trả `STEP_UP_MFA_REQUIRED` nếu toàn bộ luật `DENY` khớp chỉ đòi MFA khi phiên chưa có MFA); nếu không có luật `PERMIT` khớp thì trả `DEFAULT_DENY`; ngược lại gộp nghĩa vụ chặt nhất.
 */
export function evaluatePolicySetSimulation(
  rules: readonly VisualPolicyRule[],
  action: TargetAction,
  subject: SimulationSubject,
  resource: SimulationResource,
  environment: SimulationEnvironment,
): SimulationResult {
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

  const flatAttributes = flattenSimulationContext(subject, resource, environment);
  const sortedRules = [...rules].sort(
    (left, right) => left.priority - right.priority || left.code.localeCompare(right.code),
  );

  const ruleEvaluations: SimulationRuleEvaluation[] = sortedRules.map((rule) => {
    const actionTargeted = isRuleActionTargeted(rule.targetAction, action);
    const groupEvaluations = actionTargeted ? evaluateRuleGroups(rule, flatAttributes) : [];
    const matched = actionTargeted && groupEvaluations.some((g) => g.satisfied);
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

const STRICT_ISO_DATE_PATTERN =
  /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2}))?$/;

function toComparableScalar(value: unknown): number | string | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value !== 'string') return null;
  if (STRICT_ISO_DATE_PATTERN.test(value)) {
    const ts = Date.parse(value);
    return Number.isFinite(ts) ? ts : null;
  }
  return value;
}

function compareScalars(leftRaw: unknown, rightRaw: unknown): number {
  const left = toComparableScalar(leftRaw);
  const right = toComparableScalar(rightRaw);
  if (left === null || right === null || typeof left !== typeof right) return Number.NaN;
  if (typeof left === 'number' && typeof right === 'number') return left - right;
  return String(left).localeCompare(String(right));
}

function isSetMemberNormalized(candidate: unknown, expectedSet: unknown[]): boolean {
  return expectedSet.some((item) => {
    if (item === candidate) return true;
    if (typeof item === 'number' || typeof candidate === 'number') {
      const leftStr = String(candidate).trim();
      const rightStr = String(item).trim();
      if (!leftStr || !rightStr) return false;
      const leftNum = Number(leftStr);
      const rightNum = Number(rightStr);
      return Number.isFinite(leftNum) && Number.isFinite(rightNum) && leftNum === rightNum;
    }
    return false;
  });
}

function extractClockTime(raw: string, timeZone?: string): string {
  if (/^\d{2}:\d{2}(?::\d{2})?$/u.test(raw)) return raw;
  const parsed = Date.parse(raw);
  if (!Number.isFinite(parsed)) return raw;
  try {
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: timeZone || 'Asia/Ho_Chi_Minh',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).format(new Date(parsed));
  } catch {
    return raw;
  }
}

function evaluateCondition(cond: VisualCondition, actual: unknown): boolean {
  if (cond.operator === 'EXISTS') {
    const exists =
      actual !== undefined &&
      actual !== null &&
      actual !== '' &&
      (!Array.isArray(actual) || actual.length > 0);
    return exists === Boolean(cond.expected);
  }
  if (actual === undefined || actual === null) return false;

  switch (cond.operator) {
    case 'EQ':
      return actual === cond.expected;
    case 'NEQ':
      return actual !== cond.expected;
    case 'GTE':
      return compareScalars(actual, cond.expected) >= 0;
    case 'LTE':
      return compareScalars(actual, cond.expected) <= 0;
    case 'BETWEEN':
      if (Array.isArray(cond.expected) && cond.expected.length === 2) {
        return (
          compareScalars(actual, cond.expected[0]) >= 0 &&
          compareScalars(actual, cond.expected[1]) <= 0
        );
      }
      return false;
    case 'IN':
      if (!Array.isArray(cond.expected)) return false;
      return Array.isArray(actual)
        ? actual.some((a) => isSetMemberNormalized(a, cond.expected as unknown[]))
        : isSetMemberNormalized(actual, cond.expected as unknown[]);
    case 'NOT_IN':
      if (!Array.isArray(cond.expected)) return false;
      return Array.isArray(actual)
        ? !actual.some((a) => isSetMemberNormalized(a, cond.expected as unknown[]))
        : !isSetMemberNormalized(actual, cond.expected as unknown[]);
    case 'TIME_BETWEEN':
      if (typeof cond.expected === 'object' && cond.expected !== null) {
        const tw = cond.expected as TimeWindow;
        const current = extractClockTime(String(actual), tw.timeZone);
        const start = tw.start.slice(0, 5);
        const end = tw.end.slice(0, 5);
        const cmpCurrent = current.slice(0, 5);
        return start <= end
          ? cmpCurrent >= start && cmpCurrent <= end
          : cmpCurrent >= start || cmpCurrent <= end;
      }
      return false;
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

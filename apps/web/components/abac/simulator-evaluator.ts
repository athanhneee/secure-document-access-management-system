import type { TargetAction, TimeWindow, VisualCondition, VisualPolicyRule } from './abac-models';
import { simulatorCidrMatch } from './cidr-matcher';
import {
  buildSimulationPreset,
  type SimulationEnvironment,
  type SimulationPresetName,
  type SimulationResource,
  type SimulationResult,
  type SimulationSubject,
} from './simulator-presets';

export {
  buildSimulationPreset,
  type SimulationEnvironment,
  type SimulationPresetName,
  type SimulationResource,
  type SimulationResult,
  type SimulationSubject,
};

/**
 * Thuật toán: Bộ Đánh Giá Biểu Thức Chính Sách DNF & Chuẩn Hóa Tập Hợp Số `IN` / `NOT_IN` (`evaluatePolicySimulation`)
 * Mục đích: Xác định quyết định cấp quyền (`PERMIT` / `DENY`), mã lý do (`reasonCode`), vết đánh giá từng nhánh logic và nghĩa vụ đi kèm.
 * Cơ chế hoạt động:
 *   - Phẳng hóa không gian thuộc tính `(subject, resource, environment)` sang bảng tra cứu khóa phẳng `O(1)` và kiểm tra phạm vi `targetAction`.
 *   - Duyệt cấu trúc DNF độ phức tạp `O(G * C)` với chuẩn hóa tương đương số học/chuỗi số trong toán tử tập hợp `IN` / `NOT_IN` để `clearance_rank IN [3, 4]` luôn đánh giá chính xác.
 */
export function evaluatePolicySimulation(
  activeRule: VisualPolicyRule,
  action: TargetAction,
  subject: SimulationSubject,
  resource: SimulationResource,
  environment: SimulationEnvironment,
): SimulationResult {
  const flatAttributes: Record<string, unknown> = {
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

  if (activeRule.targetAction !== 'ALL' && activeRule.targetAction !== action) {
    return {
      decision: 'DENY',
      reasonCode: 'ACTION_NOT_TARGETED',
      matchedRuleCodes: [],
      obligations: [],
      groupEvaluations: [],
    };
  }

  const groupEvaluations = activeRule.groups.map((group) => {
    const conditionResults = group.conditions.map((cond) => {
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

  if (!groupEvaluations.some((g) => g.satisfied)) {
    return {
      decision: 'DENY',
      reasonCode: 'DEFAULT_DENY_NO_GROUP_MATCH',
      matchedRuleCodes: [],
      obligations: [],
      groupEvaluations,
    };
  }

  return activeRule.effect === 'PERMIT'
    ? {
        decision: 'PERMIT',
        reasonCode: 'RULE_PERMIT_MATCHED',
        matchedRuleCodes: [activeRule.code],
        obligations: activeRule.obligations,
        groupEvaluations,
      }
    : {
        decision: 'DENY',
        reasonCode: 'EXPLICIT_DENY_RULE_MATCHED',
        matchedRuleCodes: [activeRule.code],
        obligations: activeRule.obligations,
        groupEvaluations,
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

function evaluateCondition(cond: VisualCondition, actual: unknown): boolean {
  if (cond.operator === 'EXISTS') return actual !== undefined && actual !== null && actual !== '';
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
        const current = String(actual);
        return tw.start <= tw.end
          ? current >= tw.start && current <= tw.end
          : current >= tw.start || current <= tw.end;
      }
      return false;
    case 'CIDR_MATCH':
      if (typeof cond.expected === 'string' && typeof actual === 'string') {
        return simulatorCidrMatch(actual, cond.expected);
      }
      return false;
    default:
      return false;
  }
}

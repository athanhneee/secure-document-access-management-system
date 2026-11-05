/**
 * @module PolicyValidator
 * Algorithm: Static DNF Policy Type-Checker & Unreachable Rule Analyzer.
 * Bộ phân tích ngữ nghĩa tĩnh và phát hiện luật chết chính sách ABAC.
 */
import { POLICY_OPERATORS, type AttributeDescriptor } from './abac.types.js';
import type {
  CompiledPolicy,
  ExpectedValue,
  PolicyCondition,
  PolicyOperator,
  PolicyValidationIssue,
  TimeWindow,
} from './abac.types.js';
import { isValidCidr } from './cidr.js';
import { parseStrictIsoTimestamp } from './policy-condition-matcher.js';
import { compareExpectedValues, hasContradiction } from './policy-contradiction-solver.js';

const compatibleOperators: Readonly<
  Record<AttributeDescriptor['type'], ReadonlySet<PolicyOperator>>
> = {
  STRING: new Set(['EQ', 'NEQ', 'IN', 'NOT_IN', 'EXISTS']),
  NUMBER: new Set(['EQ', 'NEQ', 'IN', 'NOT_IN', 'GTE', 'LTE', 'BETWEEN', 'EXISTS']),
  BOOLEAN: new Set(['EQ', 'NEQ', 'EXISTS']),
  DATE: new Set(['EQ', 'NEQ', 'GTE', 'LTE', 'BETWEEN', 'TIME_BETWEEN', 'EXISTS']),
  IP: new Set(['EQ', 'NEQ', 'IN', 'NOT_IN', 'CIDR_MATCH', 'EXISTS']),
};

/**
 * Algorithm / Thuật toán: Kiểm chứng tĩnh toàn diện cây chính sách DNF và phát hiện luật chết (Dead/Unreachable Rule Analysis).
 * Cơ chế hoạt động:
 *   1. Kiểm tra thuật toán kết hợp (`DENY_OVERRIDES`) và miền hợp lệ của danh sách nghĩa vụ (`validObligations`).
 *   2. Duyệt từng nhóm hội (AND group): xác thực tên thuộc tính trong từ điển, tính tương thích giữa kiểu thuộc tính
 *      và toán tử (`compatibleOperators`), cùng cấu trúc miền giá trị kỳ vọng (`validExpected`).
 *   3. Với mỗi nhóm hợp lệ về cú pháp, gọi bộ giải ràng buộc `hasContradiction` để kiểm tra tính khả thỏa.
 *   4. Nếu toàn bộ các nhóm tuyển (OR) của một luật đều rỗng, lỗi kiểu hoặc tự mâu thuẫn, đánh dấu `UNREACHABLE_RULE`.
 */
export function validatePolicy(
  policy: CompiledPolicy,
  attributes: Readonly<Record<string, AttributeDescriptor>>,
): PolicyValidationIssue[] {
  const issues: PolicyValidationIssue[] = [];
  for (const rule of policy.rules) {
    if (rule.combiningAlgorithm !== 'DENY_OVERRIDES') {
      issues.push({
        code: 'INVALID_COMBINING_ALGORITHM',
        ruleId: rule.id,
        message: `Rule "${rule.code}" uses combining algorithm "${rule.combiningAlgorithm}" but only "DENY_OVERRIDES" is supported.`,
      });
    }
    if (!validObligations(rule.obligations)) {
      issues.push({
        code: 'INVALID_OBLIGATION',
        ruleId: rule.id,
        message: `Rule "${rule.code}" contains invalid obligations. Allowed types: REQUIRE_WATERMARK, REQUIRE_MFA, MAX_SESSION_MINUTES (1-1440), FORBID_DOWNLOAD, NO_CACHE.`,
      });
    }
    let reachableGroup = false;
    if (rule.groups.length === 0) {
      issues.push({
        code: 'EMPTY_GROUP',
        ruleId: rule.id,
        message: `Rule "${rule.code}" has no condition groups.`,
      });
    }
    for (const group of rule.groups) {
      if (group.conditions.length === 0) {
        issues.push({
          code: 'EMPTY_GROUP',
          ruleId: rule.id,
          message: `Rule "${rule.code}" has an empty condition group (group ${group.id}).`,
        });
        continue;
      }
      let validGroup = true;
      for (const condition of group.conditions) {
        const attribute = attributes[condition.attribute];
        if (!attribute) {
          issues.push({
            code: 'UNKNOWN_ATTRIBUTE',
            ruleId: rule.id,
            conditionId: condition.id,
            message: `Condition "${condition.id}" references unknown attribute "${condition.attribute}".`,
          });
          validGroup = false;
          continue;
        }
        if (
          !POLICY_OPERATORS.includes(condition.operator) ||
          !compatibleOperators[attribute.type].has(condition.operator)
        ) {
          issues.push({
            code: 'UNSUPPORTED_OPERATOR',
            ruleId: rule.id,
            conditionId: condition.id,
            message: `Operator "${condition.operator}" is not compatible with attribute "${condition.attribute}" of type "${attribute.type}".`,
          });
          validGroup = false;
        } else if (!validExpected(condition, attribute.type)) {
          issues.push({
            code: 'INVALID_EXPECTED_VALUE',
            ruleId: rule.id,
            conditionId: condition.id,
            message: `Expected value for condition "${condition.id}" is not valid for operator "${condition.operator}" on attribute type "${attribute.type}".`,
          });
          validGroup = false;
        }
      }
      if (validGroup && !hasContradiction(group.conditions)) reachableGroup = true;
    }
    if (!reachableGroup) {
      issues.push({
        code: 'UNREACHABLE_RULE',
        ruleId: rule.id,
        message: `Rule "${rule.code}" is unreachable because all condition groups contain contradictions or validation errors.`,
      });
    }
  }
  return issues;
}

/**
 * Algorithm / Thuật toán: Kiểm tra miền giá trị hợp lệ của danh sách nghĩa vụ (`MAX_SESSION_MINUTES` thuộc `[1, 1440]`).
 */
function validObligations(obligations: CompiledPolicy['rules'][number]['obligations']): boolean {
  return obligations.every((obligation) => {
    if (obligation.type === 'MAX_SESSION_MINUTES') {
      return (
        Number.isInteger(obligation.minutes) && obligation.minutes > 0 && obligation.minutes <= 1440
      );
    }
    return ['REQUIRE_WATERMARK', 'REQUIRE_MFA', 'FORBID_DOWNLOAD', 'NO_CACHE'].includes(
      obligation.type,
    );
  });
}

/**
 * Algorithm / Thuật toán: Kiểm chứng kiểu và bất biến miền của giá trị kỳ vọng theo từng toán tử.
 * Đảm bảo `BETWEEN` nhận đúng cặp `[min, max]` có thứ tự `min <= max`, `IN`/`NOT_IN` không rỗng,
 * `TIME_BETWEEN` đúng định dạng giờ/múi giờ IANA, và kiểu vô hướng khớp từ điển.
 */
function validExpected(condition: PolicyCondition, type: AttributeDescriptor['type']): boolean {
  const value = condition.expected;
  switch (condition.operator) {
    case 'EXISTS':
      return typeof value === 'boolean';
    case 'IN':
    case 'NOT_IN':
      return (
        Array.isArray(value) && value.length > 0 && value.every((item) => scalarMatches(item, type))
      );
    case 'BETWEEN':
      return (
        Array.isArray(value) &&
        value.length === 2 &&
        value.every((item) => scalarMatches(item, type)) &&
        compareExpectedValues(value[0]!, value[1]!) <= 0
      );
    case 'CIDR_MATCH':
      // CONFLICT-RESOLVED: Kiểm tra cú pháp dải mạng IPv4/IPv6 CIDR ngay lúc biên dịch để ngăn luật `DENY` sai cú pháp bị vô hiệu hóa âm thầm Fail-Open (HIGH-11).
      return (
        (typeof value === 'string' && isValidCidr(value)) ||
        (Array.isArray(value) &&
          value.length > 0 &&
          value.every((item) => typeof item === 'string' && isValidCidr(item)))
      );
    case 'TIME_BETWEEN':
      return isTimeWindow(value);
    default:
      return !Array.isArray(value) && scalarMatches(value, type);
  }
}

/**
 * Algorithm / Thuật toán: Kiểm tra tương thích kiểu vô hướng (Scalar Runtime Type Check).
 */
function scalarMatches(
  value: ExpectedValue | string | number | boolean,
  type: AttributeDescriptor['type'],
) {
  if (type === 'NUMBER') return typeof value === 'number' && Number.isFinite(value);
  if (type === 'BOOLEAN') return typeof value === 'boolean';
  if (type === 'DATE') return typeof value === 'string' && parseStrictIsoTimestamp(value) !== null;
  return typeof value === 'string';
}

/**
 * Algorithm / Thuật toán: Xác thực cấu trúc khung giờ `HH:MM[:SS]` 24h và tên múi giờ IANA qua `Intl.DateTimeFormat`.
 */
function isTimeWindow(value: ExpectedValue): value is TimeWindow {
  if (Array.isArray(value) || value === null || typeof value !== 'object') return false;
  const candidate = value as Partial<TimeWindow>;
  const time = /^(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?$/u;
  if (!time.test(candidate.start ?? '') || !time.test(candidate.end ?? '')) return false;
  try {
    new Intl.DateTimeFormat('en-GB', { timeZone: candidate.timeZone }).format(new Date(0));
    return true;
  } catch {
    return false;
  }
}

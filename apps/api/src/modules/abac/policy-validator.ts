import { POLICY_OPERATORS, type AttributeDescriptor } from './abac.types.js';
import type {
  CompiledPolicy,
  ExpectedValue,
  PolicyCondition,
  PolicyOperator,
  PolicyValidationIssue,
  TimeWindow,
} from './abac.types.js';

const compatibleOperators: Readonly<
  Record<AttributeDescriptor['type'], ReadonlySet<PolicyOperator>>
> = {
  STRING: new Set(['EQ', 'NEQ', 'IN', 'NOT_IN', 'EXISTS']),
  NUMBER: new Set(['EQ', 'NEQ', 'IN', 'NOT_IN', 'GTE', 'LTE', 'BETWEEN', 'EXISTS']),
  BOOLEAN: new Set(['EQ', 'NEQ', 'EXISTS']),
  DATE: new Set(['EQ', 'NEQ', 'GTE', 'LTE', 'BETWEEN', 'TIME_BETWEEN', 'EXISTS']),
  IP: new Set(['EQ', 'NEQ', 'IN', 'NOT_IN', 'CIDR_MATCH', 'EXISTS']),
};

export function validatePolicy(
  policy: CompiledPolicy,
  attributes: Readonly<Record<string, AttributeDescriptor>>,
): PolicyValidationIssue[] {
  const issues: PolicyValidationIssue[] = [];
  for (const rule of policy.rules) {
    if (rule.combiningAlgorithm !== 'DENY_OVERRIDES') {
      issues.push({ code: 'INVALID_COMBINING_ALGORITHM', ruleId: rule.id });
    }
    if (!validObligations(rule.obligations)) {
      issues.push({ code: 'INVALID_OBLIGATION', ruleId: rule.id });
    }
    let reachableGroup = false;
    if (rule.groups.length === 0) issues.push({ code: 'EMPTY_GROUP', ruleId: rule.id });
    for (const group of rule.groups) {
      if (group.conditions.length === 0) {
        issues.push({ code: 'EMPTY_GROUP', ruleId: rule.id });
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
          });
          validGroup = false;
        } else if (!validExpected(condition, attribute.type)) {
          issues.push({
            code: 'INVALID_EXPECTED_VALUE',
            ruleId: rule.id,
            conditionId: condition.id,
          });
          validGroup = false;
        }
      }
      if (validGroup && !hasContradiction(group.conditions)) reachableGroup = true;
    }
    if (!reachableGroup) issues.push({ code: 'UNREACHABLE_RULE', ruleId: rule.id });
  }
  return issues;
}

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
        compare(value[0]!, value[1]!) <= 0
      );
    case 'CIDR_MATCH':
      return (
        typeof value === 'string' ||
        (Array.isArray(value) &&
          value.length > 0 &&
          value.every((item) => typeof item === 'string'))
      );
    case 'TIME_BETWEEN':
      return isTimeWindow(value);
    default:
      return !Array.isArray(value) && scalarMatches(value, type);
  }
}

function scalarMatches(
  value: ExpectedValue | string | number | boolean,
  type: AttributeDescriptor['type'],
) {
  if (type === 'NUMBER') return typeof value === 'number' && Number.isFinite(value);
  if (type === 'BOOLEAN') return typeof value === 'boolean';
  if (type === 'DATE') return typeof value === 'string' && Number.isFinite(Date.parse(value));
  return typeof value === 'string';
}

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

function hasContradiction(conditions: PolicyCondition[]): boolean {
  const byAttribute = new Map<string, PolicyCondition[]>();
  for (const condition of conditions) {
    const existing = byAttribute.get(condition.attribute) ?? [];
    existing.push(condition);
    byAttribute.set(condition.attribute, existing);
  }
  for (const attributeConditions of byAttribute.values()) {
    const existence = attributeConditions
      .filter((item) => item.operator === 'EXISTS')
      .map((item) => item.expected);
    if (new Set(existence).size > 1) return true;
    if (
      existence.includes(false) &&
      attributeConditions.some((item) => item.operator !== 'EXISTS')
    ) {
      return true;
    }
    const equals = attributeConditions
      .filter((item) => item.operator === 'EQ')
      .map((item) => item.expected);
    if (new Set(equals.map(canonical)).size > 1) return true;
    const notEquals = new Set(
      attributeConditions
        .filter((item) => item.operator === 'NEQ')
        .map((item) => canonical(item.expected)),
    );
    if (equals.some((value) => notEquals.has(canonical(value)))) return true;
    const included = attributeConditions
      .filter((item) => item.operator === 'IN' && Array.isArray(item.expected))
      .flatMap((item) => item.expected as Array<string | number | boolean>);
    const excluded = new Set(
      attributeConditions
        .filter((item) => item.operator === 'NOT_IN' && Array.isArray(item.expected))
        .flatMap((item) => item.expected as Array<string | number | boolean>)
        .map(canonical),
    );
    if (
      equals.some(
        (value) =>
          included.length > 0 && !included.some((item) => canonical(item) === canonical(value)),
      )
    ) {
      return true;
    }
    if (equals.some((value) => excluded.has(canonical(value)))) return true;
    const lower = attributeConditions
      .filter((item) => item.operator === 'GTE')
      .map((item) => item.expected)
      .sort(compare)
      .at(-1);
    const upper = attributeConditions
      .filter((item) => item.operator === 'LTE')
      .map((item) => item.expected)
      .sort(compare)
      .at(0);
    if (lower !== undefined && upper !== undefined && compare(lower, upper) > 0) return true;
  }
  return false;
}

function canonical(value: ExpectedValue): string {
  return JSON.stringify(value);
}

function compare(left: ExpectedValue, right: ExpectedValue): number {
  const a = typeof left === 'string' && Number.isFinite(Date.parse(left)) ? Date.parse(left) : left;
  const b =
    typeof right === 'string' && Number.isFinite(Date.parse(right)) ? Date.parse(right) : right;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  return String(a).localeCompare(String(b));
}

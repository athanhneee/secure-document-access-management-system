import { CONTEXT_ATTRIBUTES } from './attribute-registry.js';
import type {
  CompiledPolicy,
  ExpectedValue,
  PdpResult,
  PolicyCondition,
  PolicyEvaluationInput,
  PolicyObligation,
  TimeWindow,
} from './abac.types.js';
import { validatePolicy } from './policy-validator.js';

type RuntimeValue = string | number | boolean | string[] | null | undefined;

const obligationOrder: Readonly<Record<PolicyObligation['type'], number>> = {
  REQUIRE_WATERMARK: 0,
  REQUIRE_MFA: 1,
  MAX_SESSION_MINUTES: 2,
  FORBID_DOWNLOAD: 3,
  NO_CACHE: 4,
};

export function evaluatePolicy(policy: CompiledPolicy, input: PolicyEvaluationInput): PdpResult {
  if (validatePolicy(policy, CONTEXT_ATTRIBUTES).length > 0) return deny(policy, 'INVALID_POLICY');
  const attributes = flatten(input);
  if (policy.requiredAttributes.some((key) => missing(attributes[key]))) {
    return deny(policy, 'MISSING_REQUIRED_ATTRIBUTE');
  }
  if (input.subject.clearanceRank === null || input.resource.classificationRank === null) {
    return deny(policy, 'MISSING_REQUIRED_ATTRIBUTE');
  }
  if (input.subject.clearanceRank < input.resource.classificationRank) {
    return deny(policy, 'INSUFFICIENT_CLEARANCE');
  }

  const now = Date.parse(input.environment.currentTime);
  const rules = [...policy.rules].sort(
    (left, right) => left.priority - right.priority || compareIds(left.id, right.id),
  );
  const matched = rules.filter(
    (rule) =>
      rule.targetResource === input.resourceType &&
      (rule.targetAction === null || rule.targetAction === input.action) &&
      Date.parse(rule.validFrom) <= now &&
      (rule.validTo === null || now < Date.parse(rule.validTo)) &&
      rule.groups.some((group) =>
        group.conditions.every((condition) => matches(condition, attributes)),
      ),
  );
  const matchedRuleIds = matched.map((rule) => rule.id);
  if (matched.some((rule) => rule.effect === 'DENY')) {
    return { ...deny(policy, 'EXPLICIT_DENY'), matchedRuleIds };
  }
  const permitted = matched.filter((rule) => rule.effect === 'PERMIT');
  if (permitted.length === 0) return deny(policy, 'DEFAULT_DENY');
  return {
    decision: 'PERMIT',
    reasonCode: 'POLICY_PERMIT',
    matchedRuleIds,
    obligations: mergeObligations(permitted.flatMap((rule) => rule.obligations)),
    policyVersion: policy.version,
  };
}

function deny(policy: CompiledPolicy, reasonCode: PdpResult['reasonCode']): PdpResult {
  return {
    decision: 'DENY',
    reasonCode,
    matchedRuleIds: [],
    obligations: [],
    policyVersion: policy.version,
  };
}

function flatten(input: PolicyEvaluationInput): Readonly<Record<string, RuntimeValue>> {
  return {
    'subject.clearanceRank': input.subject.clearanceRank,
    'subject.departmentId': input.subject.departmentId,
    'subject.employmentStatus': input.subject.employmentStatus,
    'subject.projects': input.subject.projects,
    'resource.classificationRank': input.resource.classificationRank,
    'resource.ownerId': input.resource.ownerId,
    'resource.departmentId': input.resource.departmentId,
    'resource.category': input.resource.category,
    'resource.status': input.resource.status,
    'environment.currentTime': input.environment.currentTime,
    'environment.ip': input.environment.ip,
    'environment.trustedNetwork': input.environment.trustedNetwork,
    'environment.deviceTrust': input.environment.deviceTrust,
    'environment.mfa': input.environment.mfa,
    'environment.riskScore': input.environment.riskScore,
  };
}

function matches(
  condition: PolicyCondition,
  attributes: Readonly<Record<string, RuntimeValue>>,
): boolean {
  const actual = attributes[condition.attribute];
  const exists = !missing(actual);
  if (condition.operator === 'EXISTS') return exists === condition.expected;
  if (!exists) return false;
  if (Array.isArray(actual)) return matchArray(condition, actual);
  switch (condition.operator) {
    case 'EQ':
      return equal(actual, condition.expected);
    case 'NEQ':
      return !equal(actual, condition.expected);
    case 'IN':
      return (
        Array.isArray(condition.expected) && condition.expected.some((item) => equal(actual, item))
      );
    case 'NOT_IN':
      return (
        Array.isArray(condition.expected) &&
        condition.expected.every((item) => !equal(actual, item))
      );
    case 'GTE':
      return compare(actual, condition.expected) >= 0;
    case 'LTE':
      return compare(actual, condition.expected) <= 0;
    case 'BETWEEN':
      return (
        Array.isArray(condition.expected) &&
        compare(actual, condition.expected[0]!) >= 0 &&
        compare(actual, condition.expected[1]!) <= 0
      );
    case 'CIDR_MATCH':
      return typeof actual === 'string' && cidrMatchesAny(actual, condition.expected);
    case 'TIME_BETWEEN':
      return typeof actual === 'string' && timeBetween(actual, condition.expected as TimeWindow);
    default:
      return false;
  }
}

function matchArray(condition: PolicyCondition, actual: string[]): boolean {
  if (condition.operator === 'EQ') return actual.some((item) => equal(item, condition.expected));
  if (condition.operator === 'NEQ') return actual.every((item) => !equal(item, condition.expected));
  const expected = condition.expected;
  if (condition.operator === 'IN' && Array.isArray(expected)) {
    return actual.some((item) => expected.some((candidate) => equal(item, candidate)));
  }
  if (condition.operator === 'NOT_IN' && Array.isArray(expected)) {
    return actual.every((item) => expected.every((candidate) => !equal(item, candidate)));
  }
  return false;
}

function equal(actual: RuntimeValue, expected: ExpectedValue): boolean {
  return (
    (typeof actual === 'string' || typeof actual === 'number' || typeof actual === 'boolean') &&
    actual === expected
  );
}

function compare(actual: RuntimeValue, expected: ExpectedValue): number {
  const left = comparable(actual);
  const right = comparable(expected);
  if (left === null || right === null) return Number.NaN;
  if (typeof left === 'number' && typeof right === 'number') return left - right;
  return String(left).localeCompare(String(right));
}

function comparable(value: RuntimeValue | ExpectedValue): string | number | null {
  if (typeof value === 'number') return value;
  if (typeof value !== 'string') return null;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : value;
}

function missing(value: RuntimeValue): boolean {
  return value === null || value === undefined || (Array.isArray(value) && value.length === 0);
}

function mergeObligations(obligations: PolicyObligation[]): PolicyObligation[] {
  const types = new Set(obligations.map((item) => item.type));
  const maximums = obligations
    .filter(
      (item): item is Extract<PolicyObligation, { type: 'MAX_SESSION_MINUTES' }> =>
        item.type === 'MAX_SESSION_MINUTES',
    )
    .map((item) => item.minutes);
  const result: PolicyObligation[] = [...types]
    .filter((type) => type !== 'MAX_SESSION_MINUTES')
    .map((type) => ({ type }) as PolicyObligation);
  if (maximums.length > 0)
    result.push({ type: 'MAX_SESSION_MINUTES', minutes: Math.min(...maximums) });
  return result.sort((left, right) => obligationOrder[left.type] - obligationOrder[right.type]);
}

function compareIds(left: string, right: string): number {
  try {
    const a = BigInt(left);
    const b = BigInt(right);
    return a < b ? -1 : a > b ? 1 : 0;
  } catch {
    return left.localeCompare(right);
  }
}

function timeBetween(value: string, window: TimeWindow): boolean {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return false;
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
}

function seconds(value: string): number {
  const [hours = 0, minutes = 0, secs = 0] = value.split(':').map(Number);
  return hours * 3600 + minutes * 60 + secs;
}

function cidrMatchesAny(ip: string, expected: ExpectedValue): boolean {
  const ranges = Array.isArray(expected) ? expected : [expected];
  return ranges.some((range) => typeof range === 'string' && cidrMatch(ip, range));
}

export function cidrMatch(ip: string, cidr: string): boolean {
  const [networkText, prefixText, extra] = cidr.split('/');
  if (!networkText || extra !== undefined) return false;
  const address = parseAddress(ip);
  const network = parseAddress(networkText);
  if (!address || !network || address.bits !== network.bits) return false;
  const prefix = prefixText === undefined ? address.bits : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > address.bits) return false;
  const shift = BigInt(address.bits - prefix);
  return address.value >> shift === network.value >> shift;
}

function parseAddress(value: string): { value: bigint; bits: 32 | 128 } | null {
  const normalized = value.toLowerCase().split('%')[0]!;
  if (normalized.includes(':')) return parseIpv6(normalized);
  const parts = normalized.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/u.test(part) || Number(part) > 255)) {
    return null;
  }
  return {
    value: parts.reduce((result, part) => (result << 8n) | BigInt(Number(part)), 0n),
    bits: 32,
  };
}

function parseIpv6(value: string): { value: bigint; bits: 128 } | null {
  if ((value.match(/::/gu) ?? []).length > 1) return null;
  let source = value;
  const ipv4Tail = source.match(/(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/u)?.[1];
  if (ipv4Tail) {
    const parsed = parseAddress(ipv4Tail);
    if (!parsed || parsed.bits !== 32) return null;
    const high = ((parsed.value >> 16n) & 0xffffn).toString(16);
    const low = (parsed.value & 0xffffn).toString(16);
    source = `${source.slice(0, -ipv4Tail.length)}${high}:${low}`;
  }
  const halves = source.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const omitted = 8 - left.length - right.length;
  if ((halves.length === 1 && omitted !== 0) || (halves.length === 2 && omitted < 1)) return null;
  const groups = [...left, ...Array.from({ length: omitted }, () => '0'), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/u.test(group))) return null;
  return {
    value: groups.reduce((result, group) => (result << 16n) | BigInt(`0x${group}`), 0n),
    bits: 128,
  };
}

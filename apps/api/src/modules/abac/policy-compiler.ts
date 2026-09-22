import { ATTRIBUTE_CODE_TO_KEY, CONTEXT_ATTRIBUTES } from './attribute-registry.js';
import { POLICY_OPERATORS } from './abac.types.js';
import type {
  CompiledPolicy,
  CompiledPolicyRule,
  ExpectedValue,
  PolicyCondition,
  PolicyObligation,
  PolicyOperator,
  TimeWindow,
} from './abac.types.js';
import { validatePolicy } from './policy-validator.js';

export interface StoredCondition {
  id: bigint;
  definitionCode: string | null;
  contextKey: string | null;
  operator: string;
  expectedValue: unknown;
  group: number;
  sequence: number;
}

export interface StoredRule {
  id: bigint;
  code: string;
  effect: 'PERMIT' | 'DENY';
  priority: number;
  targetResource: string;
  targetAction: 'DISCOVER' | 'VIEW' | 'DOWNLOAD' | 'SHARE' | 'MANAGE' | null;
  combiningAlgorithm: string;
  validFrom: Date;
  validTo: Date | null;
  obligations: unknown;
  conditions: StoredCondition[];
}

export interface StoredDefinition {
  code: string;
  required: boolean;
  scope: 'USER' | 'RESOURCE' | 'ENVIRONMENT';
  valueType: 'STRING' | 'NUMBER' | 'BOOLEAN' | 'DATE' | 'ENUM';
  options: Array<{ valueCode: string; numericRank: number | null }>;
}

export class PolicyCompilationError extends Error {
  constructor(readonly issueCodes: string[]) {
    super('Policy validation failed.');
    this.name = 'PolicyCompilationError';
  }
}

export function compilePolicy(
  version: bigint,
  definitions: StoredDefinition[],
  storedRules: StoredRule[],
): CompiledPolicy {
  validateDefinitions(definitions);
  const policy: CompiledPolicy = {
    version: version.toString(),
    requiredAttributes: uniqueSorted([
      'subject.clearanceRank',
      'resource.classificationRank',
      ...definitions
        .filter((definition) => definition.required)
        .map((definition) => ATTRIBUTE_CODE_TO_KEY[definition.code])
        .filter((key): key is string => key !== undefined),
    ]),
    rules: storedRules
      .map(compileRule)
      .sort(
        (left, right) => left.priority - right.priority || compareBigIntStrings(left.id, right.id),
      ),
  };
  const issues = validatePolicy(policy, CONTEXT_ATTRIBUTES);
  if (issues.length > 0)
    throw new PolicyCompilationError(uniqueSorted(issues.map((issue) => issue.code)));
  return policy;
}

function compileRule(rule: StoredRule): CompiledPolicyRule {
  if (rule.targetResource !== 'DOCUMENT') throw new PolicyCompilationError(['INVALID_TARGET']);
  if (rule.combiningAlgorithm !== 'DENY_OVERRIDES') {
    throw new PolicyCompilationError(['INVALID_COMBINING_ALGORITHM']);
  }
  const groups = new Map<number, PolicyCondition[]>();
  for (const condition of [...rule.conditions].sort(
    (left, right) =>
      left.group - right.group || left.sequence - right.sequence || Number(left.id - right.id),
  )) {
    const attribute =
      condition.contextKey ?? ATTRIBUTE_CODE_TO_KEY[condition.definitionCode ?? ''] ?? '';
    const values = groups.get(condition.group) ?? [];
    values.push({
      id: condition.id.toString(),
      attribute,
      operator: parseOperator(condition.operator),
      expected: parseExpected(condition.expectedValue),
    });
    groups.set(condition.group, values);
  }
  return {
    id: rule.id.toString(),
    code: rule.code,
    effect: rule.effect,
    priority: rule.priority,
    targetResource: 'DOCUMENT',
    targetAction: rule.targetAction,
    combiningAlgorithm: 'DENY_OVERRIDES',
    validFrom: rule.validFrom.toISOString(),
    validTo: rule.validTo?.toISOString() ?? null,
    groups: [...groups.entries()]
      .sort(([left], [right]) => left - right)
      .map(([id, conditions]) => ({ id, conditions })),
    obligations: parseObligations(rule.obligations),
  };
}

function validateDefinitions(definitions: StoredDefinition[]): void {
  const issues: string[] = [];
  for (const definition of definitions) {
    const key = ATTRIBUTE_CODE_TO_KEY[definition.code];
    if (!key) continue;
    const descriptor = CONTEXT_ATTRIBUTES[key];
    const expectedScope = key.split('.')[0];
    const scopeMatches =
      (expectedScope === 'subject' && definition.scope === 'USER') ||
      (expectedScope === 'resource' && definition.scope === 'RESOURCE') ||
      (expectedScope === 'environment' && definition.scope === 'ENVIRONMENT');
    const normalizedType =
      definition.code === 'CLEARANCE_LEVEL'
        ? 'NUMBER'
        : definition.code === 'SOURCE_IP'
          ? 'IP'
          : definition.valueType === 'ENUM'
            ? 'STRING'
            : definition.valueType;
    if (!descriptor || !scopeMatches || normalizedType !== descriptor.type) {
      issues.push('INVALID_ATTRIBUTE_DEFINITION');
    }
    if (
      definition.code === 'CLEARANCE_LEVEL' &&
      (definition.options.length === 0 ||
        definition.options.some((option) => option.numericRank === null))
    ) {
      issues.push('INVALID_ATTRIBUTE_OPTION');
    }
  }
  if (issues.length > 0) throw new PolicyCompilationError(uniqueSorted(issues));
}

function parseOperator(value: string): PolicyOperator {
  if (!POLICY_OPERATORS.includes(value as PolicyOperator)) {
    throw new PolicyCompilationError(['UNSUPPORTED_OPERATOR']);
  }
  return value as PolicyOperator;
}

function parseExpected(value: unknown): ExpectedValue {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean')
    return value;
  if (
    Array.isArray(value) &&
    value.every((item) => ['string', 'number', 'boolean'].includes(typeof item))
  ) {
    return value as Array<string | number | boolean>;
  }
  if (isRecord(value)) {
    const start = value['start'];
    const end = value['end'];
    const timeZone = value['timeZone'];
    if (typeof start === 'string' && typeof end === 'string' && typeof timeZone === 'string') {
      return { start, end, timeZone } satisfies TimeWindow;
    }
  }
  throw new PolicyCompilationError(['INVALID_EXPECTED_VALUE']);
}

function parseObligations(value: unknown): PolicyObligation[] {
  if (!Array.isArray(value)) throw new PolicyCompilationError(['INVALID_OBLIGATION']);
  return value.map((item) => {
    if (typeof item === 'string' && item !== 'MAX_SESSION_MINUTES') {
      return { type: item } as PolicyObligation;
    }
    if (
      isRecord(item) &&
      item['type'] === 'MAX_SESSION_MINUTES' &&
      typeof item['minutes'] === 'number'
    ) {
      return { type: 'MAX_SESSION_MINUTES', minutes: item['minutes'] };
    }
    if (
      isRecord(item) &&
      typeof item['type'] === 'string' &&
      item['type'] !== 'MAX_SESSION_MINUTES'
    ) {
      return { type: item['type'] } as PolicyObligation;
    }
    throw new PolicyCompilationError(['INVALID_OBLIGATION']);
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function compareBigIntStrings(left: string, right: string): number {
  const a = BigInt(left);
  const b = BigInt(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

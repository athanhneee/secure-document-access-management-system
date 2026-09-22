import assert from 'node:assert/strict';
import test from 'node:test';
import { isAssignmentActive } from '../dist/modules/abac/assignment-validity.js';
import { CONTEXT_ATTRIBUTES } from '../dist/modules/abac/attribute-registry.js';
import { cidrMatch, evaluatePolicy } from '../dist/modules/abac/policy-engine.js';
import { compilePolicy, PolicyCompilationError } from '../dist/modules/abac/policy-compiler.js';
import { validatePolicy } from '../dist/modules/abac/policy-validator.js';

const baseInput = {
  resourceType: 'DOCUMENT',
  action: 'VIEW',
  subject: {
    clearanceRank: 3,
    departmentId: '10',
    employmentStatus: 'ACTIVE',
    projects: ['ORION'],
  },
  resource: {
    classificationRank: 2,
    ownerId: '99',
    departmentId: '10',
    category: 'SECURITY',
    status: 'ACTIVE',
  },
  environment: {
    currentTime: '2026-01-01T02:00:00.000Z',
    ip: '10.20.30.40',
    trustedNetwork: true,
    deviceTrust: true,
    mfa: true,
    riskScore: 20,
  },
};

function rule(id, conditions, overrides = {}) {
  return {
    id: String(id),
    code: `RULE_${id}`,
    effect: 'PERMIT',
    priority: 100,
    targetResource: 'DOCUMENT',
    targetAction: 'VIEW',
    combiningAlgorithm: 'DENY_OVERRIDES',
    validFrom: '2020-01-01T00:00:00.000Z',
    validTo: null,
    groups: [
      {
        id: 1,
        conditions: conditions.map((condition, index) => ({ id: `${id}-${index}`, ...condition })),
      },
    ],
    obligations: [],
    ...overrides,
  };
}

function policy(rules) {
  return {
    version: '42',
    requiredAttributes: ['resource.classificationRank', 'subject.clearanceRank'],
    rules,
  };
}

const operatorCases = [
  ['EQ', 'subject.departmentId', '10'],
  ['NEQ', 'subject.departmentId', '11'],
  ['IN', 'resource.status', ['ACTIVE', 'DRAFT']],
  ['NOT_IN', 'resource.status', ['ARCHIVED', 'DELETED']],
  ['GTE', 'subject.clearanceRank', 3],
  ['LTE', 'environment.riskScore', 20],
  ['BETWEEN', 'environment.riskScore', [0, 20]],
  ['CIDR_MATCH', 'environment.ip', ['10.0.0.0/8', '2001:db8::/32']],
  [
    'TIME_BETWEEN',
    'environment.currentTime',
    { start: '09:00:00', end: '17:00:00', timeZone: 'Asia/Ho_Chi_Minh' },
  ],
  ['EXISTS', 'subject.projects', true],
];

for (const [operator, attribute, expected] of operatorCases) {
  test(`operator ${operator} is evaluated without executable policy code`, () => {
    const result = evaluatePolicy(
      policy([rule(1, [{ attribute, operator, expected }])]),
      baseInput,
    );
    assert.equal(result.decision, 'PERMIT');
    assert.equal(result.policyVersion, '42');
  });
}

test('missing and null required attributes fail closed with a stable reason', () => {
  const input = structuredClone(baseInput);
  input.subject.clearanceRank = null;
  assert.deepEqual(
    evaluatePolicy(
      policy([rule(1, [{ attribute: 'environment.mfa', operator: 'EQ', expected: true }])]),
      input,
    ),
    {
      decision: 'DENY',
      reasonCode: 'MISSING_REQUIRED_ATTRIBUTE',
      matchedRuleIds: [],
      obligations: [],
      policyVersion: '42',
    },
  );
});

test('clearance below classification is an unconditional deny', () => {
  const input = structuredClone(baseInput);
  input.subject.clearanceRank = 1;
  input.resource.classificationRank = 4;
  const result = evaluatePolicy(
    policy([rule(1, [{ attribute: 'environment.mfa', operator: 'EQ', expected: true }])]),
    input,
  );
  assert.equal(result.decision, 'DENY');
  assert.equal(result.reasonCode, 'INSUFFICIENT_CLEARANCE');
});

test('DENY_OVERRIDES wins and matched ids stay priority/id deterministic', () => {
  const permit = rule(20, [{ attribute: 'environment.mfa', operator: 'EQ', expected: true }], {
    priority: 200,
  });
  const deny = rule(3, [{ attribute: 'environment.riskScore', operator: 'GTE', expected: 20 }], {
    effect: 'DENY',
    priority: 10,
  });
  const result = evaluatePolicy(policy([permit, deny]), baseInput);
  assert.equal(result.decision, 'DENY');
  assert.equal(result.reasonCode, 'EXPLICIT_DENY');
  assert.deepEqual(result.matchedRuleIds, ['3', '20']);
});

test('obligations are canonical and choose the shortest maximum session', () => {
  const first = rule(1, [{ attribute: 'environment.mfa', operator: 'EQ', expected: true }], {
    obligations: [
      { type: 'NO_CACHE' },
      { type: 'MAX_SESSION_MINUTES', minutes: 60 },
      { type: 'REQUIRE_WATERMARK' },
    ],
  });
  const second = rule(
    2,
    [{ attribute: 'environment.deviceTrust', operator: 'EQ', expected: true }],
    {
      obligations: [
        { type: 'REQUIRE_MFA' },
        { type: 'MAX_SESSION_MINUTES', minutes: 15 },
        { type: 'FORBID_DOWNLOAD' },
      ],
    },
  );
  assert.deepEqual(evaluatePolicy(policy([second, first]), baseInput).obligations, [
    { type: 'REQUIRE_WATERMARK' },
    { type: 'REQUIRE_MFA' },
    { type: 'MAX_SESSION_MINUTES', minutes: 15 },
    { type: 'FORBID_DOWNLOAD' },
    { type: 'NO_CACHE' },
  ]);
});

test('time windows are timezone-aware, inclusive at boundaries, and support overnight', () => {
  const daytime = rule(1, [
    {
      attribute: 'environment.currentTime',
      operator: 'TIME_BETWEEN',
      expected: { start: '09:00:00', end: '17:00:00', timeZone: 'Asia/Ho_Chi_Minh' },
    },
  ]);
  for (const currentTime of ['2026-01-01T02:00:00.000Z', '2026-01-01T10:00:00.000Z']) {
    const input = structuredClone(baseInput);
    input.environment.currentTime = currentTime;
    assert.equal(evaluatePolicy(policy([daytime]), input).decision, 'PERMIT');
  }
  const outside = structuredClone(baseInput);
  outside.environment.currentTime = '2026-01-01T10:00:01.000Z';
  assert.equal(evaluatePolicy(policy([daytime]), outside).decision, 'DENY');
  const overnight = rule(2, [
    {
      attribute: 'environment.currentTime',
      operator: 'TIME_BETWEEN',
      expected: { start: '22:00', end: '06:00', timeZone: 'UTC' },
    },
  ]);
  const late = structuredClone(baseInput);
  late.environment.currentTime = '2026-01-01T23:30:00.000Z';
  assert.equal(evaluatePolicy(policy([overnight]), late).decision, 'PERMIT');
});

test('CIDR matching handles IPv4 and compressed IPv6 boundaries', () => {
  assert.equal(cidrMatch('10.255.255.255', '10.0.0.0/8'), true);
  assert.equal(cidrMatch('11.0.0.0', '10.0.0.0/8'), false);
  assert.equal(cidrMatch('2001:db8:ffff::1', '2001:db8::/32'), true);
  assert.equal(cidrMatch('2001:db9::1', '2001:db8::/32'), false);
  assert.equal(cidrMatch('::ffff:192.0.2.1', '::ffff:192.0.2.0/120'), true);
});

test('policy validation rejects empty groups and unreachable contradictions', () => {
  const empty = rule(1, []);
  const contradictory = rule(2, [
    { attribute: 'subject.departmentId', operator: 'EQ', expected: '10' },
    { attribute: 'subject.departmentId', operator: 'EQ', expected: '11' },
  ]);
  const issues = validatePolicy(policy([empty, contradictory]), CONTEXT_ATTRIBUTES);
  assert.ok(issues.some((issue) => issue.code === 'EMPTY_GROUP' && issue.ruleId === '1'));
  assert.ok(issues.some((issue) => issue.code === 'UNREACHABLE_RULE' && issue.ruleId === '2'));
});

test('compiler rejects mismatched definition types/scopes and invalid clearance options', () => {
  const definition = {
    code: 'CLEARANCE_LEVEL',
    required: true,
    scope: 'RESOURCE',
    valueType: 'ENUM',
    options: [{ valueCode: 'SECRET', numericRank: null }],
  };
  assert.throws(
    () => compilePolicy(1n, [definition], []),
    (error) =>
      error instanceof PolicyCompilationError &&
      error.issueCodes.includes('INVALID_ATTRIBUTE_DEFINITION') &&
      error.issueCodes.includes('INVALID_ATTRIBUTE_OPTION'),
  );
});

test('compiler creates a canonical typed policy from stored schema rows', () => {
  const definitions = [
    {
      code: 'CLEARANCE_LEVEL',
      required: true,
      scope: 'USER',
      valueType: 'ENUM',
      options: [{ valueCode: 'SECRET', numericRank: 3 }],
    },
    {
      code: 'SOURCE_IP',
      required: true,
      scope: 'ENVIRONMENT',
      valueType: 'STRING',
      options: [],
    },
    {
      code: 'EMPLOYMENT_STATUS',
      required: true,
      scope: 'USER',
      valueType: 'ENUM',
      options: [{ valueCode: 'ACTIVE', numericRank: null }],
    },
    { code: 'IGNORED_EXTENSION', required: true, scope: 'USER', valueType: 'STRING', options: [] },
  ];
  const storedRule = {
    id: 20n,
    code: 'CANONICAL_RULE',
    effect: 'PERMIT',
    priority: 10,
    targetResource: 'DOCUMENT',
    targetAction: null,
    combiningAlgorithm: 'DENY_OVERRIDES',
    validFrom: new Date('2025-01-01T00:00:00.000Z'),
    validTo: new Date('2027-01-01T00:00:00.000Z'),
    obligations: [
      'REQUIRE_MFA',
      { type: 'NO_CACHE' },
      { type: 'MAX_SESSION_MINUTES', minutes: 30 },
    ],
    conditions: [
      {
        id: 5n,
        definitionCode: null,
        contextKey: 'environment.currentTime',
        operator: 'TIME_BETWEEN',
        expectedValue: { start: '09:00', end: '17:00', timeZone: 'Asia/Ho_Chi_Minh' },
        group: 3,
        sequence: 1,
      },
      {
        id: 2n,
        definitionCode: 'CLEARANCE_LEVEL',
        contextKey: null,
        operator: 'GTE',
        expectedValue: 2,
        group: 1,
        sequence: 2,
      },
      {
        id: 1n,
        definitionCode: null,
        contextKey: 'environment.mfa',
        operator: 'EQ',
        expectedValue: true,
        group: 1,
        sequence: 1,
      },
      {
        id: 4n,
        definitionCode: null,
        contextKey: 'resource.status',
        operator: 'IN',
        expectedValue: ['ACTIVE', 'DRAFT'],
        group: 2,
        sequence: 1,
      },
      {
        id: 6n,
        definitionCode: null,
        contextKey: 'resource.ownerId',
        operator: 'EQ',
        expectedValue: '99',
        group: 4,
        sequence: 1,
      },
    ],
  };

  const compiled = compilePolicy(77n, definitions, [
    { ...storedRule, id: 21n, code: 'LATER_BY_ID' },
    storedRule,
  ]);

  assert.equal(compiled.version, '77');
  assert.deepEqual(compiled.requiredAttributes, [
    'environment.ip',
    'resource.classificationRank',
    'subject.clearanceRank',
    'subject.employmentStatus',
  ]);
  assert.deepEqual(
    compiled.rules.map((item) => item.id),
    ['20', '21'],
  );
  assert.deepEqual(
    compiled.rules[0].groups.map((group) => group.id),
    [1, 2, 3, 4],
  );
  assert.deepEqual(
    compiled.rules[0].groups[0].conditions.map((condition) => condition.id),
    ['1', '2'],
  );
  assert.deepEqual(compiled.rules[0].obligations, [
    { type: 'REQUIRE_MFA' },
    { type: 'NO_CACHE' },
    { type: 'MAX_SESSION_MINUTES', minutes: 30 },
  ]);
});

test('compiler rejects invalid storage shapes before activation', () => {
  const storedRule = {
    id: 1n,
    code: 'INVALID_RULE',
    effect: 'PERMIT',
    priority: 1,
    targetResource: 'DOCUMENT',
    targetAction: 'VIEW',
    combiningAlgorithm: 'DENY_OVERRIDES',
    validFrom: new Date('2025-01-01T00:00:00.000Z'),
    validTo: null,
    obligations: [],
    conditions: [
      {
        id: 1n,
        definitionCode: null,
        contextKey: 'environment.mfa',
        operator: 'EQ',
        expectedValue: true,
        group: 1,
        sequence: 1,
      },
    ],
  };
  const issueCodes = (change) => {
    try {
      compilePolicy(1n, [], [{ ...storedRule, ...change }]);
      assert.fail('Expected policy compilation to fail');
    } catch (error) {
      assert.ok(error instanceof PolicyCompilationError);
      return error.issueCodes;
    }
  };

  assert.deepEqual(issueCodes({ targetResource: 'FOLDER' }), ['INVALID_TARGET']);
  assert.deepEqual(issueCodes({ combiningAlgorithm: 'FIRST_APPLICABLE' }), [
    'INVALID_COMBINING_ALGORITHM',
  ]);
  assert.deepEqual(issueCodes({ obligations: null }), ['INVALID_OBLIGATION']);
  assert.deepEqual(issueCodes({ obligations: ['MAX_SESSION_MINUTES'] }), ['INVALID_OBLIGATION']);
  assert.deepEqual(issueCodes({ obligations: [{ type: 'MAX_SESSION_MINUTES', minutes: '30' }] }), [
    'INVALID_OBLIGATION',
  ]);
  assert.deepEqual(issueCodes({ obligations: [{ type: 42 }] }), ['INVALID_OBLIGATION']);
  assert.deepEqual(
    issueCodes({
      conditions: [{ ...storedRule.conditions[0], expectedValue: { unsupported: true } }],
    }),
    ['INVALID_EXPECTED_VALUE'],
  );
  assert.deepEqual(
    issueCodes({ conditions: [{ ...storedRule.conditions[0], operator: 'EXECUTE' }] }),
    ['UNSUPPORTED_OPERATOR'],
  );
  assert.deepEqual(
    issueCodes({
      conditions: [
        {
          ...storedRule.conditions[0],
          definitionCode: 'UNKNOWN_DEFINITION',
          contextKey: null,
        },
      ],
    }),
    ['UNKNOWN_ATTRIBUTE', 'UNREACHABLE_RULE'],
  );
});

test('policy strings remain inert data', () => {
  globalThis.__abacPolicyExecuted = false;
  const malicious = rule(1, [
    {
      attribute: 'subject.departmentId',
      operator: 'EQ',
      expected: 'globalThis.__abacPolicyExecuted = true',
    },
  ]);
  evaluatePolicy(policy([malicious]), baseInput);
  assert.equal(globalThis.__abacPolicyExecuted, false);
  delete globalThis.__abacPolicyExecuted;
});

test('expired assignments are inactive at the exact valid_to boundary', () => {
  const at = new Date('2026-01-01T00:00:00.000Z');
  assert.equal(
    isAssignmentActive(
      {
        validFrom: new Date('2025-01-01T00:00:00.000Z'),
        validTo: new Date('2026-01-01T00:00:00.000Z'),
      },
      at,
    ),
    false,
  );
  assert.equal(
    isAssignmentActive({ validFrom: new Date('2026-01-01T00:00:00.000Z'), validTo: null }, at),
    true,
  );
});

test('same input and policy version always produce byte-identical output', () => {
  let state = 0x12345678;
  const next = () => {
    state = (1664525 * state + 1013904223) >>> 0;
    return state;
  };
  for (let index = 0; index < 250; index += 1) {
    const input = structuredClone(baseInput);
    input.environment.riskScore = next() % 101;
    input.subject.clearanceRank = (next() % 4) + 1;
    input.resource.classificationRank = (next() % 4) + 1;
    const currentPolicy = policy([
      rule(2, [{ attribute: 'environment.riskScore', operator: 'LTE', expected: 50 }]),
      rule(1, [{ attribute: 'environment.riskScore', operator: 'GTE', expected: 80 }], {
        effect: 'DENY',
      }),
    ]);
    const first = JSON.stringify(evaluatePolicy(currentPolicy, input));
    const second = JSON.stringify(evaluatePolicy(currentPolicy, input));
    assert.equal(first, second);
  }
});

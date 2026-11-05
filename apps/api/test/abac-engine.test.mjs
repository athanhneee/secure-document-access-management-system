import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluatePolicy } from '../dist/modules/abac/policy-engine.js';
import { baseInput, policy, rule, seededRandom } from './helpers/abac-test-fixtures.mjs';

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

test('null resource classificationRank denies with MISSING_REQUIRED_ATTRIBUTE', () => {
  const input = structuredClone(baseInput);
  input.resource.classificationRank = null;
  const result = evaluatePolicy(
    policy([rule(1, [{ attribute: 'environment.mfa', operator: 'EQ', expected: true }])]),
    input,
  );
  assert.equal(result.decision, 'DENY');
  assert.equal(result.reasonCode, 'MISSING_REQUIRED_ATTRIBUTE');
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

test('multiple DENY rules matching all appear in matchedRuleIds', () => {
  const deny1 = rule(5, [{ attribute: 'environment.mfa', operator: 'EQ', expected: true }], {
    effect: 'DENY',
    priority: 10,
  });
  const deny2 = rule(8, [{ attribute: 'environment.riskScore', operator: 'LTE', expected: 50 }], {
    effect: 'DENY',
    priority: 20,
  });
  const result = evaluatePolicy(policy([deny1, deny2]), baseInput);
  assert.equal(result.decision, 'DENY');
  assert.equal(result.reasonCode, 'EXPLICIT_DENY');
  assert.ok(result.matchedRuleIds.includes('5'));
  assert.ok(result.matchedRuleIds.includes('8'));
});

test('DENY wins over PERMIT at same priority regardless of id order', () => {
  const permit = rule(1, [{ attribute: 'environment.mfa', operator: 'EQ', expected: true }], {
    priority: 50,
  });
  const deny = rule(999, [{ attribute: 'environment.riskScore', operator: 'GTE', expected: 0 }], {
    effect: 'DENY',
    priority: 50,
  });
  const result = evaluatePolicy(policy([permit, deny]), baseInput);
  assert.equal(result.decision, 'DENY');
  assert.equal(result.reasonCode, 'EXPLICIT_DENY');
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

test('empty projects array is treated as missing for EXISTS check', () => {
  const input = structuredClone(baseInput);
  input.subject.projects = [];
  const existsTrue = rule(1, [
    { attribute: 'subject.projects', operator: 'EXISTS', expected: true },
  ]);
  assert.equal(evaluatePolicy(policy([existsTrue]), input).decision, 'DENY');
  const existsFalse = rule(2, [
    { attribute: 'subject.projects', operator: 'EXISTS', expected: false },
  ]);
  assert.equal(evaluatePolicy(policy([existsFalse]), input).decision, 'PERMIT');
});

test('same input and policy version always produce byte-identical output', () => {
  const next = seededRandom(0x12345678);
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

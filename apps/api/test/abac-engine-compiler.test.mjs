import assert from 'node:assert/strict';
import test from 'node:test';
import { CONTEXT_ATTRIBUTES } from '../dist/modules/abac/attribute-registry.js';
import { compilePolicy, PolicyCompilationError } from '../dist/modules/abac/policy-compiler.js';
import { validatePolicy } from '../dist/modules/abac/policy-validator.js';
import { makeStoredRule, policy, rule } from './helpers/abac-test-fixtures.mjs';

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

test('validation issues include descriptive messages', () => {
  const badPolicy = policy([
    rule(1, [{ attribute: 'nonexistent.attr', operator: 'EQ', expected: 'value' }]),
  ]);
  const issues = validatePolicy(badPolicy, CONTEXT_ATTRIBUTES);
  assert.ok(issues.length > 0);
  for (const issue of issues) {
    assert.ok(typeof issue.message === 'string' && issue.message.length > 0);
  }
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
  const storedRule = makeStoredRule({
    id: 20n,
    code: 'CANONICAL_RULE',
    priority: 10,
    targetAction: null,
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
  });

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
  const storedRule = makeStoredRule({ code: 'INVALID_RULE' });
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

test('compiler rejects unknown obligation type strings', () => {
  const storedRule = makeStoredRule({
    code: 'INVALID_OBLIGATION_TYPE',
    obligations: ['UNKNOWN_OBLIGATION'],
  });
  assert.throws(
    () => compilePolicy(1n, [], [storedRule]),
    (error) =>
      error instanceof PolicyCompilationError && error.issueCodes.includes('INVALID_OBLIGATION'),
  );
});

test('compiler rejects MAX_SESSION_MINUTES with minutes out of range', () => {
  for (const minutes of [0, -1, 1441, 99999, 0.5]) {
    const badRule = makeStoredRule({
      code: 'BAD_MINUTES',
      obligations: [{ type: 'MAX_SESSION_MINUTES', minutes }],
    });
    assert.throws(
      () => compilePolicy(1n, [], [badRule]),
      (error) =>
        error instanceof PolicyCompilationError && error.issueCodes.includes('INVALID_OBLIGATION'),
      `Expected rejection for minutes=${minutes}`,
    );
  }
});

test('compiler accepts MAX_SESSION_MINUTES at boundaries 1 and 1440', () => {
  for (const minutes of [1, 1440]) {
    const boundaryRule = makeStoredRule({
      code: 'BOUNDARY_MINUTES',
      obligations: [{ type: 'MAX_SESSION_MINUTES', minutes }],
    });
    const compiled = compilePolicy(1n, [], [boundaryRule]);
    assert.ok(
      compiled.rules[0].obligations.some(
        (obligation) => obligation.type === 'MAX_SESSION_MINUTES' && obligation.minutes === minutes,
      ),
    );
  }
});

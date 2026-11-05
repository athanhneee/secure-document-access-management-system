import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluatePolicy } from '../dist/modules/abac/policy-engine.js';
import { policy, randomInput, rule, seededRandom } from './helpers/abac-test-fixtures.mjs';

function makeRule(id, conditions, overrides = {}) {
  return rule(id, conditions, { targetAction: null, ...overrides });
}

function makePolicy(rules) {
  return policy(rules, '1');
}

const ITERATIONS = 500;

test('PROPERTY: same input and policy always produce identical output (500 iterations)', () => {
  const rand = seededRandom(0xdeadbeef);
  const rules = [
    makeRule(1, [{ attribute: 'environment.riskScore', operator: 'LTE', expected: 50 }]),
    makeRule(2, [{ attribute: 'environment.mfa', operator: 'EQ', expected: true }]),
    makeRule(3, [{ attribute: 'environment.riskScore', operator: 'GTE', expected: 80 }], {
      effect: 'DENY',
    }),
    makeRule(4, [
      { attribute: 'subject.employmentStatus', operator: 'EQ', expected: 'ACTIVE' },
      { attribute: 'environment.deviceTrust', operator: 'EQ', expected: true },
    ]),
  ];

  for (let i = 0; i < ITERATIONS; i += 1) {
    const input = randomInput(rand);
    const pol = makePolicy(rules);
    const first = JSON.stringify(evaluatePolicy(pol, input));
    const second = JSON.stringify(evaluatePolicy(pol, input));
    assert.equal(first, second, `Idempotency violation at iteration ${i}`);
  }
});

test('PROPERTY: any policy with a matching DENY rule always yields DENY decision', () => {
  const rand = seededRandom(0xcafebabe);
  const alwaysMatchDeny = makeRule(
    1,
    [{ attribute: 'environment.riskScore', operator: 'GTE', expected: 0 }],
    { effect: 'DENY' },
  );
  const alwaysPermit = makeRule(2, [
    { attribute: 'environment.riskScore', operator: 'GTE', expected: 0 },
  ]);

  for (let i = 0; i < ITERATIONS; i += 1) {
    const input = randomInput(rand);
    input.subject.clearanceRank = 5;
    input.resource.classificationRank = 1;
    const pol = makePolicy([alwaysPermit, alwaysMatchDeny]);
    const result = evaluatePolicy(pol, input);
    assert.equal(result.decision, 'DENY', `DENY dominance violation at iteration ${i}`);
    assert.equal(result.reasonCode, 'EXPLICIT_DENY');
  }
});

test('PROPERTY: malicious strings in expected values never execute as code', () => {
  const payloads = [
    'globalThis.compromised=true',
    'require("child_process").exec("id")',
    '(() => { throw new Error("pwned") })()',
    'process.exit(1)',
    'import("fs")',
    '${process.env.SECRET}',
    '__proto__.polluted = true',
    'constructor.constructor("return this")()',
  ];

  globalThis.__propertyTestCompromised = false;

  for (const payload of payloads) {
    const maliciousRule = makeRule(1, [
      { attribute: 'subject.departmentId', operator: 'EQ', expected: payload },
    ]);
    const input = {
      resourceType: 'DOCUMENT',
      action: 'VIEW',
      subject: {
        clearanceRank: 3,
        departmentId: payload,
        employmentStatus: 'ACTIVE',
        projects: [payload],
      },
      resource: {
        classificationRank: 2,
        ownerId: '1',
        departmentId: '1',
        category: 'SECURITY',
        status: 'ACTIVE',
      },
      environment: {
        currentTime: '2026-01-01T12:00:00.000Z',
        ip: '10.0.0.1',
        trustedNetwork: true,
        deviceTrust: true,
        mfa: true,
        riskScore: 0,
      },
    };
    evaluatePolicy(makePolicy([maliciousRule]), input);
    assert.equal(globalThis.__propertyTestCompromised, false, `Code execution from: ${payload}`);
  }

  delete globalThis.__propertyTestCompromised;
});

test('PROPERTY: clearanceRank < classificationRank always denies regardless of policy', () => {
  const rand = seededRandom(0xfeedface);
  const permissiveRule = makeRule(1, [
    { attribute: 'environment.riskScore', operator: 'GTE', expected: 0 },
  ]);

  for (let i = 0; i < ITERATIONS; i += 1) {
    const input = randomInput(rand);
    const classRank = (rand() % 4) + 2;
    input.resource.classificationRank = classRank;
    input.subject.clearanceRank = classRank - 1;
    const result = evaluatePolicy(makePolicy([permissiveRule]), input);
    assert.equal(result.decision, 'DENY', `Clearance invariant violated at iteration ${i}`);
    assert.equal(result.reasonCode, 'INSUFFICIENT_CLEARANCE');
  }
});

test('PROPERTY: null clearanceRank always denies as MISSING_REQUIRED_ATTRIBUTE', () => {
  const rand = seededRandom(0xbadf00d);
  const permissiveRule = makeRule(1, [
    { attribute: 'environment.riskScore', operator: 'GTE', expected: 0 },
  ]);

  for (let i = 0; i < ITERATIONS; i += 1) {
    const input = randomInput(rand);
    input.subject.clearanceRank = null;
    input.resource.classificationRank = (rand() % 5) + 1;
    const result = evaluatePolicy(makePolicy([permissiveRule]), input);
    assert.equal(result.decision, 'DENY', `Missing required violated at iteration ${i}`);
    assert.equal(result.reasonCode, 'MISSING_REQUIRED_ATTRIBUTE');
  }
});

test('PROPERTY: null classificationRank always denies as MISSING_REQUIRED_ATTRIBUTE', () => {
  const rand = seededRandom(0xd15ea5e);
  const permissiveRule = makeRule(1, [
    { attribute: 'environment.riskScore', operator: 'GTE', expected: 0 },
  ]);

  for (let i = 0; i < ITERATIONS; i += 1) {
    const input = randomInput(rand);
    input.subject.clearanceRank = (rand() % 5) + 1;
    input.resource.classificationRank = null;
    const result = evaluatePolicy(makePolicy([permissiveRule]), input);
    assert.equal(result.decision, 'DENY', `Missing classification violated at iteration ${i}`);
    assert.equal(result.reasonCode, 'MISSING_REQUIRED_ATTRIBUTE');
  }
});

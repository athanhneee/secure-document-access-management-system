import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluatePolicy } from '../dist/modules/abac/policy-engine.js';

// ── Helpers ─────────────────────────────────────────────────────────────────

function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (1664525 * state + 1013904223) >>> 0;
    return state;
  };
}

function randomInput(rand) {
  return {
    resourceType: 'DOCUMENT',
    action: ['DISCOVER', 'VIEW', 'DOWNLOAD', 'SHARE', 'MANAGE'][rand() % 5],
    subject: {
      clearanceRank: rand() % 2 === 0 ? null : (rand() % 5) + 1,
      departmentId: String(rand() % 50),
      employmentStatus: ['ACTIVE', 'LOCKED', 'DISABLED', 'PENDING'][rand() % 4],
      projects: rand() % 3 === 0 ? [] : [`PRJ_${rand() % 10}`],
    },
    resource: {
      classificationRank: rand() % 2 === 0 ? null : (rand() % 5) + 1,
      ownerId: String(rand() % 100),
      departmentId: String(rand() % 50),
      category: ['SECURITY', 'FINANCE', 'HR', 'GENERAL'][rand() % 4],
      status: ['ACTIVE', 'DRAFT', 'ARCHIVED', 'DELETED'][rand() % 4],
    },
    environment: {
      currentTime: new Date(2026, 0, 1 + (rand() % 365), rand() % 24, rand() % 60).toISOString(),
      ip: `${rand() % 256}.${rand() % 256}.${rand() % 256}.${rand() % 256}`,
      trustedNetwork: rand() % 2 === 0,
      deviceTrust: rand() % 2 === 0,
      mfa: rand() % 2 === 0,
      riskScore: rand() % 101,
    },
  };
}

function makeRule(id, conditions, overrides = {}) {
  return {
    id: String(id),
    code: `RULE_${id}`,
    effect: 'PERMIT',
    priority: 100,
    targetResource: 'DOCUMENT',
    targetAction: null,
    combiningAlgorithm: 'DENY_OVERRIDES',
    validFrom: '2020-01-01T00:00:00.000Z',
    validTo: null,
    groups: [
      {
        id: 1,
        conditions: conditions.map((c, i) => ({ id: `${id}-${i}`, ...c })),
      },
    ],
    obligations: [],
    ...overrides,
  };
}

function makePolicy(rules) {
  return {
    version: '1',
    requiredAttributes: ['resource.classificationRank', 'subject.clearanceRank'],
    rules,
  };
}

const ITERATIONS = 500;

// ── Property 1: Idempotency ─────────────────────────────────────────────────

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

// ── Property 2: DENY dominance ──────────────────────────────────────────────

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
    // Force non-null clearance >= classification so we don't get pre-empted by clearance check
    input.subject.clearanceRank = 5;
    input.resource.classificationRank = 1;
    const pol = makePolicy([alwaysPermit, alwaysMatchDeny]);
    const result = evaluatePolicy(pol, input);
    assert.equal(result.decision, 'DENY', `DENY dominance violation at iteration ${i}`);
    assert.equal(result.reasonCode, 'EXPLICIT_DENY');
  }
});

// ── Property 3: No code execution from policy data ──────────────────────────

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

// ── Property 4: Clearance invariant ─────────────────────────────────────────

test('PROPERTY: clearanceRank < classificationRank always denies regardless of policy', () => {
  const rand = seededRandom(0xfeedface);
  const permissiveRule = makeRule(1, [
    { attribute: 'environment.riskScore', operator: 'GTE', expected: 0 },
  ]);

  for (let i = 0; i < ITERATIONS; i += 1) {
    const input = randomInput(rand);
    const classRank = (rand() % 4) + 2; // 2-5
    input.resource.classificationRank = classRank;
    input.subject.clearanceRank = classRank - 1; // always lower
    const result = evaluatePolicy(makePolicy([permissiveRule]), input);
    assert.equal(result.decision, 'DENY', `Clearance invariant violated at iteration ${i}`);
    assert.equal(result.reasonCode, 'INSUFFICIENT_CLEARANCE');
  }
});

// ── Property 5: Missing required → DENY ─────────────────────────────────────

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

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { CONTEXT_ATTRIBUTES } from '../dist/modules/abac/attribute-registry.js';
import { compilePolicy } from '../dist/modules/abac/policy-compiler.js';
import { evaluatePolicy } from '../dist/modules/abac/policy-engine.js';
import { validatePolicy } from '../dist/modules/abac/policy-validator.js';
import { hasContradiction } from '../dist/modules/abac/policy-contradiction-solver.js';

function baseInput(overrides = {}) {
  return {
    resourceType: 'DOCUMENT',
    action: 'VIEW',
    subject: {
      clearanceRank: 4,
      departmentId: 'FINANCE_DEPT',
      employmentStatus: 'ACTIVE',
      projects: ['PRJ-ALPHA'],
      ...(overrides.subject ?? {}),
    },
    resource: {
      classificationRank: 2,
      departmentId: 'FINANCE_DEPT',
      ownerId: '10',
      category: 'FINANCE',
      status: 'ACTIVE',
      ...(overrides.resource ?? {}),
    },
    environment: {
      currentTime: '2026-09-22T03:15:00.000Z', // 10:15 Asia/Ho_Chi_Minh (UTC+7)
      ip: '10.20.30.40',
      trustedNetwork: true,
      deviceTrust: true,
      mfa: true,
      riskScore: 20,
      ...(overrides.environment ?? {}),
    },
  };
}

test('Visual Policy Builder -> Real ABAC Compiler & Engine: evaluates Office Hours & Intranet template', () => {
  const compiled = compilePolicy(
    1n,
    [],
    [
      {
        id: 101n,
        code: 'POL_OFFICE_HOURS_INTRANET',
        effect: 'PERMIT',
        priority: 10,
        targetResource: 'DOCUMENT',
        targetAction: null,
        combiningAlgorithm: 'DENY_OVERRIDES',
        obligations: [{ type: 'REQUIRE_WATERMARK' }],
        validFrom: new Date('2026-01-01T00:00:00.000Z'),
        validTo: null,
        conditions: [
          {
            id: 1n,
            definitionCode: null,
            group: 1,
            sequence: 1,
            contextKey: 'environment.trustedNetwork',
            operator: 'EQ',
            expectedValue: true,
          },
          {
            id: 2n,
            definitionCode: null,
            group: 1,
            sequence: 2,
            contextKey: 'environment.currentTime',
            operator: 'TIME_BETWEEN',
            expectedValue: { start: '08:00', end: '17:30', timeZone: 'Asia/Ho_Chi_Minh' },
          },
          {
            id: 3n,
            definitionCode: null,
            group: 1,
            sequence: 3,
            contextKey: 'environment.riskScore',
            operator: 'LTE',
            expectedValue: 35,
          },
        ],
      },
    ],
  );

  assert.deepEqual(validatePolicy(compiled, CONTEXT_ATTRIBUTES), []);

  const permit = evaluatePolicy(compiled, baseInput());
  assert.equal(permit.decision, 'PERMIT');
  assert.equal(permit.reasonCode, 'POLICY_PERMIT');
  assert.deepEqual(permit.obligations, [{ type: 'REQUIRE_WATERMARK' }]);

  const offHours = evaluatePolicy(
    compiled,
    baseInput({ environment: { currentTime: '2026-09-22T13:00:00.000Z' } }), // 20:00 ICT
  );
  assert.equal(offHours.decision, 'DENY');
  assert.equal(offHours.reasonCode, 'DEFAULT_DENY');

  const highRisk = evaluatePolicy(compiled, baseInput({ environment: { riskScore: 70 } }));
  assert.equal(highRisk.decision, 'DENY');

  const untrustedNet = evaluatePolicy(
    compiled,
    baseInput({ environment: { trustedNetwork: false } }),
  );
  assert.equal(untrustedNet.decision, 'DENY');
});

test('Visual Policy Builder -> Real ABAC Engine: evaluates Top Secret rule with strict obligations & Bell-LaPadula', () => {
  const compiled = compilePolicy(
    2n,
    [],
    [
      {
        id: 202n,
        code: 'POL_TOP_SECRET_HARDENED',
        effect: 'PERMIT',
        priority: 5,
        targetResource: 'DOCUMENT',
        targetAction: 'VIEW',
        combiningAlgorithm: 'DENY_OVERRIDES',
        obligations: [
          { type: 'REQUIRE_WATERMARK' },
          { type: 'REQUIRE_MFA' },
          { type: 'FORBID_DOWNLOAD' },
          { type: 'MAX_SESSION_MINUTES', minutes: 20 },
        ],
        validFrom: new Date('2026-01-01T00:00:00.000Z'),
        validTo: null,
        conditions: [
          {
            id: 1n,
            definitionCode: null,
            group: 1,
            sequence: 1,
            contextKey: 'resource.classificationRank',
            operator: 'GTE',
            expectedValue: 4,
          },
          {
            id: 2n,
            definitionCode: null,
            group: 1,
            sequence: 2,
            contextKey: 'subject.clearanceRank',
            operator: 'GTE',
            expectedValue: 4,
          },
          {
            id: 3n,
            definitionCode: null,
            group: 1,
            sequence: 3,
            contextKey: 'environment.mfa',
            operator: 'EQ',
            expectedValue: true,
          },
          {
            id: 4n,
            definitionCode: null,
            group: 1,
            sequence: 4,
            contextKey: 'environment.deviceTrust',
            operator: 'EQ',
            expectedValue: true,
          },
        ],
      },
    ],
  );

  const resultView = evaluatePolicy(
    compiled,
    baseInput({ resource: { classificationRank: 4 }, subject: { clearanceRank: 4 } }),
  );
  assert.equal(resultView.decision, 'PERMIT');
  assert.equal(resultView.obligations.length, 4);
  assert.ok(resultView.obligations.some((o) => o.type === 'FORBID_DOWNLOAD'));
  assert.ok(
    resultView.obligations.some((o) => o.type === 'MAX_SESSION_MINUTES' && o.minutes === 20),
  );

  const resultDownload = evaluatePolicy(compiled, {
    ...baseInput({ resource: { classificationRank: 4 }, subject: { clearanceRank: 4 } }),
    action: 'DOWNLOAD',
  });
  assert.equal(resultDownload.decision, 'DENY');
  assert.equal(resultDownload.reasonCode, 'DEFAULT_DENY');

  const lowClearance = evaluatePolicy(
    compiled,
    baseInput({ resource: { classificationRank: 4 }, subject: { clearanceRank: 3 } }),
  );
  assert.equal(lowClearance.decision, 'DENY');
  assert.equal(lowClearance.reasonCode, 'INSUFFICIENT_CLEARANCE');
});

test('Visual Policy Builder -> Real ABAC Engine & Contradiction Solver: DENY_OVERRIDES & contradiction detection', () => {
  const compiled = compilePolicy(
    3n,
    [],
    [
      {
        id: 300n,
        code: 'POL_GENERAL_PERMIT',
        effect: 'PERMIT',
        priority: 10,
        targetResource: 'DOCUMENT',
        targetAction: null,
        combiningAlgorithm: 'DENY_OVERRIDES',
        obligations: [],
        validFrom: new Date('2026-01-01T00:00:00.000Z'),
        validTo: null,
        conditions: [
          {
            id: 1n,
            definitionCode: null,
            group: 1,
            sequence: 1,
            contextKey: 'environment.mfa',
            operator: 'EQ',
            expectedValue: true,
          },
        ],
      },
      {
        id: 301n,
        code: 'POL_FINANCE_DEPT_ISOLATION',
        effect: 'DENY',
        priority: 1,
        targetResource: 'DOCUMENT',
        targetAction: null,
        combiningAlgorithm: 'DENY_OVERRIDES',
        obligations: [],
        validFrom: new Date('2026-01-01T00:00:00.000Z'),
        validTo: null,
        conditions: [
          {
            id: 2n,
            definitionCode: null,
            group: 1,
            sequence: 1,
            contextKey: 'resource.departmentId',
            operator: 'EQ',
            expectedValue: 'FINANCE_DEPT',
          },
          {
            id: 3n,
            definitionCode: null,
            group: 1,
            sequence: 2,
            contextKey: 'subject.departmentId',
            operator: 'NEQ',
            expectedValue: 'FINANCE_DEPT',
          },
        ],
      },
    ],
  );

  const crossDept = evaluatePolicy(compiled, baseInput({ subject: { departmentId: 'IT_DEPT' } }));
  assert.equal(crossDept.decision, 'DENY');
  assert.equal(crossDept.reasonCode, 'EXPLICIT_DENY');

  const sameDept = evaluatePolicy(
    compiled,
    baseInput({ subject: { departmentId: 'FINANCE_DEPT' } }),
  );
  assert.equal(sameDept.decision, 'PERMIT');

  assert.equal(
    hasContradiction([
      { id: '1', attribute: 'environment.riskScore', operator: 'GTE', expected: 80 },
      { id: '2', attribute: 'environment.riskScore', operator: 'LTE', expected: 30 },
    ]),
    true,
  );
});

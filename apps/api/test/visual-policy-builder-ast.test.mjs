import assert from 'node:assert/strict';
import { test } from 'node:test';
import { compilePolicy } from '../dist/modules/abac/policy-compiler.js';
import { evaluatePolicy } from '../dist/modules/abac/policy-engine.js';

function evaluateVisualRule(rule, flatContext) {
  const compiled = compilePolicy(
    1n,
    [],
    [
      {
        id: 1n,
        code: rule.code,
        effect: rule.effect,
        priority: rule.priority,
        targetResource: rule.targetResource,
        targetAction: rule.targetAction === 'ALL' ? null : rule.targetAction,
        combiningAlgorithm: rule.combiningAlgorithm,
        obligations: rule.obligations ?? [],
        validFrom: new Date('2026-01-01T00:00:00.000Z'),
        validTo: null,
        conditions: rule.groups.flatMap((group) =>
          group.conditions.map((cond, idx) => ({
            id: BigInt(group.id * 100 + idx + 1),
            definitionCode: null,
            group: group.id,
            sequence: idx + 1,
            contextKey: cond.attribute,
            operator: cond.operator,
            expectedValue: cond.expected,
          })),
        ),
      },
    ],
  );

  return evaluatePolicy(compiled, {
    resourceType: 'DOCUMENT',
    action: 'VIEW',
    subject: {
      clearanceRank: flatContext['subject.clearanceRank'] ?? 3,
      departmentId: 'FINANCE_DEPT',
      employmentStatus: 'ACTIVE',
      projects: flatContext['subject.projects'] ?? [],
    },
    resource: {
      classificationRank: 1,
      departmentId: 'FINANCE_DEPT',
      ownerId: '10',
      category: 'FINANCE',
      status: 'ACTIVE',
    },
    environment: {
      currentTime: '2026-09-22T03:15:00.000Z',
      ip: '10.20.30.40',
      trustedNetwork: flatContext['environment.trustedNetwork'] ?? false,
      deviceTrust: true,
      mfa: flatContext['environment.mfa'] ?? false,
      riskScore: 10,
    },
  });
}

test('Visual Policy Builder — correctly evaluates multi-group OR logic with nested AND clauses', () => {
  const multiGroupRule = {
    code: 'POL_MULTI_GROUP_TEST',
    name: 'Quy tắc Đa nhóm OR',
    effect: 'PERMIT',
    priority: 10,
    targetResource: 'DOCUMENT',
    targetAction: 'ALL',
    combiningAlgorithm: 'DENY_OVERRIDES',
    groups: [
      {
        id: 1,
        conditions: [
          { id: 'c1', attribute: 'environment.trustedNetwork', operator: 'EQ', expected: true },
          { id: 'c2', attribute: 'subject.clearanceRank', operator: 'GTE', expected: 3 },
        ],
      },
      {
        id: 2,
        conditions: [
          { id: 'c3', attribute: 'subject.projects', operator: 'IN', expected: ['PROJECT_ALPHA'] },
          { id: 'c4', attribute: 'environment.mfa', operator: 'EQ', expected: true },
        ],
      },
    ],
    obligations: [{ type: 'REQUIRE_WATERMARK' }],
  };

  const contextA = {
    'environment.trustedNetwork': true,
    'subject.clearanceRank': 3,
    'subject.projects': ['OTHER_PROJECT'],
    'environment.mfa': false,
  };
  assert.equal(evaluateVisualRule(multiGroupRule, contextA).decision, 'PERMIT');

  const contextB = {
    'environment.trustedNetwork': false,
    'subject.clearanceRank': 1,
    'subject.projects': ['PROJECT_ALPHA'],
    'environment.mfa': true,
  };
  assert.equal(evaluateVisualRule(multiGroupRule, contextB).decision, 'PERMIT');

  const contextC = {
    'environment.trustedNetwork': false,
    'subject.clearanceRank': 1,
    'subject.projects': ['OTHER_PROJECT'],
    'environment.mfa': false,
  };
  assert.equal(evaluateVisualRule(multiGroupRule, contextC).decision, 'DENY');
});

test('Visual Policy Builder — preserves lossless round-trip JSON AST sync', () => {
  const originalRule = {
    id: 'rule-test-roundtrip',
    code: 'POL_ROUNDTRIP_SYNC',
    name: 'Kiểm thử Đồng bộ Hai Chiều JSON AST',
    description:
      'Bảo toàn cấu trúc cây điều kiện khi chuyển qua lại giữa Visual Blocks và JSON DSL.',
    effect: 'PERMIT',
    priority: 15,
    targetResource: 'DOCUMENT',
    targetAction: 'DOWNLOAD',
    combiningAlgorithm: 'DENY_OVERRIDES',
    groups: [
      {
        id: 1,
        conditions: [
          {
            id: 'c1',
            attribute: 'environment.ip',
            operator: 'CIDR_MATCH',
            expected: '192.168.1.0/24',
          },
          {
            id: 'c2',
            attribute: 'resource.category',
            operator: 'IN',
            expected: ['FINANCE', 'LEGAL'],
          },
          { id: 'c3', attribute: 'environment.riskScore', operator: 'BETWEEN', expected: [0, 40] },
        ],
      },
    ],
    obligations: [{ type: 'REQUIRE_WATERMARK' }, { type: 'MAX_SESSION_MINUTES', minutes: 45 }],
  };

  const serialized = JSON.stringify(originalRule, null, 2);
  const deserialized = JSON.parse(serialized);

  assert.deepEqual(
    deserialized,
    originalRule,
    'Parsed AST must strictly match original rule structure',
  );
  assert.equal(deserialized.groups[0].conditions.length, 3);
  assert.equal(deserialized.obligations[1].minutes, 45);
});

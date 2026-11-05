/**
 * Module: Visual Policy Builder End-to-End Backend AST Pipeline Tests
 * Thuật toán: Kiểm chứng trực tiếp chuỗi xử lý thật `UpsertAbacPolicySchema` -> `buildPolicyConditionRows`
 *   -> `serializeAbacPolicyRow` -> `validatePolicyDraft` -> `compilePolicy` -> `evaluatePolicy`.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  UpsertAbacPolicySchema,
  buildPolicyConditionRows,
  serializeAbacPolicyRow,
} from '../dist/modules/abac/abac-policy-dto.helper.js';
import { CONTEXT_ATTRIBUTES } from '../dist/modules/abac/attribute-registry.js';
import { compilePolicy } from '../dist/modules/abac/policy-compiler.js';
import { evaluatePolicy } from '../dist/modules/abac/policy-engine.js';
import { validatePolicy } from '../dist/modules/abac/policy-validator.js';

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

  assert.equal(
    evaluateVisualRule(multiGroupRule, {
      'environment.trustedNetwork': true,
      'subject.clearanceRank': 3,
      'subject.projects': ['OTHER_PROJECT'],
      'environment.mfa': false,
    }).decision,
    'PERMIT',
  );

  assert.equal(
    evaluateVisualRule(multiGroupRule, {
      'environment.trustedNetwork': false,
      'subject.clearanceRank': 1,
      'subject.projects': ['PROJECT_ALPHA'],
      'environment.mfa': true,
    }).decision,
    'PERMIT',
  );

  assert.equal(
    evaluateVisualRule(multiGroupRule, {
      'environment.trustedNetwork': false,
      'subject.clearanceRank': 1,
      'subject.projects': ['OTHER_PROJECT'],
      'environment.mfa': false,
    }).decision,
    'DENY',
  );
});

test('Visual Policy Builder — lossless round-trip through UpsertAbacPolicySchema, buildPolicyConditionRows, validatePolicyDraft & serializeAbacPolicyRow', async () => {
  const visualBuilderPayload = {
    code: 'POL_ROUNDTRIP_SYNC',
    name: 'Kiểm thử Đồng bộ Hai Chiều JSON AST',
    description:
      'Bảo toàn cấu trúc cây điều kiện khi ánh xạ qua tầng DTO, hàng CSDL quan hệ và trình biên dịch ABAC.',
    effect: 'PERMIT',
    priority: 15,
    targetResource: 'DOCUMENT',
    targetAction: 'DOWNLOAD',
    obligations: [{ type: 'REQUIRE_WATERMARK' }, { type: 'MAX_SESSION_MINUTES', minutes: 45 }],
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
      {
        id: 2,
        conditions: [{ id: 'c4', attribute: 'environment.mfa', operator: 'EQ', expected: true }],
      },
    ],
  };

  // 1. Validate DTO boundary with real Zod schema
  const parsedDto = UpsertAbacPolicySchema.parse(visualBuilderPayload);

  // 2. Transform DNF groups into relational policy_rule_conditions rows
  const mockTx = { attributeDefinition: { findMany: async () => [] } };
  const relationalRows = await buildPolicyConditionRows(mockTx, parsedDto.groups);
  assert.equal(relationalRows.length, 4);
  assert.ok(
    relationalRows.every((r) => (r.attribute_definition_id !== null) !== (r.context_key !== null)),
  );

  // 3. Compile & validate semantic rules + CIDR/BETWEEN bounds via real PolicyValidator
  const compiledRoundTrip = compilePolicy(
    42n,
    [],
    [
      {
        id: 42n,
        code: parsedDto.code,
        effect: parsedDto.effect,
        priority: parsedDto.priority,
        targetResource: 'DOCUMENT',
        targetAction: 'DOWNLOAD',
        combiningAlgorithm: 'DENY_OVERRIDES',
        obligations: parsedDto.obligations,
        validFrom: new Date('2026-01-01T00:00:00.000Z'),
        validTo: null,
        conditions: relationalRows.map((row, idx) => ({
          id: BigInt(idx + 1),
          definitionCode: null,
          group: row.condition_group,
          sequence: row.sequence_no,
          contextKey: row.context_key,
          operator: row.operator,
          expectedValue: row.expected_value,
        })),
      },
    ],
  );
  const validationIssues = validatePolicy(compiledRoundTrip, CONTEXT_ATTRIBUTES);
  assert.deepEqual(validationIssues, []);

  // 4. Serialize DB row back to Visual Builder DTO and assert lossless DNF reconstruction
  const roundTripped = serializeAbacPolicyRow({
    id: 42n,
    code: parsedDto.code,
    name: parsedDto.name,
    description: parsedDto.description ?? null,
    effect: parsedDto.effect,
    priority: parsedDto.priority,
    target_resource: 'DOCUMENT',
    target_action: 'DOWNLOAD',
    combining_algorithm: 'DENY_OVERRIDES',
    obligations: parsedDto.obligations,
    is_active: true,
    valid_from: new Date('2026-01-01T00:00:00.000Z'),
    valid_to: null,
    version: 1n,
    policy_rule_conditions: relationalRows.map((row, idx) => ({
      id: BigInt(100 + idx),
      policy_rule_id: 42n,
      ...row,
    })),
  });

  assert.equal(roundTripped.id, '42');
  assert.equal(roundTripped.targetAction, 'DOWNLOAD');
  assert.equal(roundTripped.groups.length, 2);
  assert.deepEqual(
    roundTripped.groups[0].conditions.map((c) => ({
      attribute: c.attribute,
      operator: c.operator,
      expected: c.expected,
    })),
    [
      { attribute: 'environment.ip', operator: 'CIDR_MATCH', expected: '192.168.1.0/24' },
      { attribute: 'resource.category', operator: 'IN', expected: ['FINANCE', 'LEGAL'] },
      { attribute: 'environment.riskScore', operator: 'BETWEEN', expected: [0, 40] },
    ],
  );
  assert.equal(roundTripped.obligations[1].minutes, 45);
});

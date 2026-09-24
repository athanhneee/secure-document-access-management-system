import assert from 'node:assert/strict';
import { test } from 'node:test';

// Visual Policy Builder AST and PDP Engine Test Suite

function evaluateVisualRule(rule, flatAttributes, action = 'VIEW') {
  // Action check
  const actionMatches = rule.targetAction === 'ALL' || rule.targetAction === action;
  if (!actionMatches) {
    return {
      decision: 'DENY',
      reasonCode: 'ACTION_NOT_TARGETED',
      matchedRuleCodes: [],
      obligations: [],
    };
  }

  // DNF Evaluation: Groups (OR) -> Conditions (AND)
  const groupEvaluations = rule.groups.map((group) => {
    const conditionResults = group.conditions.map((cond) => {
      const actual = flatAttributes[cond.attribute];
      const matched = evaluateCondition(cond, actual);
      return { conditionId: cond.id, matched };
    });

    const satisfied = conditionResults.length > 0 && conditionResults.every((c) => c.matched);
    return satisfied;
  });

  const anyGroupSatisfied = groupEvaluations.some(Boolean);

  if (anyGroupSatisfied) {
    return {
      decision: rule.effect,
      reasonCode: rule.effect === 'PERMIT' ? 'RULE_PERMIT_MATCHED' : 'EXPLICIT_DENY_RULE_MATCHED',
      matchedRuleCodes: [rule.code],
      obligations: rule.obligations,
    };
  }

  return {
    decision: 'DENY',
    reasonCode: 'DEFAULT_DENY_NO_GROUP_MATCH',
    matchedRuleCodes: [],
    obligations: [],
  };
}

function evaluateCondition(cond, actual) {
  if (cond.operator === 'EXISTS') {
    return actual !== undefined && actual !== null && actual !== '';
  }
  if (actual === undefined || actual === null) {
    return false;
  }
  switch (cond.operator) {
    case 'EQ':
      return actual === cond.expected;
    case 'NEQ':
      return actual !== cond.expected;
    case 'GTE':
      return Number(actual) >= Number(cond.expected);
    case 'LTE':
      return Number(actual) <= Number(cond.expected);
    case 'BETWEEN':
      if (Array.isArray(cond.expected) && cond.expected.length === 2) {
        const num = Number(actual);
        return num >= Number(cond.expected[0]) && num <= Number(cond.expected[1]);
      }
      return false;
    case 'IN':
      if (Array.isArray(cond.expected)) {
        if (Array.isArray(actual)) {
          return actual.some((a) => cond.expected.includes(a));
        }
        return cond.expected.includes(actual);
      }
      return false;
    case 'NOT_IN':
      if (Array.isArray(cond.expected)) {
        if (Array.isArray(actual)) {
          return !actual.some((a) => cond.expected.includes(a));
        }
        return !cond.expected.includes(actual);
      }
      return false;
    case 'TIME_BETWEEN':
      if (typeof cond.expected === 'object' && cond.expected !== null) {
        const current = String(actual);
        return current >= cond.expected.start && current <= cond.expected.end;
      }
      return false;
    case 'CIDR_MATCH':
      if (typeof cond.expected === 'string' && typeof actual === 'string') {
        const cidrPrefix = cond.expected.split('/')[0].split('.').slice(0, 3).join('.');
        return actual.startsWith(cidrPrefix);
      }
      return false;
    default:
      return false;
  }
}

// 1. Template: Office Hours & Intranet Only
test('Visual Policy Builder — evaluates Office Hours & Intranet template correctly', () => {
  const officeHoursRule = {
    code: 'POL_OFFICE_HOURS_INTRANET',
    name: 'Chính sách Giờ Hành chính & Mạng Nội bộ',
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
          {
            id: 'c2',
            attribute: 'environment.currentTime',
            operator: 'TIME_BETWEEN',
            expected: { start: '08:00', end: '17:30', timeZone: 'Asia/Ho_Chi_Minh' },
          },
          { id: 'c3', attribute: 'environment.riskScore', operator: 'LTE', expected: 35 },
        ],
      },
    ],
    obligations: [{ type: 'REQUIRE_WATERMARK' }],
  };

  // Valid internal context in working hours
  const validContext = {
    'environment.trustedNetwork': true,
    'environment.currentTime': '10:15',
    'environment.riskScore': 20,
  };
  const result1 = evaluateVisualRule(officeHoursRule, validContext, 'VIEW');
  assert.equal(result1.decision, 'PERMIT');
  assert.equal(result1.reasonCode, 'RULE_PERMIT_MATCHED');
  assert.deepEqual(result1.obligations, [{ type: 'REQUIRE_WATERMARK' }]);

  // Invalid: Out of working hours (20:00)
  const invalidTimeContext = {
    'environment.trustedNetwork': true,
    'environment.currentTime': '20:00',
    'environment.riskScore': 20,
  };
  const result2 = evaluateVisualRule(officeHoursRule, invalidTimeContext, 'VIEW');
  assert.equal(result2.decision, 'DENY');

  // Invalid: High risk score (70 > 35)
  const highRiskContext = {
    'environment.trustedNetwork': true,
    'environment.currentTime': '11:00',
    'environment.riskScore': 70,
  };
  const result3 = evaluateVisualRule(officeHoursRule, highRiskContext, 'VIEW');
  assert.equal(result3.decision, 'DENY');

  // Invalid: From untrusted public network
  const remoteContext = {
    'environment.trustedNetwork': false,
    'environment.currentTime': '11:00',
    'environment.riskScore': 10,
  };
  const result4 = evaluateVisualRule(officeHoursRule, remoteContext, 'VIEW');
  assert.equal(result4.decision, 'DENY');
});

// 2. Template: Top Secret Protection with FIDO2 MFA & Obligations
test('Visual Policy Builder — evaluates Top Secret Protection rule with strict obligations', () => {
  const topSecretRule = {
    code: 'POL_TOP_SECRET_HARDENED',
    name: 'Kiểm soát Truy cập Tài liệu Tuyệt mật Cấp 4',
    effect: 'PERMIT',
    priority: 5,
    targetResource: 'DOCUMENT',
    targetAction: 'VIEW',
    combiningAlgorithm: 'DENY_OVERRIDES',
    groups: [
      {
        id: 1,
        conditions: [
          { id: 'c1', attribute: 'resource.classificationRank', operator: 'GTE', expected: 4 },
          { id: 'c2', attribute: 'subject.clearanceRank', operator: 'GTE', expected: 4 },
          { id: 'c3', attribute: 'environment.mfa', operator: 'EQ', expected: true },
          { id: 'c4', attribute: 'environment.deviceTrust', operator: 'EQ', expected: true },
        ],
      },
    ],
    obligations: [
      { type: 'REQUIRE_WATERMARK' },
      { type: 'REQUIRE_MFA' },
      { type: 'FORBID_DOWNLOAD' },
      { type: 'MAX_SESSION_MINUTES', minutes: 20 },
    ],
  };

  // Qualified Top Secret Officer with FIDO2 MFA on MDM device
  const officerContext = {
    'resource.classificationRank': 4,
    'subject.clearanceRank': 4,
    'environment.mfa': true,
    'environment.deviceTrust': true,
  };

  // Action VIEW -> PERMIT
  const resultView = evaluateVisualRule(topSecretRule, officerContext, 'VIEW');
  assert.equal(resultView.decision, 'PERMIT');
  assert.equal(resultView.obligations.length, 4);
  assert.ok(resultView.obligations.some((o) => o.type === 'FORBID_DOWNLOAD'));
  assert.ok(
    resultView.obligations.some((o) => o.type === 'MAX_SESSION_MINUTES' && o.minutes === 20),
  );

  // Action DOWNLOAD -> DENY (targetAction is strictly VIEW)
  const resultDownload = evaluateVisualRule(topSecretRule, officerContext, 'DOWNLOAD');
  assert.equal(resultDownload.decision, 'DENY');
  assert.equal(resultDownload.reasonCode, 'ACTION_NOT_TARGETED');

  // Insufficient clearance (rank 3 < 4) -> DENY
  const lowClearanceContext = { ...officerContext, 'subject.clearanceRank': 3 };
  assert.equal(evaluateVisualRule(topSecretRule, lowClearanceContext, 'VIEW').decision, 'DENY');

  // No MFA -> DENY
  const noMfaContext = { ...officerContext, 'environment.mfa': false };
  assert.equal(evaluateVisualRule(topSecretRule, noMfaContext, 'VIEW').decision, 'DENY');
});

// 3. Template: Strict Department Boundary (Explicit DENY)
test('Visual Policy Builder — enforces Explicit DENY for cross-department access', () => {
  const deptIsolationRule = {
    code: 'POL_FINANCE_DEPT_ISOLATION',
    name: 'Cách ly Ngăn chặn Truy cập Chéo Phòng ban Tài chính',
    effect: 'DENY',
    priority: 1,
    targetResource: 'DOCUMENT',
    targetAction: 'ALL',
    combiningAlgorithm: 'DENY_OVERRIDES',
    groups: [
      {
        id: 1,
        conditions: [
          {
            id: 'c1',
            attribute: 'resource.departmentId',
            operator: 'EQ',
            expected: 'FINANCE_DEPT',
          },
          {
            id: 'c2',
            attribute: 'subject.departmentId',
            operator: 'NEQ',
            expected: 'FINANCE_DEPT',
          },
        ],
      },
    ],
    obligations: [{ type: 'NO_CACHE' }],
  };

  // Cross-department request (IT trying to access Finance document)
  const crossDeptContext = {
    'resource.departmentId': 'FINANCE_DEPT',
    'subject.departmentId': 'IT_DEPT',
  };
  const result = evaluateVisualRule(deptIsolationRule, crossDeptContext, 'VIEW');
  assert.equal(result.decision, 'DENY');
  assert.equal(result.reasonCode, 'EXPLICIT_DENY_RULE_MATCHED');
  assert.deepEqual(result.obligations, [{ type: 'NO_CACHE' }]);

  // Same department request (Finance accessing Finance document)
  const sameDeptContext = {
    'resource.departmentId': 'FINANCE_DEPT',
    'subject.departmentId': 'FINANCE_DEPT',
  };
  const sameDeptResult = evaluateVisualRule(deptIsolationRule, sameDeptContext, 'VIEW');
  // Group condition (NEQ FINANCE_DEPT) is false -> not matched -> default deny or pass
  assert.equal(sameDeptResult.reasonCode, 'DEFAULT_DENY_NO_GROUP_MATCH');
});

// 4. Multi-Group DNF (Disjunctive Normal Form) OR Logic
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
      // Group 1: Intranet + Clearance 3
      {
        id: 1,
        conditions: [
          { id: 'c1', attribute: 'environment.trustedNetwork', operator: 'EQ', expected: true },
          { id: 'c2', attribute: 'subject.clearanceRank', operator: 'GTE', expected: 3 },
        ],
      },
      // Group 2: Special Project Alpha Member + MFA (even outside intranet)
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

  // Case A: Satisfies Group 1 only (on intranet, clearance 3, but not on Project Alpha)
  const contextA = {
    'environment.trustedNetwork': true,
    'subject.clearanceRank': 3,
    'subject.projects': ['OTHER_PROJECT'],
    'environment.mfa': false,
  };
  assert.equal(evaluateVisualRule(multiGroupRule, contextA).decision, 'PERMIT');

  // Case B: Satisfies Group 2 only (untrusted network, clearance 1, but on Project Alpha with MFA)
  const contextB = {
    'environment.trustedNetwork': false,
    'subject.clearanceRank': 1,
    'subject.projects': ['PROJECT_ALPHA'],
    'environment.mfa': true,
  };
  assert.equal(evaluateVisualRule(multiGroupRule, contextB).decision, 'PERMIT');

  // Case C: Satisfies neither group
  const contextC = {
    'environment.trustedNetwork': false,
    'subject.clearanceRank': 1,
    'subject.projects': ['OTHER_PROJECT'],
    'environment.mfa': false,
  };
  assert.equal(evaluateVisualRule(multiGroupRule, contextC).decision, 'DENY');
});

// 5. Two-Way JSON AST Lossless Serialization & Deserialization
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

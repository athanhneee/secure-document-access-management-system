import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { registerHooks } from 'node:module';
import { describe, it } from 'node:test';

// Cho phép Node 24 native TS loader phân giải import nội bộ không có hậu tố `.ts` của Next.js
registerHooks({
  resolve(specifier, context, nextResolve) {
    try {
      return nextResolve(specifier, context);
    } catch (error) {
      if (specifier.startsWith('./') || specifier.startsWith('../')) {
        return nextResolve(`${specifier}.ts`, context);
      }
      throw error;
    }
  },
});

const { evaluatePolicySimulation, evaluatePolicySetSimulation, mergeSimulationObligations } =
  await import('../../apps/web/components/abac/simulator-evaluator.ts');

const BASELINE_DB_RULES = [
  {
    id: '1',
    code: 'POL-DENY-HIGH-RISK-SESSION',
    name: 'Từ chối truy cập khi điểm rủi ro phiên vượt ngưỡng an toàn',
    description: 'Chặn mọi hành động trên tài liệu nếu điểm rủi ro môi trường >= 80',
    effect: 'DENY',
    priority: 10,
    targetResource: 'DOCUMENT',
    targetAction: 'ALL',
    combiningAlgorithm: 'DENY_OVERRIDES',
    groups: [
      {
        id: 1,
        conditions: [
          { id: 'c1', attribute: 'environment.riskScore', operator: 'GTE', expected: 80 },
        ],
      },
    ],
    obligations: [{ type: 'NO_CACHE' }],
  },
  {
    id: '2',
    code: 'POL-DENY-TOP-SECRET-WITHOUT-MFA',
    name: 'Bắt buộc xác thực đa yếu tố (MFA) đối với tài liệu Tuyệt mật',
    description:
      'Chặn mọi thao tác (tra cứu, xem, tải, chia sẻ, quản trị) trên tài liệu hạng 4 (TOP_SECRET) khi phiên chưa hoàn tất xác thực MFA',
    effect: 'DENY',
    priority: 20,
    targetResource: 'DOCUMENT',
    targetAction: 'ALL',
    combiningAlgorithm: 'DENY_OVERRIDES',
    groups: [
      {
        id: 1,
        conditions: [
          { id: 'c2', attribute: 'resource.classificationRank', operator: 'GTE', expected: 4 },
          { id: 'c3', attribute: 'environment.mfa', operator: 'EQ', expected: false },
        ],
      },
    ],
    obligations: [{ type: 'REQUIRE_MFA' }],
  },
  {
    id: '3',
    code: 'POL-PERMIT-CLEARED-ACTIVE-STAFF',
    name: 'Cho phép nhân sự đang hoạt động truy cập tài liệu đủ cấp độ mật',
    description: 'Cho phép nhân sự ACTIVE/ACTIVE_STAFF truy cập tài liệu ACTIVE',
    effect: 'PERMIT',
    priority: 100,
    targetResource: 'DOCUMENT',
    targetAction: 'ALL',
    combiningAlgorithm: 'DENY_OVERRIDES',
    groups: [
      {
        id: 1,
        conditions: [
          {
            id: 'c4',
            attribute: 'subject.employmentStatus',
            operator: 'IN',
            expected: ['ACTIVE', 'ACTIVE_STAFF'],
          },
          { id: 'c5', attribute: 'resource.status', operator: 'EQ', expected: 'ACTIVE' },
        ],
      },
    ],
    obligations: [{ type: 'REQUIRE_WATERMARK' }, { type: 'NO_CACHE' }],
  },
];

const BASE_SUBJECT = {
  clearanceRank: 4,
  departmentId: '1',
  employmentStatus: 'ACTIVE',
  projects: ['ALPHA'],
};

const BASE_RESOURCE = {
  classificationRank: 4,
  departmentId: '1',
  category: 'SECURITY_OPERATIONS',
  status: 'ACTIVE',
  ownerId: '1',
};

const BASE_ENV = {
  currentTime: '10:30',
  ip: '192.168.1.10',
  trustedNetwork: true,
  deviceTrust: true,
  mfa: true,
  riskScore: 10,
};

describe('Local ABAC Simulator (Bell-LaPadula + Full DB Policy Set + Step-Up MFA)', () => {
  it('enforces Bell-LaPadula Simple Security Property in both single-rule and policy-set simulation', () => {
    const lowClearanceSubject = { ...BASE_SUBJECT, clearanceRank: 2 };
    const single = evaluatePolicySimulation(
      BASELINE_DB_RULES[2],
      'VIEW',
      lowClearanceSubject,
      BASE_RESOURCE,
      BASE_ENV,
    );
    assert.equal(single.decision, 'DENY');
    assert.equal(single.reasonCode, 'INSUFFICIENT_CLEARANCE');
    assert.equal(single.bellLaPadulaBlocked, true);
    assert.deepEqual(single.obligations, []);

    const multi = evaluatePolicySetSimulation(
      BASELINE_DB_RULES,
      'VIEW',
      lowClearanceSubject,
      BASE_RESOURCE,
      BASE_ENV,
    );
    assert.equal(multi.decision, 'DENY');
    assert.equal(multi.reasonCode, 'INSUFFICIENT_CLEARANCE');
    assert.equal(multi.bellLaPadulaBlocked, true);
  });

  it('evaluates all 3 baseline DB policies accurately with DENY_OVERRIDES, STEP_UP_MFA_REQUIRED and DEFAULT_DENY', () => {
    // 1. Law 1: high riskScore >= 80 -> EXPLICIT_DENY (even with MFA and clearance 4)
    const highRisk = evaluatePolicySetSimulation(
      BASELINE_DB_RULES,
      'VIEW',
      BASE_SUBJECT,
      BASE_RESOURCE,
      { ...BASE_ENV, riskScore: 85 },
    );
    assert.equal(highRisk.decision, 'DENY');
    assert.equal(highRisk.reasonCode, 'EXPLICIT_DENY');
    assert.ok(highRisk.matchedRuleCodes.includes('POL-DENY-HIGH-RISK-SESSION'));
    assert.deepEqual(highRisk.obligations, []);

    // 2. Law 2: TOP_SECRET without MFA on DOWNLOAD & SHARE -> STEP_UP_MFA_REQUIRED
    for (const action of ['VIEW', 'DOWNLOAD', 'SHARE']) {
      const mfaBlocked = evaluatePolicySetSimulation(
        BASELINE_DB_RULES,
        action,
        BASE_SUBJECT,
        BASE_RESOURCE,
        { ...BASE_ENV, mfa: false, riskScore: 30 },
      );
      assert.equal(mfaBlocked.decision, 'DENY');
      assert.equal(mfaBlocked.reasonCode, 'STEP_UP_MFA_REQUIRED');
      assert.ok(mfaBlocked.matchedRuleCodes.includes('POL-DENY-TOP-SECRET-WITHOUT-MFA'));
      assert.deepEqual(mfaBlocked.obligations, []);
    }

    // 3. Combined Law 1 (risk >= 80) + Law 2 (no MFA) -> stays EXPLICIT_DENY (not STEP_UP_MFA_REQUIRED)
    const combined = evaluatePolicySetSimulation(
      BASELINE_DB_RULES,
      'VIEW',
      BASE_SUBJECT,
      BASE_RESOURCE,
      { ...BASE_ENV, mfa: false, riskScore: 90 },
    );
    assert.equal(combined.decision, 'DENY');
    assert.equal(combined.reasonCode, 'EXPLICIT_DENY');

    // 4. Law 3: Active staff + MFA + low risk -> PERMIT with merged obligations
    const permitted = evaluatePolicySetSimulation(
      BASELINE_DB_RULES,
      'VIEW',
      BASE_SUBJECT,
      BASE_RESOURCE,
      BASE_ENV,
    );
    assert.equal(permitted.decision, 'PERMIT');
    assert.equal(permitted.reasonCode, 'POLICY_PERMIT');
    assert.deepEqual(permitted.matchedRuleCodes, ['POL-PERMIT-CLEARED-ACTIVE-STAFF']);
    assert.deepEqual(permitted.obligations, [{ type: 'REQUIRE_WATERMARK' }, { type: 'NO_CACHE' }]);

    // 5. CONTRACTOR -> DEFAULT_DENY
    const contractor = evaluatePolicySetSimulation(
      BASELINE_DB_RULES,
      'VIEW',
      { ...BASE_SUBJECT, employmentStatus: 'CONTRACTOR' },
      BASE_RESOURCE,
      BASE_ENV,
    );
    assert.equal(contractor.decision, 'DENY');
    assert.equal(contractor.reasonCode, 'DEFAULT_DENY');
  });

  it('merges MAX_SESSION_MINUTES using shortest duration in canonical order', () => {
    const merged = mergeSimulationObligations([
      { type: 'NO_CACHE' },
      { type: 'MAX_SESSION_MINUTES', minutes: 60 },
      { type: 'REQUIRE_WATERMARK' },
      { type: 'MAX_SESSION_MINUTES', minutes: 15 },
    ]);
    assert.deepEqual(merged, [
      { type: 'REQUIRE_WATERMARK' },
      { type: 'MAX_SESSION_MINUTES', minutes: 15 },
      { type: 'NO_CACHE' },
    ]);
  });

  it('wires AbacTab simulator to active DB policies rather than hardcoded PRESET_POLICY_TEMPLATES[0]', async () => {
    const [abacTabSrc, dialogSrc, uiLabelsSrc] = await Promise.all([
      readFile(new URL('../../apps/web/app/admin/tabs/abac-tab.tsx', import.meta.url), 'utf8'),
      readFile(
        new URL('../../apps/web/components/abac/policy-simulator-dialog.tsx', import.meta.url),
        'utf8',
      ),
      readFile(new URL('../../apps/web/lib/ui-labels.ts', import.meta.url), 'utf8'),
    ]);

    assert.doesNotMatch(abacTabSrc, /PRESET_POLICY_TEMPLATES/u);
    assert.match(abacTabSrc, /policySet=\{activeDbVisualRules\}/u);
    assert.match(dialogSrc, /evaluatePolicySetSimulation/u);
    assert.match(uiLabelsSrc, /INSUFFICIENT_CLEARANCE:/u);
    assert.match(uiLabelsSrc, /STEP_UP_MFA_REQUIRED:/u);
    assert.match(uiLabelsSrc, /EXPLICIT_DENY:/u);
  });
});

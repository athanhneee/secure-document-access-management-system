import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';
import {
  buildCategorySelectOptions,
  buildDepartmentSelectOptions,
  buildDynamicAttributeRegistry,
} from '../../apps/web/components/abac/abac-presets.ts';
import {
  applyOptimisticDepartmentActive,
  applyOptimisticPolicyActive,
  applyOptimisticRoleEnable,
  applyOptimisticUserStatus,
} from '../../apps/web/lib/optimistic-state.ts';
import { localizeApiErrorMessage } from '../../apps/web/lib/api-error-messages.ts';

describe('Admin ABAC Dynamic Registry, Obligations & Immediate Logout Contracts', () => {
  it('builds dynamic ABAC attribute registry using live DB numeric department IDs and category codes', () => {
    const departments = [
      { id: '10', code: 'FINANCE_TREASURY', name: 'Khối Tài chính' },
      { id: '12', code: 'NEW_AI_LAB', name: 'Phòng Nghiên cứu AI' },
    ];
    const categories = [
      { id: '1', code: 'FINANCIAL_REPORTS', name: 'Báo cáo tài chính' },
      { id: '2', code: 'AI_BLUEPRINTS', name: 'Thiết kế AI' },
    ];
    const registry = buildDynamicAttributeRegistry(departments, categories);

    assert.deepEqual(buildDepartmentSelectOptions(departments), [
      { label: 'Khối Tài chính (FINANCE_TREASURY)', value: '10' },
      { label: 'Phòng Nghiên cứu AI (NEW_AI_LAB)', value: '12' },
    ]);
    assert.deepEqual(registry['subject.departmentId']?.options, [
      { label: 'Khối Tài chính (FINANCE_TREASURY)', value: '10' },
      { label: 'Phòng Nghiên cứu AI (NEW_AI_LAB)', value: '12' },
    ]);
    assert.equal(registry['subject.departmentId']?.defaultValue, '10');
    assert.equal(registry['resource.departmentId']?.defaultValue, '10');
    assert.deepEqual(buildCategorySelectOptions(categories), [
      { label: 'Báo cáo tài chính (FINANCIAL_REPORTS)', value: 'FINANCIAL_REPORTS' },
      { label: 'Thiết kế AI (AI_BLUEPRINTS)', value: 'AI_BLUEPRINTS' },
    ]);
    assert.equal(registry['resource.category']?.defaultValue, 'FINANCIAL_REPORTS');
    assert.ok(
      registry['subject.employmentStatus']?.options?.some((o) => o.value === 'ACTIVE_STAFF'),
    );
    assert.ok(registry['resource.status']?.options?.some((o) => o.value === 'DELETED'));
  });

  it('supports optimistic reactivate, department toggle, role enable, policy deactivate, and Vietnamese errors', () => {
    const users = applyOptimisticUserStatus(
      [{ id: '1', status: 'DISABLED', version: 2 }],
      '1',
      'reactivate',
    );
    assert.equal(users[0]?.status, 'ACTIVE');
    assert.equal(users[0]?.version, 3);

    const depts = applyOptimisticDepartmentActive(
      [{ id: '4', isActive: true, version: 0 }],
      '4',
      false,
    );
    assert.equal(depts[0]?.isActive, false);
    assert.equal(depts[0]?.version, 1);

    const roles = applyOptimisticRoleEnable([{ id: '7', isActive: false, version: 1 }], '7');
    assert.equal(roles[0]?.isActive, true);
    assert.equal(roles[0]?.version, 2);

    const policies = applyOptimisticPolicyActive([{ id: '2', isActive: true }], '2', false);
    assert.equal(policies[0]?.isActive, false);

    assert.match(
      localizeApiErrorMessage(400, { message: 'validTo must be in the future' }),
      /tương lai/u,
    );
    assert.match(
      localizeApiErrorMessage(400, { message: 'validFrom cannot be in the past' }),
      /quá khứ/u,
    );
    assert.match(
      localizeApiErrorMessage(400, { message: 'Disabled accounts cannot be unlocked.' }),
      /Kích hoạt lại/u,
    );
    assert.match(
      localizeApiErrorMessage(409, {
        message: 'Role assignment history prevents deletion; disable the role instead.',
      }),
      /Vô hiệu hóa/u,
    );
  });

  it('wires immediate session expiration on USER_SESSION_REVOKED and 401 without ever logging out on 403', async () => {
    const [apiClientSrc, authContextSrc, loginPageSrc] = await Promise.all([
      readFile(new URL('../../apps/web/lib/api-client.ts', import.meta.url), 'utf8'),
      readFile(new URL('../../apps/web/lib/auth-context.tsx', import.meta.url), 'utf8'),
      readFile(new URL('../../apps/web/app/login/page.tsx', import.meta.url), 'utf8'),
    ]);
    assert.match(apiClientSrc, /emitSessionExpired\('session_revoked'\)/u);
    assert.doesNotMatch(apiClientSrc, /status === 403[\s\S]{0,120}emitSessionExpired/u);
    assert.match(authContextSrc, /USER_SESSION_REVOKED/u);
    assert.match(authContextSrc, /subscribeSessionExpired/u);
    assert.match(authContextSrc, /\/login\?reason=/u);
    assert.match(loginPageSrc, /searchParams\.get\('reason'\)/u);
  });

  it('enforces Admin UI rule gates: self-lock hidden, reactivate dialog, active roles filter, past-date guard, ABAC obligations & EXISTS widget', async () => {
    const [usersTab, assignModal, abacHelpers, abacTab, expectedWidget, simEvaluator] =
      await Promise.all([
        readFile(new URL('../../apps/web/app/admin/tabs/users-tab.tsx', import.meta.url), 'utf8'),
        readFile(
          new URL('../../apps/web/app/admin/modals/assign-role-modal.tsx', import.meta.url),
          'utf8',
        ),
        readFile(new URL('../../apps/web/app/admin/abac-helpers.ts', import.meta.url), 'utf8'),
        readFile(new URL('../../apps/web/app/admin/tabs/abac-tab.tsx', import.meta.url), 'utf8'),
        readFile(
          new URL('../../apps/web/components/abac/expected-value-widget.tsx', import.meta.url),
          'utf8',
        ),
        readFile(
          new URL('../../apps/web/components/abac/simulator-evaluator.ts', import.meta.url),
          'utf8',
        ),
      ]);

    assert.match(usersTab, /const isSelf = Boolean\(currentUserId && u\.id === currentUserId\)/u);
    assert.match(usersTab, /action: 'reactivate'/u);
    assert.match(assignModal, /roles\.filter\(\(r\) => r\.isActive\)/u);
    assert.match(assignModal, /min=\{minDateTimeLocal\}/u);
    assert.match(assignModal, /UserRoleAssignmentsList/u);
    assert.match(abacHelpers, /export function normalizeVisualObligations/u);
    assert.match(abacTab, /canManagePolicies/u);
    assert.match(abacTab, /canSimulatePolicy/u);
    assert.match(abacTab, /onDeactivatePolicy/u);
    assert.match(abacTab, /onDeletePolicy/u);
    assert.match(expectedWidget, /if \(operator === 'EXISTS'\)/u);
    assert.match(simEvaluator, /return exists === Boolean\(cond\.expected\)/u);
  });
});

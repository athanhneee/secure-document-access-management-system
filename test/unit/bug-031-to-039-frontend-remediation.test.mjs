import assert from 'node:assert/strict';
import fs from 'node:fs';
import { registerHooks } from 'node:module';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname, '../../apps/web');

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith('@/')) {
      for (const ext of ['.ts', '.tsx']) {
        const candidate = path.join(webRoot, `${specifier.slice(2)}${ext}`);
        if (fs.existsSync(candidate)) {
          return { url: pathToFileURL(candidate).href, shortCircuit: true };
        }
      }
    }
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

const { STATUS_LABELS, VALID_TRANSITIONS } =
  await import('../../apps/web/app/security/modals/alert-status-config.ts');
const { resolveNotificationHref } =
  await import('../../apps/web/components/navigation/notification-routing.ts');
const { ApiError, isPreMfaApiError } = await import('../../apps/web/lib/api-client.ts');
const { buildAssignableRoleScopeOptions } =
  await import('../../apps/web/app/admin/role-scope-options.ts');
const { normalizeAbacPolicyRow, resolveVisualRuleForPolicy } =
  await import('../../apps/web/app/admin/abac-helpers.ts');
const { simulatorCidrMatch, isValidCidr } =
  await import('../../apps/web/components/abac/cidr-matcher.ts');
const {
  evaluatePolicySetSimulation,
  evaluatePolicySimulation,
  isMissingAttribute,
  resolveSimulationDate,
} = await import('../../apps/web/components/abac/simulator-evaluator.ts');

function readWebFile(relPath) {
  return fs.readFileSync(path.join(webRoot, relPath), 'utf8');
}

describe('BUG-031 — Security Alert State Machine & Reopen Resolution Note Cleanup', () => {
  it('matches Backend VALID_ALERT_TRANSITIONS 1-to-1 and removes ghost ESCALATED state everywhere', () => {
    assert.deepEqual(VALID_TRANSITIONS, {
      OPEN: ['INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'],
      INVESTIGATING: ['RESOLVED', 'FALSE_POSITIVE', 'OPEN'],
      RESOLVED: ['INVESTIGATING'],
      FALSE_POSITIVE: ['INVESTIGATING'],
    });
    assert.equal('ESCALATED' in STATUS_LABELS, false);

    for (const rel of [
      'app/security/types.ts',
      'app/security/modals/alert-status-config.ts',
      'app/security/tabs/alerts-tab.tsx',
      'app/auditor/types.ts',
      'app/auditor/tabs/auditor-alerts-tab.tsx',
      'app/auditor/modals/auditor-alert-detail-modal.tsx',
      'lib/ui-labels.ts',
    ]) {
      assert.doesNotMatch(
        readWebFile(rel),
        /\bESCALATED\b/u,
        `${rel} must not contain ghost ESCALATED status`,
      );
    }

    const detailModalSrc = readWebFile('app/security/modals/alert-detail-modal.tsx');
    assert.match(detailModalSrc, /isReopeningInvestigation/u);
    assert.match(detailModalSrc, /\?\s*null/u);
  });
});

describe('BUG-032 & BUG-033 — ActiveSessionsTab Pagination & Security Modal Snapshots', () => {
  it('separates sessionsAllTotal vs sessionsFilteredTotal and enables pagination on ACTIVE filter', () => {
    const hookSrc = readWebFile('app/security/hooks/use-security-data.ts');
    const tabSrc = readWebFile('app/security/tabs/active-sessions-tab.tsx');
    const workspaceSrc = readWebFile('app/security/security-workspace.tsx');

    assert.match(hookSrc, /sessionsAllTotal/u);
    assert.match(hookSrc, /sessionsFilteredTotal/u);
    assert.doesNotMatch(tabSrc, /statusFilter !== 'ACTIVE' && totalPages > 1/u);
    assert.match(tabSrc, /effectiveFilteredTotal/u);
    assert.match(tabSrc, /Xem toàn bộ lịch sử \(\$\{totalCount\}\)/u);
    assert.match(workspaceSrc, /totalCount=\{data\.sessionsAllTotal\}/u);
    assert.match(workspaceSrc, /filteredCount=\{data\.sessionsFilteredTotal\}/u);
  });

  it('preserves modal item snapshots across SSE refreshes and guards inactive sessions in TerminateSessionModal', () => {
    const workspaceSrc = readWebFile('app/security/security-workspace.tsx');
    const alertModalSrc = readWebFile('app/security/modals/alert-detail-modal.tsx');
    const termModalSrc = readWebFile('app/security/modals/terminate-session-modal.tsx');

    assert.match(workspaceSrc, /selectedAlertSnapshot/u);
    assert.match(workspaceSrc, /pendingTerminateSessionSnapshot/u);
    assert.match(alertModalSrc, /open && alert \?/u);
    assert.match(termModalSrc, /open && session \?/u);
    assert.match(termModalSrc, /isSessionInactive = session\.status !== 'ACTIVE'/u);
    assert.match(termModalSrc, /disabled=\{isSubmitting \|\| isSessionInactive\}/u);
  });
});

describe('BUG-034 — Fine-Grained Tab Permission Checks in resolveNotificationHref', () => {
  it('hides detail link when target tab permission is missing and routes SOC incidents & Auditor exports', () => {
    const makeCaps = (portals, perms) => {
      const permSet = new Set(perms);
      return {
        canAccessOwner: portals.includes('OWNER'),
        canAccessReader: portals.includes('READER'),
        canAccessSecurity: portals.includes('SECURITY'),
        canAccessAuditor: portals.includes('AUDITOR'),
        hasPermission: (p) => permSet.has(p),
      };
    };

    // Owner WITH AUDIT_LOG:VIEW sees /owner?tab=history on INCIDENT_REPORT_SUBMITTED
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'INCIDENT_REPORT_SUBMITTED', relatedObjectType: 'INCIDENT_REPORT' },
        makeCaps(['OWNER'], ['DOCUMENT:UPLOAD', 'AUDIT_LOG:VIEW']),
      ),
      '/owner?tab=history',
    );

    // Owner WITHOUT AUDIT_LOG:VIEW gets null (no dead link to hidden history tab)
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'INCIDENT_REPORT_SUBMITTED', relatedObjectType: 'INCIDENT_REPORT' },
        makeCaps(['OWNER'], ['DOCUMENT:UPLOAD']),
      ),
      null,
    );

    // Custom Owner WITHOUT ACCESS_REQUEST:DECIDE/VIEW_OWN gets null on ACCESS_REQUEST_CREATED
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'ACCESS_REQUEST_CREATED', relatedObjectType: 'ACCESS_REQUEST' },
        makeCaps(['OWNER'], ['DOCUMENT:UPLOAD']),
      ),
      null,
    );

    // Reader WITHOUT ACCESS_REQUEST:VIEW_OWN gets null on ACCESS_REQUEST_REJECTED
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'ACCESS_REQUEST_REJECTED', relatedObjectType: 'ACCESS_REQUEST' },
        makeCaps(['READER'], ['DOCUMENT:DISCOVER']),
      ),
      null,
    );

    // SOC Officer routes incident notifications to /security?tab=incidents
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'INCIDENT_REPORT_SUBMITTED', relatedObjectType: 'INCIDENT_REPORT' },
        makeCaps(['SECURITY'], ['SECURITY_ALERT:VIEW', 'INCIDENT_REPORT:MANAGE']),
      ),
      '/security?tab=incidents',
    );

    // Auditor with export permission routes export notifications to /auditor?tab=exports
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'EXPORT_JOB_COMPLETED', relatedObjectType: 'ASYNC_EXPORT_JOB' },
        makeCaps(['AUDITOR'], ['AUDIT_LOG:VIEW', 'AUDIT_LOG:EXPORT']),
      ),
      '/auditor?tab=exports',
    );

    // Auditor WITHOUT export permission gets null for export notifications
    assert.equal(
      resolveNotificationHref(
        { notificationType: 'EXPORT_JOB_COMPLETED', relatedObjectType: 'ASYNC_EXPORT_JOB' },
        makeCaps(['AUDITOR'], ['AUDIT_LOG:VIEW']),
      ),
      null,
    );
  });
});

describe('BUG-035 & BUG-036 — SSE Single-Refresh Gate & Pre-MFA Boot Preservation', () => {
  it('prevents recursive 0ms SSE reconnect loops via refreshAttemptedSinceOpen while preserving RECENT_REFRESH_WINDOW_MS', () => {
    const sseSrc = readWebFile('lib/realtime-events.ts');
    const refreshSrc = readWebFile('lib/api-refresh.ts');

    assert.match(sseSrc, /private refreshAttemptedSinceOpen = false/u);
    assert.match(
      sseSrc,
      /if \(this\.refreshAttemptedSinceOpen\)\s*\{\s*this\.scheduleReconnect\(\);\s*return;\s*\}/u,
    );
    assert.match(refreshSrc, /const RECENT_REFRESH_WINDOW_MS = 1_200/u);
  });

  it('detects Pre-MFA 401 errors, subscribes at AuthProvider mount, and preserves /mfa query params', () => {
    const preMfaErr = new ApiError(401, {
      statusCode: 401,
      message: 'MFA verification is required.',
    });
    const revokedErr = new ApiError(401, {
      statusCode: 401,
      message: 'Session is no longer valid.',
    });
    assert.equal(isPreMfaApiError(preMfaErr), true);
    assert.equal(isPreMfaApiError(revokedErr), false);

    const authCtxSrc = readWebFile('lib/auth-context.tsx');
    const authGuardSrc = readWebFile('components/auth-guard.tsx');

    assert.match(authCtxSrc, /mfaPending/u);
    assert.match(authCtxSrc, /if \(!pathname\?\.startsWith\('\/mfa'\)\)/u);
    assert.match(authGuardSrc, /if \(mfaPending\)/u);
    assert.match(authGuardSrc, /\/mfa\?redirect=/u);
  });
});

describe('BUG-038 — Admin AssignRoleModal Department Ancestor Scope Filtering', () => {
  const companyTree = [
    { id: '1', code: 'HQ', name: 'Trụ sở chính', parentId: null, isActive: true, version: 0 },
    { id: '2', code: 'FIN', name: 'Khối Tài chính', parentId: '1', isActive: true, version: 0 },
    { id: '3', code: 'ACC', name: 'Phòng Kế toán', parentId: '2', isActive: true, version: 0 },
    { id: '4', code: 'TAX', name: 'Tổ Thuế', parentId: '3', isActive: true, version: 0 },
    { id: '5', code: 'ENG', name: 'Khối Kỹ thuật', parentId: '1', isActive: true, version: 0 },
  ];

  it('allows Global Admin to pick Global (null) or targetUser ancestor chain, excluding cross-branch/child departments', () => {
    const options = buildAssignableRoleScopeOptions({
      targetDepartmentId: '3',
      departments: companyTree,
      hasGlobalUserManage: true,
      userManageDepartmentIds: [],
    });

    assert.deepEqual(
      options.map((o) => o.scopeDepartmentId),
      [null, '3', '2', '1'],
      'Must include Global + ACC(3) -> FIN(2) -> HQ(1), excluding child TAX(4) and sibling ENG(5)',
    );
  });

  it('restricts Department-Scoped Admin to in-scope ancestors of targetUser and defaults to valid department', () => {
    const options = buildAssignableRoleScopeOptions({
      targetDepartmentId: '3',
      departments: companyTree,
      hasGlobalUserManage: false,
      userManageDepartmentIds: ['2'], // Admin manages FIN(2) subtree, NOT HQ(1) and NOT Global
    });

    assert.deepEqual(
      options.map((o) => o.scopeDepartmentId),
      ['3', '2'],
      'Scoped Admin on FIN(2) must only see ACC(3) and FIN(2), never Global(null) or parent HQ(1)',
    );
    assert.equal(options[0]?.scopeDepartmentId, '3');
  });
});

describe('BUG-039 — Local ABAC Simulator 1-to-1 Semantic Parity with Backend PDP', () => {
  const baseSubject = {
    clearanceRank: 4,
    departmentId: '1',
    employmentStatus: 'ACTIVE',
    projects: ['ALPHA', 'BETA'],
  };
  const baseResource = {
    classificationRank: 2,
    departmentId: '1',
    category: 'SECURITY_OPERATIONS',
    status: 'ACTIVE',
    ownerId: '1',
  };
  const baseEnv = {
    currentTime: '10:00',
    ip: '192.168.1.25',
    trustedNetwork: true,
    deviceTrust: true,
    mfa: true,
    riskScore: 10,
  };

  function makeSingleConditionRule(condition, extra = {}) {
    return {
      id: '10',
      code: 'POL_PARITY_TEST',
      name: 'Parity Test Rule',
      description: '',
      effect: 'PERMIT',
      priority: 10,
      targetResource: 'DOCUMENT',
      targetAction: 'ALL',
      combiningAlgorithm: 'DENY_OVERRIDES',
      groups: [{ id: 1, conditions: [{ id: 'c1', ...condition }] }],
      obligations: [],
      ...extra,
    };
  }

  it('enforces all 6 parity invariants: CIDR dual-stack, isMissingAttribute([]), matchArray EQ/NEQ, strict ===, [validFrom, validTo), and TIME_BETWEEN HH:MM/ISO', () => {
    // 1. CIDR parity: bare IP, IPv4-mapped IPv6, and cross-family IPv4 vs ::/0 rejection
    assert.equal(simulatorCidrMatch('192.168.1.25', '192.168.1.25'), true);
    assert.equal(simulatorCidrMatch('::ffff:192.168.1.25', '192.168.1.0/24'), true);
    assert.equal(simulatorCidrMatch('192.168.1.25', '::/0'), false);
    assert.equal(simulatorCidrMatch('fe80::1%eth0', 'fe80::/10'), true);
    assert.equal(isValidCidr('10.0.0.0/8'), true);

    // 2. isMissingAttribute: [] is missing, '' is NOT missing
    assert.equal(isMissingAttribute([]), true);
    assert.equal(isMissingAttribute(''), false);

    const neqProjectRule = makeSingleConditionRule({
      attribute: 'subject.projects',
      operator: 'NEQ',
      expected: 'FORBIDDEN_PROJ',
    });
    const emptyProjectsRes = evaluatePolicySimulation(
      neqProjectRule,
      'VIEW',
      { ...baseSubject, projects: [] },
      baseResource,
      baseEnv,
    );
    assert.equal(
      emptyProjectsRes.decision,
      'DENY',
      'Empty multi-value array [] must fail NEQ just like Backend (!exists -> false)',
    );

    const existsStringRule = makeSingleConditionRule({
      attribute: 'resource.category',
      operator: 'EXISTS',
      expected: true,
    });
    assert.equal(
      evaluatePolicySimulation(
        existsStringRule,
        'VIEW',
        baseSubject,
        { ...baseResource, category: '' },
        baseEnv,
      ).decision,
      'PERMIT',
    );

    // 3. matchArray for EQ (some) and NEQ (every)
    const eqProjectRule = makeSingleConditionRule({
      attribute: 'subject.projects',
      operator: 'EQ',
      expected: 'BETA',
    });
    assert.equal(
      evaluatePolicySimulation(eqProjectRule, 'VIEW', baseSubject, baseResource, baseEnv).decision,
      'PERMIT',
    );
    assert.equal(
      evaluatePolicySimulation(
        makeSingleConditionRule({
          attribute: 'subject.projects',
          operator: 'NEQ',
          expected: 'BETA',
        }),
        'VIEW',
        baseSubject,
        baseResource,
        baseEnv,
      ).decision,
      'DENY',
    );

    // 4. No loose type coercion ("1" !== 1) in IN / EQ
    const numericInRule = makeSingleConditionRule({
      attribute: 'subject.departmentId',
      operator: 'IN',
      expected: [1, 2],
    });
    assert.equal(
      evaluatePolicySimulation(numericInRule, 'VIEW', baseSubject, baseResource, baseEnv).decision,
      'DENY',
      'String departmentId "1" must not match numeric [1, 2] without type match',
    );

    // 5. Temporal validity [validFrom, validTo) + helper preservation
    const normalizedRow = normalizeAbacPolicyRow({
      id: 99,
      code: 'POL_TIMED',
      name: 'Timed Policy',
      effect: 'PERMIT',
      is_active: true,
      valid_from: '2026-01-01T00:00:00.000Z',
      valid_to: '2026-06-01T00:00:00.000Z',
      groups: [
        {
          id: 1,
          conditions: [{ id: 'c1', attribute: 'environment.mfa', operator: 'EQ', expected: true }],
        },
      ],
    });
    const visualTimedRule = resolveVisualRuleForPolicy(normalizedRow);
    assert.equal(visualTimedRule.validFrom, '2026-01-01T00:00:00.000Z');
    assert.equal(visualTimedRule.validTo, '2026-06-01T00:00:00.000Z');

    // Exact boundary validTo (half-open): now === validTo -> DENY
    assert.equal(
      evaluatePolicySetSimulation([visualTimedRule], 'VIEW', baseSubject, baseResource, {
        ...baseEnv,
        currentTime: '2026-06-01T00:00:00.000Z',
      }).decision,
      'DENY',
    );
    assert.equal(
      evaluatePolicySetSimulation([visualTimedRule], 'VIEW', baseSubject, baseResource, {
        ...baseEnv,
        currentTime: '2026-05-31T23:59:59.000Z',
      }).decision,
      'PERMIT',
    );

    // 6. TIME_BETWEEN supports both HH:MM (<input type="time">) and full ISO with second precision & h23 midnight
    assert.ok(resolveSimulationDate('10:00') instanceof Date);
    const localTz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'Asia/Ho_Chi_Minh';
    const businessHoursRule = makeSingleConditionRule({
      attribute: 'environment.currentTime',
      operator: 'TIME_BETWEEN',
      expected: { start: '08:00:00', end: '17:30:00', timeZone: localTz },
    });
    assert.equal(
      evaluatePolicySimulation(businessHoursRule, 'VIEW', baseSubject, baseResource, {
        ...baseEnv,
        currentTime: '10:00',
      }).decision,
      'PERMIT',
    );
    assert.equal(
      evaluatePolicySimulation(businessHoursRule, 'VIEW', baseSubject, baseResource, {
        ...baseEnv,
        currentTime: '22:15',
      }).decision,
      'DENY',
    );

    // Second-level precision on ISO timestamp in UTC
    const utcWindowRule = makeSingleConditionRule({
      attribute: 'environment.currentTime',
      operator: 'TIME_BETWEEN',
      expected: { start: '00:00:00', end: '00:30:00', timeZone: 'UTC' },
    });
    assert.equal(
      evaluatePolicySimulation(utcWindowRule, 'VIEW', baseSubject, baseResource, {
        ...baseEnv,
        currentTime: '2026-11-26T00:15:45.000Z',
      }).decision,
      'PERMIT',
    );
    assert.equal(
      evaluatePolicySimulation(utcWindowRule, 'VIEW', baseSubject, baseResource, {
        ...baseEnv,
        currentTime: '2026-11-26T00:30:01.000Z',
      }).decision,
      'DENY',
    );

    // SimulatorContextForm exposes both subject.projects and environment.deviceTrust controls
    const formSrc = readWebFile('components/abac/simulator-context-form.tsx');
    assert.match(formSrc, /sim-subject-projects/u);
    assert.match(formSrc, /sim-env-device-trust/u);
  });
});

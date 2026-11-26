import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { BadRequestException, ConflictException, ForbiddenException } from '@nestjs/common';
import { AppConfigService } from '../dist/config/config.service.js';
import { CsrfService } from '../dist/modules/auth/csrf.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';
import { UsersService } from '../dist/modules/users/users.service.js';
import { DepartmentsService } from '../dist/modules/departments/departments.service.js';
import { RealtimeEventsService } from '../dist/modules/realtime/realtime-events.service.js';
import { RbacController } from '../dist/modules/rbac/rbac.controller.js';
import { executeAssignUserRole } from '../dist/modules/rbac/rbac-assignments.helper.js';
import { executeReplaceRolePermissions } from '../dist/modules/rbac/rbac-role-permissions.helper.js';
import { executeEnableRole } from '../dist/modules/rbac/rbac-roles.helper.js';
import {
  normalizeObligationEntries,
  serializeAbacPolicyRow,
  UpsertAbacPolicySchema,
} from '../dist/modules/abac/abac-policy-dto.helper.js';
import {
  executeDeactivateAbacRule,
  executeDeleteAbacRule,
} from '../dist/modules/abac/abac-policy-lifecycle.helper.js';

const adminPrincipal = {
  userId: 1n,
  sessionId: 'sess-admin',
  username: 'admin',
  roles: ['SYSTEM_ADMIN'],
  mfa: true,
};
const ctx = { ip: '127.0.0.1', correlationId: 'corr-admin-fixes' };

test('UsersService.reactivate restores DISABLED account while lock/disable emit USER_SESSION_REVOKED and close SSE socket', async () => {
  const users = new Map([
    [
      2n,
      {
        id: 2n,
        username: 'target.user',
        email: 'target@corp.internal',
        full_name: 'Target User',
        employee_code: 'NV-02',
        department_id: 1n,
        status: 'ACTIVE',
        locked_until: null,
        disabled_at: null,
        failed_login_count: 3,
        version: 0,
      },
    ],
  ]);
  const db = {
    user: {
      findUnique: async ({ where }) => users.get(where.id) ?? null,
      findUniqueOrThrow: async ({ where }) => users.get(where.id),
      updateMany: async ({ where, data }) => {
        const cur = users.get(where.id);
        if (!cur || cur.version !== where.version) return { count: 0 };
        users.set(where.id, { ...cur, ...data, version: cur.version + 1 });
        return { count: 1 };
      },
    },
    authSession: { updateMany: async () => ({ count: 1 }) },
    refreshToken: { updateMany: async () => ({ count: 1 }) },
    accessSession: { updateMany: async () => ({ count: 0 }) },
    $transaction: async (fn) => fn(db),
  };

  const realtime = new RealtimeEventsService();
  const deliveredFrames = [];
  let closed = false;
  realtime.registerClient({
    userId: '2',
    roles: ['DOCUMENT_READER'],
    writeFrame: (frame) => {
      deliveredFrames.push(frame);
      return true;
    },
    close: () => {
      closed = true;
    },
  });

  const audits = [];
  const authz = {
    hasPermission: async () => true,
    assertPermission: async () => {},
    invalidateUser: async () => {},
  };
  const service = new UsersService(
    authz,
    new PasswordService(),
    { record: async (_tx, ev) => audits.push(ev) },
    db,
    realtime,
  );

  // Locking active account emits USER_SESSION_REVOKED and closes that user's SSE stream
  const locked = await service.lock(adminPrincipal, 2n, 0, ctx);
  assert.equal(locked.status, 'LOCKED');
  assert.equal(deliveredFrames.length, 1);
  assert.match(deliveredFrames[0], /event: USER_SESSION_REVOKED/u);
  assert.equal(closed, true);
  assert.equal(realtime.activeConnectionCount(), 0);

  // Disable account -> unlock must still reject (MED-07 / BUG-105 409 state conflict), reactivate must succeed
  const disabled = await service.disable(adminPrincipal, 2n, 1, ctx);
  assert.equal(disabled.status, 'DISABLED');
  await assert.rejects(() => service.unlock(adminPrincipal, 2n, 2, ctx), ConflictException);

  const reactivated = await service.reactivate(adminPrincipal, 2n, 2, ctx);
  assert.equal(reactivated.status, 'ACTIVE');
  assert.equal(audits.at(-1).action, 'USER_REACTIVATED');

  // Reactivating an already ACTIVE account is rejected
  await assert.rejects(() => service.reactivate(adminPrincipal, 2n, 3, ctx), ConflictException);
});

test('DepartmentsService.activate re-enables inactive department, blocks inactive parent, and enforces CAS', async () => {
  const departments = new Map([
    [
      1n,
      { id: 1n, code: 'ROOT', name: 'Trụ sở chính', parent_id: null, is_active: true, version: 0 },
    ],
    [
      2n,
      {
        id: 2n,
        code: 'INACTIVE_PARENT',
        name: 'Khối tạm ngừng',
        parent_id: 1n,
        is_active: false,
        version: 0,
      },
    ],
    [
      3n,
      {
        id: 3n,
        code: 'CHILD_DEPT',
        name: 'Phòng con',
        parent_id: 2n,
        is_active: false,
        version: 1,
      },
    ],
  ]);
  const db = {
    department: {
      findUnique: async ({ where }) => departments.get(where.id) ?? null,
      findUniqueOrThrow: async ({ where }) => departments.get(where.id),
      findFirst: async ({ where }) => {
        const d = departments.get(where.id);
        return d && d.is_active === where.is_active ? d : null;
      },
      updateMany: async ({ where, data }) => {
        const cur = departments.get(where.id);
        if (!cur || cur.version !== where.version) return { count: 0 };
        departments.set(where.id, { ...cur, ...data, version: cur.version + 1 });
        return { count: 1 };
      },
    },
    $transaction: async (fn) => fn(db),
  };
  const audits = [];
  const service = new DepartmentsService(
    { hasPermission: async () => true, invalidateAll: async () => {} },
    { record: async (_tx, ev) => audits.push(ev) },
    db,
  );

  // Child cannot be activated while parent #2 is inactive
  await assert.rejects(() => service.activate(adminPrincipal, 3n, 1, ctx), ConflictException);

  // Activate parent #2 -> succeeds
  const activatedParent = await service.activate(adminPrincipal, 2n, 0, ctx);
  assert.equal(activatedParent.isActive, true);
  assert.equal(audits.at(-1).action, 'DEPARTMENT_ACTIVATED');

  // Already active rejects
  await assert.rejects(() => service.activate(adminPrincipal, 2n, 1, ctx), ConflictException);

  // Child #3 now succeeds with matching CAS version
  const activatedChild = await service.activate(adminPrincipal, 3n, 1, ctx);
  assert.equal(activatedChild.isActive, true);
});

test('RBAC replacePermissions allows global SYSTEM_ADMIN to manage non-admin roles while keeping SoD, matrix, and custom-admin ceilings', async () => {
  const readerRole = {
    id: 3n,
    code: 'DOCUMENT_READER',
    is_system_role: true,
    is_active: true,
    role_permissions: [],
  };
  const perms = [
    { id: 10n, code: 'DOCUMENT_VIEW', resource_type: 'DOCUMENT', action: 'VIEW' },
    { id: 11n, code: 'DOCUMENT_DISCOVER', resource_type: 'DOCUMENT', action: 'DISCOVER' },
    { id: 99n, code: 'USER_MANAGE', resource_type: 'USER', action: 'MANAGE' },
  ];
  let createdRows = [];
  const tx = {
    role: { findUnique: async () => readerRole },
    userRole: { count: async () => 0, findMany: async () => [] },
    permission: {
      findMany: async ({ where }) => perms.filter((p) => where.id.in.includes(p.id)),
    },
    rolePermission: {
      deleteMany: async () => ({ count: 0 }),
      createMany: async ({ data }) => {
        createdRows = data;
        return { count: data.length };
      },
    },
  };
  const db = { $transaction: async (fn) => fn(tx) };
  const audit = { record: async () => {} };

  const strictAuthzForSysAdmin = {
    effectiveGrants: async () => [
      {
        roleCode: 'SYSTEM_ADMIN',
        code: 'ROLE_MANAGE',
        resource: 'ROLE',
        action: 'MANAGE',
        scopeDepartmentId: null,
      },
    ],
    assertCanDelegate: async () => {
      throw new ForbiddenException('Delegation ceiling exceeded');
    },
    invalidateAll: async () => {},
  };

  // Global SYSTEM_ADMIN succeeds updating DOCUMENT_READER with valid matrix permissions
  const updated = await executeReplaceRolePermissions({
    database: db,
    authorization: strictAuthzForSysAdmin,
    audit,
    principal: adminPrincipal,
    roleId: 3n,
    permissionIds: [10n, 11n],
    context: ctx,
  });
  assert.deepEqual(updated.permissionCodes, ['DOCUMENT_DISCOVER', 'DOCUMENT_VIEW']);
  assert.equal(createdRows.length, 2);

  // System role matrix still blocks adding USER_MANAGE to DOCUMENT_READER
  await assert.rejects(
    () =>
      executeReplaceRolePermissions({
        database: db,
        authorization: strictAuthzForSysAdmin,
        audit,
        principal: adminPrincipal,
        roleId: 3n,
        permissionIds: [10n, 99n],
        context: ctx,
      }),
    ForbiddenException,
  );

  // Non-SYSTEM_ADMIN custom admin is still blocked by assertCanDelegate
  const customAdminAuthz = {
    effectiveGrants: async () => [
      {
        roleCode: 'CUSTOM_ROLE_MGR',
        code: 'ROLE_MANAGE',
        resource: 'ROLE',
        action: 'MANAGE',
        scopeDepartmentId: null,
      },
    ],
    assertCanDelegate: async () => {
      throw new ForbiddenException('Delegation ceiling exceeded');
    },
    invalidateAll: async () => {},
  };
  await assert.rejects(
    () =>
      executeReplaceRolePermissions({
        database: db,
        authorization: customAdminAuthz,
        audit,
        principal: { ...adminPrincipal, roles: ['CUSTOM_ROLE_MGR'] },
        roleId: 3n,
        permissionIds: [10n],
        context: ctx,
      }),
    ForbiddenException,
  );
});

test('RBAC role assignment rejects past validTo & past validFrom, and executeEnableRole re-enables custom role', async () => {
  const csrf = new CsrfService(new AppConfigService({ CORS_ORIGIN: 'http://localhost:3000' }));
  const token = 'test-placeholder-csrf-rbac-000000000000';
  let assignedPayload = null;
  const controller = new RbacController(
    {
      assignUserRole: async (_p, _uid, input) => {
        assignedPayload = input;
        return { id: '777' };
      },
    },
    csrf,
  );
  const req = {
    auth: adminPrincipal,
    ip: '127.0.0.1',
    cookies: { sda_csrf: token },
    headers: { origin: 'http://localhost:3000', 'x-csrf-token': token },
  };

  // Past validFrom (> 5 minutes ago) rejected by Zod schema
  assert.throws(() =>
    controller.assignUserRole(
      '5',
      {
        roleId: '2',
        scopeDepartmentId: null,
        validFrom: new Date(Date.now() - 2 * 3600_000).toISOString(),
        validTo: new Date(Date.now() + 3600_000).toISOString(),
      },
      req,
    ),
  );

  // Past validTo rejected in both controller and helper
  assert.throws(() =>
    controller.assignUserRole(
      '5',
      {
        roleId: '2',
        scopeDepartmentId: null,
        validFrom: new Date(Date.now() - 10_000).toISOString(),
        validTo: new Date(Date.now() - 1_000).toISOString(),
      },
      req,
    ),
  );
  await assert.rejects(
    () =>
      executeAssignUserRole(
        { effectiveGrants: async () => [] },
        { record: async () => {} },
        adminPrincipal,
        5n,
        {
          roleId: 2n,
          scopeDepartmentId: null,
          validFrom: new Date(Date.now() - 7200_000),
          validTo: new Date(Date.now() - 3600_000),
        },
        ctx,
      ),
    BadRequestException,
  );

  // Current validFrom + future validTo succeeds
  const ok = await controller.assignUserRole(
    '5',
    {
      roleId: '2',
      scopeDepartmentId: null,
      validFrom: new Date().toISOString(),
      validTo: new Date(Date.now() + 86_400_000).toISOString(),
    },
    req,
  );
  assert.equal(ok.id, '777');
  assert.ok(assignedPayload);

  // executeEnableRole re-enables disabled custom role
  let roleState = {
    id: 9n,
    code: 'CUSTOM_REVIEWER',
    name: 'Reviewer',
    description: null,
    is_system_role: false,
    is_active: false,
    version: 2,
  };
  const roleDb = {
    role: {
      findUnique: async () => roleState,
      findUniqueOrThrow: async () => roleState,
      updateMany: async ({ where, data }) => {
        if (roleState.version !== where.version) return { count: 0 };
        roleState = { ...roleState, ...data, version: roleState.version + 1 };
        return { count: 1 };
      },
    },
    userRole: { count: async () => 0 },
    $transaction: async (fn) => fn(roleDb),
  };
  const enabledId = await executeEnableRole({
    database: roleDb,
    authorization: { invalidateAll: async () => {} },
    audit: { record: async () => {} },
    principal: adminPrincipal,
    id: 9n,
    expectedVersion: 2,
    context: ctx,
  });
  assert.equal(enabledId, 9n);
  assert.equal(roleState.is_active, true);
});

test('ABAC obligations normalization, deactivate & delete policy lifecycle', async () => {
  // String obligations from seeded rules normalize cleanly in both DTO serialization and Zod input parsing
  assert.deepEqual(normalizeObligationEntries(['NO_CACHE', { type: 'REQUIRE_WATERMARK' }]), [
    { type: 'NO_CACHE' },
    { type: 'REQUIRE_WATERMARK' },
  ]);

  const parsed = UpsertAbacPolicySchema.parse({
    code: 'POL_DENY_HIGH_RISK',
    name: 'Chặn rủi ro cao',
    effect: 'DENY',
    obligations: ['NO_CACHE', { type: 'REQUIRE_MFA' }],
    groups: [],
  });
  assert.deepEqual(parsed.obligations, [{ type: 'NO_CACHE' }, { type: 'REQUIRE_MFA' }]);

  const serialized = serializeAbacPolicyRow({
    id: 1n,
    code: 'POL_DENY_HIGH_RISK',
    name: 'Chặn rủi ro cao',
    description: null,
    effect: 'DENY',
    priority: 10,
    target_resource: 'DOCUMENT',
    target_action: null,
    combining_algorithm: 'DENY_OVERRIDES',
    obligations: ['NO_CACHE'],
    is_active: true,
    valid_from: new Date('2026-01-01T00:00:00Z'),
    valid_to: null,
    version: 1n,
    policy_rule_conditions: [],
  });
  assert.deepEqual(serialized.obligations, [{ type: 'NO_CACHE' }]);

  // Deactivate and Delete policy rules record audits and bump cache epoch
  let policyRow = {
    id: 42n,
    code: 'POL_TEMP',
    name: 'Temporary Policy',
    effect: 'PERMIT',
    priority: 50,
    is_active: true,
    version: 5n,
  };
  let deleted = false;
  let bumpedEpochs = 0;
  const audits = [];
  const abacDb = {
    policyRule: {
      findUnique: async () => (deleted ? null : policyRow),
      update: async ({ data }) => {
        policyRow = { ...policyRow, ...data };
        return policyRow;
      },
      delete: async () => {
        deleted = true;
        return policyRow;
      },
    },
    policyRuleCondition: { deleteMany: async () => ({ count: 2 }) },
    $transaction: async (fn) => fn(abacDb),
  };
  const repo = { currentPolicyVersion: async () => policyRow.version };
  const cache = {
    bumpPolicyEpoch: async () => {
      bumpedEpochs += 1;
    },
  };
  const audit = { record: async (_tx, ev) => audits.push(ev) };

  const deactivated = await executeDeactivateAbacRule({
    ruleId: 42n,
    principal: adminPrincipal,
    context: ctx,
    database: abacDb,
    repository: repo,
    cache,
    audit,
  });
  assert.equal(deactivated.id, '42');
  assert.equal(policyRow.is_active, false);
  assert.equal(audits.at(-1).action, 'POLICY_DEACTIVATED');

  await executeDeleteAbacRule({
    ruleId: 42n,
    principal: adminPrincipal,
    context: ctx,
    database: abacDb,
    repository: repo,
    cache,
    audit,
  });
  assert.equal(deleted, true);
  assert.equal(audits.at(-1).action, 'POLICY_DELETED');
  assert.equal(bumpedEpochs, 2);
});

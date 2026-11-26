import 'reflect-metadata';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { ConflictException, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthorizationCache } from '../dist/modules/rbac/authorization-cache.js';
import { AuthorizationGuard } from '../dist/modules/rbac/authorization.guard.js';
import {
  SYSTEM_ROLE_PERMISSION_MATRIX,
  systemRoleAllows,
} from '../dist/modules/rbac/permission-matrix.js';
import {
  executeAssignUserRole,
  executeRevokeUserRole,
  PRIVILEGED_ROLE_MFA_REVOKE_REASON,
} from '../dist/modules/rbac/rbac-assignments.helper.js';
import { executeReplaceRolePermissions } from '../dist/modules/rbac/rbac-role-permissions.helper.js';
import { executeEnableRole } from '../dist/modules/rbac/rbac-roles.helper.js';
import { REQUIRED_PERMISSION_METADATA } from '../dist/modules/rbac/require-permission.js';
import { createSysAdminDelegationHarness } from './helpers/rbac-sysadmin-fixture.helper.mjs';

test('authorization cache expires at role valid_to and invalidates immediately', async () => {
  const cache = new AuthorizationCache();
  const grant = {
    permissionId: 1n,
    code: 'USER_MANAGE',
    resource: 'USER',
    action: 'MANAGE',
    roleId: 2n,
    roleCode: 'SCOPED_ADMIN',
    scopeDepartmentId: 3n,
    validTo: new Date(2_000),
  };
  await cache.set(9n, [grant], 30_000, 1_000);
  assert.equal((await cache.get(9n, 1_999))?.length, 1);
  assert.equal(await cache.get(9n, 2_000), undefined, 'expired role must not survive cache TTL');
  await cache.set(9n, [{ ...grant, validTo: null }], 30_000, 3_000);
  const generation = cache.currentGeneration();
  await cache.invalidateUser(9n);
  assert.equal(await cache.get(9n, 3_001), undefined);
  assert.equal(cache.currentGeneration(), generation + 1);
});

/**
 * Thuật toán kiểm thử [CRITICAL 1.1]: Gán vai trò đặc quyền (`SECURITY_OFFICER` / quyền SOC)
 * thu hồi tức thì mọi `auth_sessions` có `mfa_verified_at === null` và vô hiệu bộ đệm phân quyền.
 */
test('assigning privileged role immediately revokes unverified-MFA sessions of target user', async () => {
  let sessionRevokeArgs = null;
  let refreshRevokeArgs = null;
  let invalidatedUserId = null;

  const mockTx = {
    user: {
      findUnique: async () => ({ id: 50n, status: 'ACTIVE', department_id: 10n }),
    },
    role: {
      findFirst: async () => ({
        id: 3n,
        code: 'SECURITY_OFFICER',
        is_active: true,
        role_permissions: [
          {
            permission_id: 99n,
            permissions: {
              id: 99n,
              code: 'SECURITY_ALERT_VIEW',
              resource: 'SECURITY_ALERT',
              action: 'VIEW',
            },
          },
        ],
      }),
    },
    userRole: {
      findMany: async () => [],
      create: async ({ data }) => ({ id: 501n, ...data }),
    },
    authSession: {
      updateMany: async (args) => {
        sessionRevokeArgs = args;
        return { count: 2 };
      },
    },
    refreshToken: {
      updateMany: async (args) => {
        refreshRevokeArgs = args;
        return { count: 2 };
      },
    },
  };
  const mockDb = {
    $transaction: async (fn) => fn(mockTx),
  };
  const mockAuthorization = {
    assertPermission: async () => undefined,
    assertCanDelegate: async () => undefined,
    departmentWithinScope: async () => true,
    invalidateUser: async (uid) => {
      invalidatedUserId = uid;
    },
  };
  const mockAudit = { record: async () => undefined };

  const res = await executeAssignUserRole(
    mockAuthorization,
    mockAudit,
    { userId: 1n, sessionId: 's-admin', username: 'admin', roles: ['SYSTEM_ADMIN'], mfa: true },
    50n,
    {
      roleId: 3n,
      scopeDepartmentId: null,
      validFrom: new Date('2026-10-01T00:00:00Z'),
      validTo: null,
    },
    { ip: '10.0.0.5', correlationId: 'corr-assign-1' },
    mockDb,
  );

  assert.equal(res.id, '501');
  assert.ok(sessionRevokeArgs, 'authSession.updateMany must be invoked');
  assert.deepEqual(sessionRevokeArgs.where, {
    user_id: { in: [50n] },
    status: 'ACTIVE',
    mfa_verified_at: null,
  });
  assert.equal(sessionRevokeArgs.data.status, 'REVOKED');
  assert.equal(sessionRevokeArgs.data.revocation_reason, PRIVILEGED_ROLE_MFA_REVOKE_REASON);
  assert.ok(refreshRevokeArgs, 'refreshToken.updateMany must be invoked');
  assert.equal(refreshRevokeArgs.data.revocation_reason, PRIVILEGED_ROLE_MFA_REVOKE_REASON);
  assert.equal(invalidatedUserId, 50n);
});

test('five-role matrix preserves least privilege and admin has no document content view', () => {
  assert.deepEqual(Object.keys(SYSTEM_ROLE_PERMISSION_MATRIX).sort(), [
    'AUDITOR',
    'DOCUMENT_OWNER',
    'DOCUMENT_READER',
    'SECURITY_OFFICER',
    'SYSTEM_ADMIN',
  ]);
  assert.equal(SYSTEM_ROLE_PERMISSION_MATRIX.SYSTEM_ADMIN.includes('DOCUMENT_VIEW'), false);
  assert.equal(systemRoleAllows('SYSTEM_ADMIN', ['USER_MANAGE', 'DEPARTMENT_MANAGE']), true);
  assert.equal(systemRoleAllows('SYSTEM_ADMIN', ['DOCUMENT_VIEW']), false);
  assert.equal(systemRoleAllows('AUDITOR', ['ROLE_MANAGE']), false);
  assert.equal(
    systemRoleAllows('DOCUMENT_OWNER', [
      'DOCUMENT_VIEW',
      'DOCUMENT_DOWNLOAD',
      'DOCUMENT_DISCOVER',
      'ACCESS_REQUEST_VIEW_OWN',
      'NOTIFICATION_VIEW',
    ]),
    true,
  );
});

test('authorization guard returns forbidden when resource/action permission is absent', async () => {
  const reflector = new Reflector();
  const handler = () => undefined;
  Reflect.defineMetadata(
    REQUIRED_PERMISSION_METADATA,
    { resource: 'ROLE', action: 'MANAGE', global: true },
    handler,
  );
  const guard = new AuthorizationGuard(reflector, {
    assertPermission: async () => {
      throw new ForbiddenException('missing');
    },
  });
  const context = {
    getHandler: () => handler,
    switchToHttp: () => ({ getRequest: () => ({ auth: { userId: 7n } }) }),
  };
  await assert.rejects(guard.canActivate(context), (error) => error.getStatus() === 403);
});

test('controllers declare resource/action permissions and contain no role string checks', async () => {
  const files = [
    new URL('../src/modules/users/users.controller.ts', import.meta.url),
    new URL('../src/modules/departments/departments.controller.ts', import.meta.url),
    new URL('../src/modules/rbac/rbac.controller.ts', import.meta.url),
  ];
  for (const file of files) {
    const source = await readFile(file, 'utf8');
    assert.match(source, /@RequirePermission\(/u);
    assert.doesNotMatch(source, /roles\.includes|SYSTEM_ADMIN|SECURITY_OFFICER|AUDITOR/u);
  }
});

/**
 * Thuật toán kiểm thử: `SYSTEM_ADMIN` toàn cục có `ROLE_MANAGE` toàn cục gán được `DOCUMENT_READER` cho nhân sự khác,
 * bị chặn `403` nếu tự gán cho chính mình, bị chặn `409` nếu mục tiêu vi phạm Phân tách Nhiệm vụ (SoD),
 * và quản trị viên cấp thấp không phải `SYSTEM_ADMIN` vẫn bị chặn bởi trần ủy quyền `assertCanDelegate`.
 */
test('SYSTEM_ADMIN assigns DOCUMENT_READER to another user, blocks self-assign and SoD conflicts, and enforces subset ceiling on custom admin', async () => {
  const { mockDb, strictAuthz, audit, setOverlappingRoles, sysAdmin, customAdmin, ctx, input } =
    createSysAdminDelegationHarness();

  const assigned = await executeAssignUserRole(
    strictAuthz,
    audit,
    sysAdmin,
    88n,
    input,
    ctx,
    mockDb,
  );
  assert.equal(assigned.id, '901');

  await assert.rejects(
    () => executeAssignUserRole(strictAuthz, audit, sysAdmin, 1n, input, ctx, mockDb),
    (err) => err instanceof ForbiddenException,
  );

  setOverlappingRoles([
    {
      roles: {
        code: 'AUDITOR',
        role_permissions: [
          {
            permissions: {
              id: 301n,
              code: 'AUDIT_LOG_VIEW',
              resource_type: 'AUDIT_LOG',
              action: 'VIEW',
            },
          },
        ],
      },
    },
  ]);
  await assert.rejects(
    () => executeAssignUserRole(strictAuthz, audit, sysAdmin, 88n, input, ctx, mockDb),
    (err) => err instanceof ConflictException,
  );

  setOverlappingRoles([]);
  await assert.rejects(
    () => executeAssignUserRole(strictAuthz, audit, customAdmin, 88n, input, ctx, mockDb),
    (err) => err instanceof ForbiddenException,
  );
});

test('BUG-005 — executeEnableRole blocks SoD bypass, delegation escalation, active ROLE/USER grants, and revokes unverified MFA sessions on privileged re-enable', async () => {
  const now = Date.now();
  const alertManagePerm = {
    id: 401n,
    code: 'ALERT_MANAGE',
    resource_type: 'SECURITY_ALERT',
    action: 'MANAGE',
  };
  const docUploadPerm = {
    id: 402n,
    code: 'DOCUMENT_UPLOAD',
    resource_type: 'DOCUMENT',
    action: 'UPLOAD',
  };
  let roleState = {
    id: 70n,
    code: 'CUSTOM_SOC',
    name: 'Custom SOC',
    description: null,
    is_system_role: false,
    is_active: false,
    version: 3,
    role_permissions: [{ permission_id: alertManagePerm.id, permissions: alertManagePerm }],
  };
  let holderOtherAssignments = [
    {
      user_id: 50n,
      role_id: 71n,
      valid_from: new Date(now - 60_000),
      valid_to: null,
      roles: {
        code: 'DOCUMENT_OWNER',
        role_permissions: [{ permissions: docUploadPerm }],
      },
    },
  ];
  let activeRoleGrantCount = 0;
  let activeUserGrantCount = 0;
  let ownedDocumentsCount = 0;
  let cascadeRevokeCalls = 0;
  let revokedSessionArgs = null;
  let revokedRefreshArgs = null;

  const tx = {
    document: {
      count: async () => ownedDocumentsCount,
    },
    role: {
      findUnique: async () => roleState,
      findUniqueOrThrow: async () => roleState,
      updateMany: async ({ where, data }) => {
        if (roleState.version !== where.version) return { count: 0 };
        roleState = { ...roleState, ...data, version: roleState.version + 1 };
        return { count: 1 };
      },
    },
    userRole: {
      count: async () => 0,
      findMany: async ({ where }) => {
        if (where.role_id === 70n) {
          return [{ user_id: 50n, valid_from: new Date(now - 120_000), valid_to: null }];
        }
        return holderOtherAssignments;
      },
    },
    accessGrant: {
      count: async ({ where }) => {
        if (where.principal_type === 'ROLE') return activeRoleGrantCount;
        if (where.principal_type === 'USER') return activeUserGrantCount;
        return 0;
      },
      findMany: async () => {
        const list = [];
        if (activeRoleGrantCount > 0) list.push({ id: 'g-role-1' });
        if (activeUserGrantCount > 0) list.push({ id: 'g-user-1' });
        return list;
      },
      updateMany: async ({ data }) => {
        assert.ok(data.revoked_by && data.revoked_at && data.revoke_reason);
        cascadeRevokeCalls += 1;
        activeRoleGrantCount = 0;
        activeUserGrantCount = 0;
        return { count: 1 };
      },
    },
    authSession: {
      updateMany: async (args) => {
        revokedSessionArgs = args;
        return { count: 1 };
      },
    },
    refreshToken: {
      updateMany: async (args) => {
        revokedRefreshArgs = args;
        return { count: 1 };
      },
    },
  };
  const db = { $transaction: async (fn) => fn(tx) };
  const audit = { record: async () => {} };
  const ctx = { ip: '10.0.0.9', correlationId: 'corr-bug005-enable' };

  const globalSysAdmin = {
    userId: 1n,
    sessionId: 's-sysadmin',
    username: 'sysadmin',
    roles: ['SYSTEM_ADMIN'],
    mfa: true,
  };
  const customRoleAdmin = {
    userId: 2n,
    sessionId: 's-custom-admin',
    username: 'custom.admin',
    roles: ['CUSTOM_ROLE_ADMIN'],
    mfa: true,
  };

  const makeAuthz = (isGlobalSysAdmin) => ({
    effectiveGrants: async () =>
      isGlobalSysAdmin
        ? [
            {
              permissionId: 1n,
              code: 'ROLE_MANAGE',
              resource: 'ROLE',
              action: 'MANAGE',
              roleId: 1n,
              roleCode: 'SYSTEM_ADMIN',
              scopeDepartmentId: null,
              validTo: null,
            },
          ]
        : [
            {
              permissionId: 1n,
              code: 'ROLE_MANAGE',
              resource: 'ROLE',
              action: 'MANAGE',
              roleId: 2n,
              roleCode: 'CUSTOM_ROLE_ADMIN',
              scopeDepartmentId: null,
              validTo: null,
            },
          ],
    assertCanDelegate: async () => {
      throw new ForbiddenException('Cannot delegate permissions outside the administrator grant.');
    },
    invalidateAll: async () => {},
  });

  // 1. Custom admin without ALERT_MANAGE cannot re-enable CUSTOM_SOC (delegation ceiling)
  await assert.rejects(
    () =>
      executeEnableRole({
        database: db,
        authorization: makeAuthz(false),
        audit,
        principal: customRoleAdmin,
        id: 70n,
        expectedVersion: 3,
        context: ctx,
      }),
    ForbiddenException,
  );
  assert.equal(roleState.is_active, false);

  // 2. Global SYSTEM_ADMIN blocked by overlapping SoD (holder U=50 holds active DOCUMENT_OWNER)
  await assert.rejects(
    () =>
      executeEnableRole({
        database: db,
        authorization: makeAuthz(true),
        audit,
        principal: globalSysAdmin,
        id: 70n,
        expectedVersion: 3,
        context: ctx,
      }),
    ConflictException,
  );
  assert.equal(roleState.is_active, false);

  // CONFLICT-RESOLVED: Hợp nhất BUG-005 và BUG-047 — chặn 409 khi người giữ đang sở hữu tài liệu chưa bàn giao (`owner_id`),
  // sau khi bàn giao tài liệu thì tự động thu hồi dây chuyền AccessGrant (kèm đủ revoked_by/revoked_at/revoke_reason) và thu hồi phiên thiếu MFA.
  holderOtherAssignments = [];
  ownedDocumentsCount = 1;
  activeRoleGrantCount = 1;
  activeUserGrantCount = 1;
  await assert.rejects(
    () =>
      executeEnableRole({
        database: db,
        authorization: makeAuthz(true),
        audit,
        principal: globalSysAdmin,
        id: 70n,
        expectedVersion: 3,
        context: ctx,
      }),
    ConflictException,
  );
  assert.equal(roleState.is_active, false);

  // Once owned documents are handed over, re-enabling succeeds, cascade-revokes active grants, AND revokes unverified-MFA sessions of holders
  ownedDocumentsCount = 0;
  const enabledId = await executeEnableRole({
    database: db,
    authorization: makeAuthz(true),
    audit,
    principal: globalSysAdmin,
    id: 70n,
    expectedVersion: 3,
    context: ctx,
  });
  assert.equal(enabledId, 70n);
  assert.equal(roleState.is_active, true);
  assert.equal(cascadeRevokeCalls, 1);
  assert.equal(activeRoleGrantCount, 0);
  assert.equal(activeUserGrantCount, 0);
  assert.deepEqual(revokedSessionArgs?.where, {
    user_id: { in: [50n] },
    status: 'ACTIVE',
    mfa_verified_at: null,
  });
  assert.equal(revokedSessionArgs?.data?.revocation_reason, PRIVILEGED_ROLE_MFA_REVOKE_REASON);
  assert.equal(revokedRefreshArgs?.data?.revocation_reason, PRIVILEGED_ROLE_MFA_REVOKE_REASON);
});

// CONFLICT-RESOLVED: Hợp nhất BUG-005 và BUG-047 — khi nâng vai trò lên đặc quyền hoặc gán vai trò đặc quyền: chặn 409 nếu người giữ đang sở hữu tài liệu chưa bàn giao (`owner_id`), ngược lại tự động thu hồi dây chuyền các AccessGrant ACTIVE (điền đủ `revoked_by`, `revoked_at`, `revoke_reason` thỏa CHECK 23514).
test('BUG-005 & BUG-047 — executeReplaceRolePermissions checks SoD even when target role is disabled, blocks owned documents, and cascade-revokes active ROLE grants', async () => {
  const now = Date.now();
  const alertManagePerm = {
    id: 401n,
    code: 'ALERT_MANAGE',
    resource_type: 'SECURITY_ALERT',
    action: 'MANAGE',
  };
  const docUploadPerm = {
    id: 402n,
    code: 'DOCUMENT_UPLOAD',
    resource_type: 'DOCUMENT',
    action: 'UPLOAD',
  };
  let activeHolderOtherRoles = [
    {
      user_id: 50n,
      role_id: 71n,
      valid_from: new Date(now - 60_000),
      valid_to: null,
      roles: {
        code: 'DOCUMENT_OWNER',
        role_permissions: [{ permissions: docUploadPerm }],
      },
    },
  ];
  let ownedDocCount = 0;
  const revokedGrants = [];

  const tx = {
    role: {
      findUnique: async () => ({
        id: 70n,
        code: 'CUSTOM_DISABLED',
        is_system_role: false,
        is_active: false,
        role_permissions: [],
      }),
    },
    permission: {
      findMany: async () => [alertManagePerm],
    },
    userRole: {
      count: async () => 0,
      findMany: async ({ where }) => {
        if (where.role_id === 70n) {
          return [{ user_id: 50n, valid_from: new Date(now - 120_000), valid_to: null }];
        }
        // Only active roles are returned (excluding disabled roleId 70n), mimicking Prisma `roles: { is_active: true }`
        return activeHolderOtherRoles;
      },
    },
    document: {
      count: async () => ownedDocCount,
    },
    accessGrant: {
      findMany: async () => [{ id: 8801n }],
      updateMany: async ({ where, data }) => {
        revokedGrants.push({ where, data });
        return { count: 1 };
      },
    },
    accessSession: {
      updateMany: async () => ({ count: 0 }),
    },
    accessRequest: {
      updateMany: async () => ({ count: 0 }),
    },
    rolePermission: {
      deleteMany: async () => ({ count: 0 }),
      createMany: async () => ({ count: 1 }),
    },
  };
  const db = { $transaction: async (fn) => fn(tx) };
  const sysAdminAuthz = {
    effectiveGrants: async () => [
      {
        permissionId: 1n,
        code: 'ROLE_MANAGE',
        resource: 'ROLE',
        action: 'MANAGE',
        roleId: 1n,
        roleCode: 'SYSTEM_ADMIN',
        scopeDepartmentId: null,
        validTo: null,
      },
    ],
    invalidateAll: async () => {},
  };
  const sysAdmin = {
    userId: 1n,
    sessionId: 's-sys',
    username: 'sysadmin',
    roles: ['SYSTEM_ADMIN'],
    mfa: true,
  };
  const ctx = { ip: '10.0.0.9', correlationId: 'corr-bug005-replace' };

  // Disabled role held by user who also holds active DOCUMENT_OWNER cannot be given ALERT_MANAGE
  await assert.rejects(
    () =>
      executeReplaceRolePermissions({
        database: db,
        authorization: sysAdminAuthz,
        audit: { record: async () => {} },
        principal: sysAdmin,
        roleId: 70n,
        permissionIds: [alertManagePerm.id],
        context: ctx,
      }),
    ConflictException,
  );

  // Holder owns unhanded-over business documents -> blocked with 409 Conflict
  activeHolderOtherRoles = [];
  ownedDocCount = 1;
  await assert.rejects(
    () =>
      executeReplaceRolePermissions({
        database: db,
        authorization: sysAdminAuthz,
        audit: { record: async () => {} },
        principal: sysAdmin,
        roleId: 70n,
        permissionIds: [alertManagePerm.id],
        context: ctx,
      }),
    ConflictException,
  );

  // No owned documents -> succeeds and cascade-revokes active USER/ROLE AccessGrants with full CHECK 23514 fields
  ownedDocCount = 0;
  await executeReplaceRolePermissions({
    database: db,
    authorization: sysAdminAuthz,
    audit: { record: async () => {} },
    principal: sysAdmin,
    roleId: 70n,
    permissionIds: [alertManagePerm.id],
    context: ctx,
  });
  assert.equal(revokedGrants.length, 1);
  assert.equal(revokedGrants[0].data.status, 'REVOKED');
  assert.equal(revokedGrants[0].data.revoked_by, 1n);
  assert.ok(revokedGrants[0].data.revoked_at instanceof Date);
  assert.ok(typeof revokedGrants[0].data.revoke_reason === 'string');
});

test('BUG-005 & BUG-047 — executeAssignUserRole blocks owned documents on privileged escalation, cascade-revokes grants, and blocks assigning grant-bearing role to privileged user', async () => {
  const alertManagePerm = {
    id: 401n,
    code: 'ALERT_MANAGE',
    resource_type: 'SECURITY_ALERT',
    action: 'MANAGE',
  };
  let targetRole = {
    id: 80n,
    code: 'CUSTOM_SOC',
    is_active: true,
    role_permissions: [{ permission_id: alertManagePerm.id, permissions: alertManagePerm }],
  };
  let existingUserRoles = [];
  let ownedDocCount = 1;
  let roleGrantCount = 0;
  const revokedGrantUpdates = [];

  const tx = {
    user: { findUnique: async () => ({ id: 50n, status: 'ACTIVE', department_id: 10n }) },
    role: { findFirst: async () => targetRole },
    userRole: {
      findMany: async () => existingUserRoles,
      create: async ({ data }) => ({ id: 999n, ...data }),
    },
    document: {
      count: async () => ownedDocCount,
    },
    accessGrant: {
      count: async ({ where }) => (where.principal_type === 'ROLE' ? roleGrantCount : 0),
      findMany: async () => [{ id: 9901n }],
      updateMany: async ({ data }) => {
        revokedGrantUpdates.push(data);
        return { count: 1 };
      },
    },
    accessSession: {
      updateMany: async () => ({ count: 0 }),
    },
    accessRequest: {
      updateMany: async () => ({ count: 0 }),
    },
    authSession: {
      findMany: async () => [],
    },
  };
  const db = { $transaction: async (fn) => fn(tx) };
  const sysAdminAuthz = {
    effectiveGrants: async () => [
      {
        permissionId: 1n,
        code: 'ROLE_MANAGE',
        resource: 'ROLE',
        action: 'MANAGE',
        roleId: 1n,
        roleCode: 'SYSTEM_ADMIN',
        scopeDepartmentId: null,
        validTo: null,
      },
    ],
    assertPermission: async () => {},
    departmentWithinScope: async () => true,
    invalidateUser: async () => {},
  };
  const sysAdmin = {
    userId: 1n,
    sessionId: 's-sys',
    username: 'sysadmin',
    roles: ['SYSTEM_ADMIN'],
    mfa: true,
  };
  const ctx = { ip: '10.0.0.9', correlationId: 'corr-bug005-assign' };
  const assignInput = {
    roleId: 80n,
    scopeDepartmentId: null,
    validFrom: new Date(Date.now() - 1_000),
    validTo: null,
  };

  // 1a. User owns unhanded-over documents -> assigning privileged CUSTOM_SOC blocked (409)
  await assert.rejects(
    () =>
      executeAssignUserRole(
        sysAdminAuthz,
        { record: async () => {} },
        sysAdmin,
        50n,
        assignInput,
        ctx,
        db,
      ),
    ConflictException,
  );

  // 1b. Once documents are handed over (ownedDocCount = 0), assigning CUSTOM_SOC cascade-revokes active AccessGrants
  ownedDocCount = 0;
  await executeAssignUserRole(
    sysAdminAuthz,
    { record: async () => {} },
    sysAdmin,
    50n,
    assignInput,
    ctx,
    db,
  );
  assert.equal(revokedGrantUpdates.length, 1);
  assert.equal(revokedGrantUpdates[0].status, 'REVOKED');
  assert.equal(revokedGrantUpdates[0].revoked_by, 1n);

  // 2. User holds active CUSTOM_SOC -> assigning non-privileged role with active ROLE AccessGrant blocked (409)
  roleGrantCount = 1;
  targetRole = { id: 81n, code: 'GROUP_FINANCE', is_active: true, role_permissions: [] };
  existingUserRoles = [
    {
      role_id: 80n,
      roles: { code: 'CUSTOM_SOC', role_permissions: [{ permissions: alertManagePerm }] },
    },
  ];
  await assert.rejects(
    () =>
      executeAssignUserRole(
        sysAdminAuthz,
        { record: async () => {} },
        sysAdmin,
        50n,
        { ...assignInput, roleId: 81n },
        ctx,
        db,
      ),
    ConflictException,
  );
});

test('BUG-006 — executeRevokeUserRole blocks revoking last active global SYSTEM_ADMIN and blocks non-global-SYSTEM_ADMIN from revoking privileged/global user roles', async () => {
  const past = new Date(Date.now() - 3600_000);
  const future = new Date(Date.now() + 3600_000);
  const targetAssign = {
    id: 500n,
    user_id: 2n,
    role_id: 1n,
    scope_department_id: null,
    valid_from: past,
    valid_to: null,
    roles: {
      code: 'SYSTEM_ADMIN',
      is_active: true,
      role_permissions: [
        {
          permission_id: 10n,
          permissions: { id: 10n, code: 'USER_MANAGE', resource_type: 'USER', action: 'MANAGE' },
        },
      ],
    },
  };
  let remainingGlobalSysAdmins = 0;
  let revokedId = null;

  const tx = {
    userRole: {
      findFirst: async () => targetAssign,
      findMany: async () => [targetAssign],
      count: async () => remainingGlobalSysAdmins,
      update: async ({ where, data }) => {
        revokedId = where.id;
        return { ...targetAssign, ...data };
      },
      delete: async ({ where }) => {
        revokedId = where.id;
      },
    },
    user: { findUniqueOrThrow: async () => ({ id: 2n, department_id: 1n, status: 'ACTIVE' }) },
  };
  const db = { $transaction: async (fn) => fn(tx) };
  const audit = { record: async () => {} };
  const ctx = { ip: '10.0.0.9', correlationId: 'corr-bug006-revoke' };

  const deptMgr = {
    userId: 99n,
    sessionId: 's-mgr',
    username: 'dept.mgr',
    roles: ['DEPT_MGR'],
    mfa: true,
  };
  const deptMgrAuthz = {
    effectiveGrants: async () => [
      {
        permissionId: 10n,
        code: 'USER_MANAGE',
        resource: 'USER',
        action: 'MANAGE',
        roleId: 5n,
        roleCode: 'DEPT_MGR',
        scopeDepartmentId: 1n,
        validTo: null,
      },
    ],
    assertPermission: async () => {},
    assertCanDelegate: async () => {},
    invalidateUser: async () => {},
  };

  // 1. Non-global-SYSTEM_ADMIN cannot revoke a role from a SYSTEM_ADMIN user (403 Forbidden)
  await assert.rejects(
    () => executeRevokeUserRole(deptMgrAuthz, audit, deptMgr, 2n, 500n, ctx, db),
    ForbiddenException,
  );

  // 2. Global SYSTEM_ADMIN cannot revoke the last active global SYSTEM_ADMIN assignment (409 Conflict)
  const sysAdmin = {
    userId: 1n,
    sessionId: 's-sys',
    username: 'sysadmin',
    roles: ['SYSTEM_ADMIN'],
    mfa: true,
  };
  const sysAdminAuthz = {
    effectiveGrants: async () => [
      {
        permissionId: 10n,
        code: 'USER_MANAGE',
        resource: 'USER',
        action: 'MANAGE',
        roleId: 1n,
        roleCode: 'SYSTEM_ADMIN',
        scopeDepartmentId: null,
        validTo: null,
      },
      {
        permissionId: 11n,
        code: 'ROLE_MANAGE',
        resource: 'ROLE',
        action: 'MANAGE',
        roleId: 1n,
        roleCode: 'SYSTEM_ADMIN',
        scopeDepartmentId: null,
        validTo: null,
      },
    ],
    assertPermission: async () => {},
    invalidateUser: async () => {},
  };
  await assert.rejects(
    () => executeRevokeUserRole(sysAdminAuthz, audit, sysAdmin, 2n, 500n, ctx, db),
    ConflictException,
  );

  // 3. Once at least 1 other active global SYSTEM_ADMIN exists, revocation succeeds
  remainingGlobalSysAdmins = 1;
  await executeRevokeUserRole(sysAdminAuthz, audit, sysAdmin, 2n, 500n, ctx, db);
  assert.equal(revokedId, 500n);

  // 4. Revoking a future-scheduled global SYSTEM_ADMIN assignment succeeds even when remainingGlobalSysAdmins === 0
  remainingGlobalSysAdmins = 0;
  revokedId = null;
  targetAssign.valid_from = future;
  await executeRevokeUserRole(sysAdminAuthz, audit, sysAdmin, 2n, 500n, ctx, db);
  assert.equal(revokedId, 500n);
});

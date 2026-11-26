import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  ConflictException,
  ForbiddenException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { AppConfigService } from '../dist/config/config.service.js';
import { CsrfService } from '../dist/modules/auth/csrf.service.js';
import { DepartmentsService } from '../dist/modules/departments/departments.service.js';
import { DepartmentsController } from '../dist/modules/departments/departments.controller.js';
import { AuthorizationService } from '../dist/modules/rbac/authorization.service.js';

const adminPrincipal = {
  userId: 1n,
  sessionId: 'sess-dept-admin',
  username: 'admin.dept',
  roles: ['ROLE_MANAGE_DEPT'],
  mfa: true,
};
const ctx = { ip: '10.0.0.10', correlationId: 'corr-dept-test' };

function createInMemoryDepartmentDb(initialRows = []) {
  const rows = new Map(initialRows.map((r) => [r.id, { ...r }]));
  let nextId = BigInt(initialRows.length + 10);

  const db = {
    rows,
    department: {
      findMany: async ({ where } = {}) => {
        let list = [...rows.values()];
        if (where?.is_active !== undefined) {
          list = list.filter((r) => r.is_active === where.is_active);
        }
        if (where?.id?.in) {
          const allowed = new Set(where.id.in.map(String));
          list = list.filter((r) => allowed.has(String(r.id)));
        }
        return list.sort((a, b) => a.code.localeCompare(b.code));
      },
      findUnique: async ({ where }) => rows.get(where.id) ?? null,
      findUniqueOrThrow: async ({ where }) => {
        const found = rows.get(where.id);
        if (!found) throw new Error('Not found');
        return found;
      },
      findFirst: async ({ where }) => {
        for (const r of rows.values()) {
          if (where.id !== undefined && r.id !== where.id) continue;
          if (where.parent_id !== undefined && r.parent_id !== where.parent_id) continue;
          if (where.is_active !== undefined && r.is_active !== where.is_active) continue;
          return r;
        }
        return null;
      },
      create: async ({ data }) => {
        const created = {
          id: nextId++,
          code: data.code,
          name: data.name,
          parent_id: data.parent_id ?? null,
          is_active: true,
          version: 0,
          created_at: new Date(),
          updated_at: new Date(),
        };
        rows.set(created.id, created);
        return created;
      },
      updateMany: async ({ where, data }) => {
        const current = rows.get(where.id);
        if (!current || current.version !== where.version) return { count: 0 };
        rows.set(where.id, {
          ...current,
          ...(data.name !== undefined ? { name: data.name } : {}),
          ...(data.parent_id !== undefined ? { parent_id: data.parent_id } : {}),
          ...(data.is_active !== undefined ? { is_active: data.is_active } : {}),
          updated_at: data.updated_at ?? new Date(),
          version: current.version + 1,
        });
        return { count: 1 };
      },
      count: async ({ where }) => {
        let total = 0;
        for (const r of rows.values()) {
          if (r.parent_id === where.parent_id && r.is_active === where.is_active) total++;
        }
        return total;
      },
    },
    user: { count: async () => 0 },
    userRole: { count: async () => 0 },
    businessCategory: { count: async () => 0 },
    document: { count: async () => 0 },
    $transaction: async (fn) => fn(db),
  };
  return db;
}

test('DepartmentsService — scoped list, lookup, anti-enumeration get, and create with active parent validation', async () => {
  const db = createInMemoryDepartmentDb([
    { id: 1n, code: 'HQ', name: 'Trụ sở chính', parent_id: null, is_active: true, version: 0 },
    { id: 2n, code: 'FIN', name: 'Tài chính', parent_id: 1n, is_active: true, version: 0 },
    { id: 3n, code: 'OLD', name: 'Phòng giải thể', parent_id: 1n, is_active: false, version: 1 },
  ]);
  const audits = [];
  const authz = {
    visibleDepartmentIds: async () => [1n, 2n],
    hasPermission: async (_p, _r, _a, opts) => opts.targetDepartmentId !== 99n,
    assertPermission: async () => {},
    invalidateAll: () => {},
  };
  const service = new DepartmentsService(authz, { record: async (_tx, ev) => audits.push(ev) }, db);

  const listed = await service.list(adminPrincipal);
  assert.equal(listed.data.length, 2);

  const lookup = await service.lookup();
  assert.equal(lookup.data.length, 2, 'Inactive departments must be excluded from lookup');

  await assert.rejects(() => service.get(adminPrincipal, 99n), NotFoundException);

  await assert.rejects(
    () => service.create(adminPrincipal, { code: 'SUB_OLD', name: 'Sub', parentId: 3n }, ctx),
    NotFoundException,
  );

  const created = await service.create(
    adminPrincipal,
    { code: 'FIN_TAX', name: 'Phòng Thuế', parentId: 2n },
    ctx,
  );
  assert.equal(created.code, 'FIN_TAX');
  assert.equal(created.parentId, '2');
  assert.equal(audits[0].action, 'DEPARTMENT_CREATED');
});

test('DepartmentsService — update blocks self-parent, tree cycles, and stale OCC versions; deactivate enforces leaf integrity', async () => {
  const db = createInMemoryDepartmentDb([
    { id: 1n, code: 'ROOT', name: 'Root', parent_id: null, is_active: true, version: 0 },
    { id: 2n, code: 'CHILD', name: 'Child', parent_id: 1n, is_active: true, version: 0 },
    { id: 3n, code: 'GRANDCHILD', name: 'Grandchild', parent_id: 2n, is_active: true, version: 0 },
  ]);
  let invalidated = 0;
  const service = new DepartmentsService(
    {
      hasPermission: async () => true,
      assertPermission: async () => {},
      invalidateAll: () => {
        invalidated++;
      },
    },
    { record: async () => {} },
    db,
  );

  await assert.rejects(
    () => service.update(adminPrincipal, 1n, { expectedVersion: 0, parentId: 1n }, ctx),
    ConflictException,
  );

  await assert.rejects(
    () => service.update(adminPrincipal, 1n, { expectedVersion: 0, parentId: 3n }, ctx),
    /cycle is not allowed/i,
  );

  await assert.rejects(
    () => service.update(adminPrincipal, 3n, { expectedVersion: 99, name: 'Stale' }, ctx),
    /changed by another request/i,
  );

  await assert.rejects(() => service.deactivate(adminPrincipal, 2n, 0, ctx), ConflictException);

  const deactivatedLeaf = await service.deactivate(adminPrincipal, 3n, 0, ctx);
  assert.equal(deactivatedLeaf.isActive, false);
  assert.equal(deactivatedLeaf.version, 1);
  assert.ok(invalidated >= 1);
});

test('DepartmentsController — enforces authentication, CSRF double-submit token, and strict Zod payload schemas', async () => {
  const db = createInMemoryDepartmentDb([
    { id: 1n, code: 'HQ', name: 'HQ', parent_id: null, is_active: true, version: 0 },
  ]);
  const service = new DepartmentsService(
    {
      visibleDepartmentIds: async () => null,
      hasPermission: async () => true,
      assertPermission: async () => {},
      invalidateAll: () => {},
    },
    { record: async () => {} },
    db,
  );
  const csrf = new CsrfService(new AppConfigService({ CORS_ORIGIN: 'http://localhost:3000' }));
  const token = 'csrf-token-0123456789abcdef0123456789abcdef';
  const controller = new DepartmentsController(service, csrf);

  await assert.rejects(
    async () => controller.lookup({ ip: '127.0.0.1', headers: {} }),
    UnauthorizedException,
  );

  const authedReq = {
    auth: adminPrincipal,
    ip: '127.0.0.1',
    cookies: { sda_csrf: token },
    headers: {
      origin: 'http://localhost:3000',
      'x-csrf-token': token,
      'user-agent': 'node-test',
    },
  };

  const created = await controller.create(
    { code: 'LEGAL_01', name: 'Ban Pháp Chế', parentId: '1' },
    authedReq,
  );
  assert.equal(created.code, 'LEGAL_01');
  await assert.rejects(async () =>
    controller.create({ code: 'bad lowercase', name: 'X' }, authedReq),
  );
});

function createScopedAuthorizationService(db, grantsByUserId) {
  const authz = Object.create(AuthorizationService.prototype);
  authz.database = db;
  authz.effectiveGrants = async (userId) => grantsByUserId.get(userId) ?? [];
  authz.invalidateAll = async () => {};
  return authz;
}

test('DepartmentsService [BUG-004] — blocks scoped admin from promoting child to root (parentId: null) or detaching outside scope, while allowing in-scope reparent, no-op parentId rename, global promotion, and TOCTOU guard', async () => {
  const db = createInMemoryDepartmentDb([
    { id: 1n, code: 'HQ', name: 'Trụ sở chính', parent_id: null, is_active: true, version: 0 },
    { id: 2n, code: 'DEPT_A', name: 'Phòng A', parent_id: 1n, is_active: true, version: 0 },
    { id: 3n, code: 'DEPT_B', name: 'Phòng B', parent_id: 2n, is_active: true, version: 0 },
    { id: 4n, code: 'DEPT_C', name: 'Phòng C', parent_id: 2n, is_active: true, version: 0 },
    { id: 5n, code: 'OTHER_ROOT', name: 'Khối Khác', parent_id: null, is_active: true, version: 0 },
  ]);

  const deptManageGrant = (scopeDepartmentId) => ({
    permissionId: 10n,
    code: 'DEPARTMENT_MANAGE',
    resource: 'DEPARTMENT',
    action: 'MANAGE',
    roleId: 1n,
    roleCode: 'DEPT_ADMIN',
    scopeDepartmentId,
    validTo: null,
  });

  const deptAAdmin = { ...adminPrincipal, userId: 101n, username: 'admin.depta' };
  const hqScopedAdmin = { ...adminPrincipal, userId: 102n, username: 'admin.hq' };
  const dualScopedAdmin = { ...adminPrincipal, userId: 103n, username: 'admin.dual' };
  const globalAdmin = { ...adminPrincipal, userId: 104n, username: 'admin.global' };

  const grantsByUserId = new Map([
    [deptAAdmin.userId, [deptManageGrant(2n)]],
    [hqScopedAdmin.userId, [deptManageGrant(1n)]],
    [dualScopedAdmin.userId, [deptManageGrant(2n), deptManageGrant(5n)]],
    [globalAdmin.userId, [deptManageGrant(null)]],
  ]);

  const authz = createScopedAuthorizationService(db, grantsByUserId);
  const service = new DepartmentsService(authz, { record: async () => {} }, db);

  // 1. BUG-004: Dept A admin cannot promote child Dept B to global root (parentId: null)
  await assert.rejects(
    () => service.update(deptAAdmin, 3n, { expectedVersion: 0, parentId: null }, ctx),
    ForbiddenException,
  );
  assert.equal(db.rows.get(3n).parent_id, 2n);

  // 2. Dept A admin cannot promote Dept A itself to global root (parentId: null)
  await assert.rejects(
    () => service.update(deptAAdmin, 2n, { expectedVersion: 0, parentId: null }, ctx),
    ForbiddenException,
  );
  assert.equal(db.rows.get(2n).parent_id, 1n);

  // 3. Dept A admin cannot move Dept B into external branch OTHER_ROOT
  await assert.rejects(
    () => service.update(deptAAdmin, 3n, { expectedVersion: 0, parentId: 5n }, ctx),
    ForbiddenException,
  );
  assert.equal(db.rows.get(3n).parent_id, 2n);

  // 4. Dual-scoped admin (Dept A + OTHER_ROOT, no HQ) cannot detach Dept A from HQ into OTHER_ROOT
  await assert.rejects(
    () => service.update(dualScopedAdmin, 2n, { expectedVersion: 0, parentId: 5n }, ctx),
    ForbiddenException,
  );
  assert.equal(db.rows.get(2n).parent_id, 1n);

  // 5. Dual-scoped admin (HQ + OTHER_ROOT, no global) cannot demote root HQ under OTHER_ROOT
  grantsByUserId.set(dualScopedAdmin.userId, [deptManageGrant(1n), deptManageGrant(5n)]);
  await assert.rejects(
    () => service.update(dualScopedAdmin, 1n, { expectedVersion: 0, parentId: 5n }, ctx),
    ForbiddenException,
  );
  assert.equal(db.rows.get(1n).parent_id, null);

  // 6. Dept A admin CAN legitimately reparent Dept B under sibling Dept C inside Dept A's subtree
  const movedInScope = await service.update(
    deptAAdmin,
    3n,
    { expectedVersion: 0, parentId: 4n },
    ctx,
  );
  assert.equal(movedInScope.parentId, '4');
  assert.equal(movedInScope.version, 1);

  // 7. Scoped admins CAN rename their own scope root even when client echoes unchanged parentId
  const renamedDeptA = await service.update(
    deptAAdmin,
    2n,
    { expectedVersion: 0, name: 'Phòng A Đổi Tên', parentId: 1n },
    ctx,
  );
  assert.equal(renamedDeptA.name, 'Phòng A Đổi Tên');
  assert.equal(renamedDeptA.parentId, '1');

  const renamedHq = await service.update(
    hqScopedAdmin,
    1n,
    { expectedVersion: 0, name: 'Trụ Sở Chính Mới', parentId: null },
    ctx,
  );
  assert.equal(renamedHq.name, 'Trụ Sở Chính Mới');
  assert.equal(renamedHq.parentId, null);

  // 8. Global admin CAN legitimately promote Dept B to global root (parentId: null)
  const promotedToRoot = await service.update(
    globalAdmin,
    3n,
    { expectedVersion: 1, parentId: null },
    ctx,
  );
  assert.equal(promotedToRoot.parentId, null);
  assert.equal(promotedToRoot.version, 2);

  // 9. TOCTOU guard: if parent_id mutates concurrently between pre-tx checks and entering SERIALIZABLE tx, reject with ConflictException
  const origTransaction = db.$transaction;
  db.$transaction = async (fn) => {
    const current = db.rows.get(1n);
    db.rows.set(1n, { ...current, parent_id: 5n });
    return origTransaction(fn);
  };
  await assert.rejects(
    () =>
      service.update(
        hqScopedAdmin,
        1n,
        { expectedVersion: 1, name: 'TOCTOU Attempt', parentId: null },
        ctx,
      ),
    ConflictException,
  );
  assert.equal(db.rows.get(1n).parent_id, 5n);
});

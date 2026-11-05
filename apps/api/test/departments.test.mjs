import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ConflictException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { AppConfigService } from '../dist/config/config.service.js';
import { CsrfService } from '../dist/modules/auth/csrf.service.js';
import { DepartmentsService } from '../dist/modules/departments/departments.service.js';
import { DepartmentsController } from '../dist/modules/departments/departments.controller.js';

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

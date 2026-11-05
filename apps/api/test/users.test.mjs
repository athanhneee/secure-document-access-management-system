import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { AppConfigService } from '../dist/config/config.service.js';
import { CsrfService } from '../dist/modules/auth/csrf.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';
import { UsersService } from '../dist/modules/users/users.service.js';
import { UsersController } from '../dist/modules/users/users.controller.js';

const managerPrincipal = {
  userId: 1n,
  sessionId: 'sess-mgr',
  username: 'mgr.identity',
  roles: ['USER_MANAGER_CUSTOM'],
  mfa: true,
};
const ctx = { ip: '10.0.0.25', correlationId: 'corr-users-test' };

function makeUserRow(id, username, email, fullName, empCode, dept, extra = {}) {
  return {
    id,
    username,
    email,
    full_name: fullName,
    employee_code: empCode,
    department_id: dept?.id ?? null,
    password_hash: 'argon2id-hash',
    status: 'ACTIVE',
    locked_until: null,
    disabled_at: null,
    failed_login_count: 0,
    version: 0,
    departments: dept ?? null,
    user_roles_user_roles_user_idTousers: [],
    ...extra,
  };
}

function createInMemoryUsersDb() {
  const departments = new Map([
    [1n, { id: 1n, code: 'DEPT_A', name: 'Khối Công Nghệ', is_active: true }],
    [2n, { id: 2n, code: 'DEPT_B', name: 'Khối Vận Hành', is_active: true }],
  ]);
  const users = new Map([
    [
      1n,
      makeUserRow(
        1n,
        'mgr.identity',
        'mgr@sda.local',
        'Quản lý Định danh',
        'EMP-001',
        departments.get(1n),
      ),
    ],
    [
      2n,
      makeUserRow(
        2n,
        'staff.alpha',
        'staff.alpha@sda.local',
        'Nhân viên Alpha',
        'EMP-002',
        departments.get(1n),
        {
          failed_login_count: 2,
          user_roles_user_roles_user_idTousers: [
            {
              id: 11n,
              role_id: 5n,
              scope_department_id: 1n,
              valid_from: new Date('2026-01-01T00:00:00Z'),
              valid_to: null,
              roles: { id: 5n, code: 'DOCUMENT_READER' },
            },
          ],
        },
      ),
    ],
  ]);

  let nextUserId = 10n;
  let expiredDeptRolesCount = 0;
  let revokedSessionsCount = 0;

  const db = {
    users,
    get expiredDeptRolesCount() {
      return expiredDeptRolesCount;
    },
    get revokedSessionsCount() {
      return revokedSessionsCount;
    },
    department: {
      findFirst: async ({ where }) => {
        const d = departments.get(where.id);
        return d && d.is_active === where.is_active ? d : null;
      },
    },
    user: {
      findUnique: async ({ where }) => users.get(where.id) ?? null,
      findUniqueOrThrow: async ({ where }) => {
        const u = users.get(where.id);
        if (!u) throw new Error('User missing');
        return u;
      },
      findMany: async ({ where } = {}) => {
        let list = [...users.values()];
        if (where?.department_id?.in) {
          const allowed = new Set(where.department_id.in.map(String));
          list = list.filter((u) => allowed.has(String(u.department_id)));
        }
        if (where?.status) list = list.filter((u) => u.status === where.status);
        return list;
      },
      create: async ({ data }) => {
        const dept = data.department_id ? departments.get(data.department_id) : null;
        const created = makeUserRow(
          nextUserId++,
          data.username,
          data.email,
          data.full_name,
          data.employee_code,
          dept,
          { password_hash: data.password_hash, status: data.status },
        );
        users.set(created.id, created);
        return created;
      },
      updateMany: async ({ where, data }) => {
        const current = users.get(where.id);
        if (!current || current.version !== where.version) return { count: 0 };
        const patch = Object.fromEntries(
          Object.entries(data).filter(([, val]) => val !== undefined),
        );
        users.set(where.id, { ...current, ...patch, version: current.version + 1 });
        return { count: 1 };
      },
    },
    userRole: {
      updateMany: async () => {
        expiredDeptRolesCount += 1;
        return { count: 1 };
      },
    },
    authSession: {
      updateMany: async () => {
        revokedSessionsCount += 1;
        return { count: 1 };
      },
    },
    refreshToken: { updateMany: async () => ({ count: 1 }) },
    accessSession: { updateMany: async () => ({ count: 1 }) },
    userAttributeAssignment: { findMany: async () => [] },
    $transaction: async (fn) => fn(db),
  };
  return db;
}

test('UsersService — currentUser projects deduplicated roles/permissions, list/get enforce scope, create hashes Argon2id & rejects weak passwords', async () => {
  const db = createInMemoryUsersDb();
  const audits = [];
  const authz = {
    effectiveGrants: async () => [
      { roleCode: 'USER_MANAGER', resource: 'USER', action: 'MANAGE' },
      { roleCode: 'USER_MANAGER', resource: 'DEPARTMENT', action: 'VIEW' },
    ],
    visibleDepartmentIds: async () => [1n],
    hasPermission: async (_p, _r, _a, opts) => opts.targetDepartmentId === 1n,
    assertPermission: async () => {},
    invalidateUser: () => {},
  };
  const service = new UsersService(
    authz,
    new PasswordService(),
    { record: async (_tx, ev) => audits.push(ev) },
    db,
  );

  const me = await service.currentUser(managerPrincipal);
  assert.deepEqual(me.roles, ['USER_MANAGER']);
  assert.deepEqual(me.permissions, ['DEPARTMENT:VIEW', 'USER:MANAGE']);
  assert.equal(me.departmentName, 'Khối Công Nghệ');

  const listed = await service.list(managerPrincipal);
  assert.equal(listed.data.length, 2);

  const detail = await service.get(managerPrincipal, 2n);
  assert.equal(detail.username, 'staff.alpha');
  assert.equal(detail.roleAssignments.length, 1);

  await assert.rejects(() => service.get(managerPrincipal, 999n), NotFoundException);

  await assert.rejects(
    () =>
      service.create(
        managerPrincipal,
        {
          username: 'new.user',
          email: 'new.user@sda.local',
          fullName: 'New User',
          departmentId: 1n,
          password: 'invalid-new.user-WeakPassword123!',
        },
        ctx,
      ),
    BadRequestException,
  );

  const created = await service.create(
    managerPrincipal,
    {
      username: 'sec.analyst',
      email: 'analyst@sda.local',
      fullName: 'Chuyên viên Phân tích',
      employeeCode: 'EMP-010',
      departmentId: 1n,
      password: 'fixture-Str0ng#Passphrase!2026$XyZ',
    },
    ctx,
  );
  const storedNewUser = db.users.get(BigInt(created.id));
  assert.ok(storedNewUser.password_hash.startsWith('$argon2id$'));
  assert.equal(audits.at(-1).action, 'USER_CREATED');
});

test('UsersService & UsersController — department transfer expires old roles, OCC CAS rejects stale version, lock/unlock/disable revokes sessions & blocks self-disable', async () => {
  const db = createInMemoryUsersDb();
  const authz = {
    effectiveGrants: async () => [],
    visibleDepartmentIds: async () => null,
    hasPermission: async () => true,
    assertPermission: async () => {},
    invalidateUser: () => {},
  };
  const service = new UsersService(authz, new PasswordService(), { record: async () => {} }, db);

  const transferred = await service.update(
    managerPrincipal,
    2n,
    { expectedVersion: 0, departmentId: 2n, fullName: 'Nhân viên Alpha (Điều chuyển)' },
    ctx,
  );
  assert.equal(transferred.departmentId, '2');
  assert.equal(db.expiredDeptRolesCount, 1);

  await assert.rejects(
    () => service.update(managerPrincipal, 2n, { expectedVersion: 0, fullName: 'Stale' }, ctx),
    ConflictException,
  );

  const locked = await service.lock(managerPrincipal, 2n, 1, ctx);
  assert.equal(locked.status, 'LOCKED');
  assert.equal(db.revokedSessionsCount, 1);

  const unlocked = await service.unlock(managerPrincipal, 2n, 2, ctx);
  assert.equal(unlocked.status, 'ACTIVE');
  assert.equal(db.users.get(2n).failed_login_count, 0);

  await assert.rejects(
    async () => service.disable(managerPrincipal, 1n, 0, ctx),
    ForbiddenException,
  );

  const csrf = new CsrfService(new AppConfigService({ CORS_ORIGIN: 'http://localhost:3000' }));
  const token = 'csrf-token-0123456789abcdef0123456789abcdef';
  const controller = new UsersController(service, csrf);

  await assert.rejects(
    async () => controller.me({ ip: '127.0.0.1', headers: {} }),
    UnauthorizedException,
  );

  const disabledViaController = await controller.disable(
    '2',
    { expectedVersion: 3 },
    {
      auth: managerPrincipal,
      ip: '127.0.0.1',
      cookies: { sda_csrf: token },
      headers: { origin: 'http://localhost:3000', 'x-csrf-token': token },
    },
  );
  assert.equal(disabledViaController.status, 'DISABLED');
});

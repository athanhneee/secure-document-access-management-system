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
  const token = 'test-placeholder-csrf-token-000000000000';
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

test('UsersService & UsersController — clearance options, create/update/PUT clearance, OCC CAS & Bell-LaPadula downgrade cascade', async () => {
  const baseDb = createInMemoryUsersDb();
  const clearanceDef = { id: 1n, code: 'CLEARANCE_LEVEL', is_active: true };
  const clearanceOptions = new Map([
    [
      1n,
      {
        id: 1n,
        attribute_definition_id: 1n,
        value_code: 'INTERNAL',
        display_name: 'Nội bộ',
        numeric_rank: 1,
        is_active: true,
        sort_order: 1,
      },
    ],
    [
      2n,
      {
        id: 2n,
        attribute_definition_id: 1n,
        value_code: 'CONFIDENTIAL',
        display_name: 'Mật',
        numeric_rank: 2,
        is_active: true,
        sort_order: 2,
      },
    ],
    [
      3n,
      {
        id: 3n,
        attribute_definition_id: 1n,
        value_code: 'SECRET',
        display_name: 'Tối mật',
        numeric_rank: 3,
        is_active: true,
        sort_order: 3,
      },
    ],
    [
      99n,
      {
        id: 99n,
        attribute_definition_id: 2n,
        value_code: 'ACTIVE_STAFF',
        display_name: 'Nhân sự chính thức',
        numeric_rank: 2,
        is_active: true,
        sort_order: 1,
      },
    ],
  ]);

  let nextAttrAssignId = 100n;
  const assignments = [];
  const grants = [
    {
      id: 'grant-secret',
      principal_type: 'USER',
      principal_user_id: 2n,
      status: 'ACTIVE',
      version: 0,
      documents: { classification_history: [{ classification_levels: { rank: 3 } }] },
    },
    {
      id: 'grant-internal',
      principal_type: 'USER',
      principal_user_id: 2n,
      status: 'ACTIVE',
      version: 0,
      documents: { classification_history: [{ classification_levels: { rank: 1 } }] },
    },
  ];
  const sessions = [
    {
      id: 'sess-secret',
      user_id: 2n,
      status: 'ACTIVE',
      document_versions: {
        document: { classification_history: [{ classification_levels: { rank: 3 } }] },
      },
    },
    {
      id: 'sess-internal',
      user_id: 2n,
      status: 'ACTIVE',
      document_versions: {
        document: { classification_history: [{ classification_levels: { rank: 1 } }] },
      },
    },
  ];

  const enrichAssignment = (row) => ({
    ...row,
    attribute_definitions: clearanceDef,
    attribute_options: clearanceOptions.get(row.option_id) ?? null,
  });

  const db = {
    ...baseDb,
    attributeDefinition: {
      findUnique: async ({ where }) =>
        where.code === 'CLEARANCE_LEVEL'
          ? {
              ...clearanceDef,
              attribute_options: [...clearanceOptions.values()]
                .filter((o) => o.attribute_definition_id === 1n && o.is_active)
                .sort((a, b) => a.numeric_rank - b.numeric_rank),
            }
          : null,
    },
    attributeOption: {
      findFirst: async ({ where }) => {
        const opt = clearanceOptions.get(where.id);
        if (!opt) return null;
        if (opt.attribute_definition_id !== where.attribute_definition_id) return null;
        if (where.is_active !== undefined && opt.is_active !== where.is_active) return null;
        return opt;
      },
    },
    userAttributeAssignment: {
      findFirst: async ({ where }) => {
        const now = where.valid_from?.lte ?? new Date();
        const matches = assignments
          .filter(
            (a) =>
              a.user_id === where.user_id &&
              a.valid_from <= now &&
              (a.valid_to === null || a.valid_to > now),
          )
          .map(enrichAssignment)
          .sort(
            (a, b) =>
              (b.attribute_options?.numeric_rank ?? 0) - (a.attribute_options?.numeric_rank ?? 0),
          );
        return matches[0] ?? null;
      },
      findMany: async ({ where }) => {
        const userFilter = where.user_id?.in
          ? new Set(where.user_id.in.map(String))
          : where.user_id !== undefined
            ? new Set([String(where.user_id)])
            : null;
        const now = where.valid_from?.lte ?? where.OR?.[1]?.valid_to?.gt ?? new Date();
        return assignments
          .filter((a) => {
            if (userFilter && !userFilter.has(String(a.user_id))) return false;
            if (where.valid_from?.lte && a.valid_from > where.valid_from.lte) return false;
            if (where.OR && !(a.valid_to === null || a.valid_to > now)) return false;
            return true;
          })
          .map(enrichAssignment);
      },
      create: async ({ data }) => {
        const row = { id: nextAttrAssignId++, ...data };
        assignments.push(row);
        return row;
      },
      updateMany: async ({ where, data }) => {
        const ids = new Set((where.id?.in ?? []).map(String));
        let count = 0;
        for (const row of assignments) {
          if (ids.has(String(row.id))) {
            Object.assign(row, data);
            count += 1;
          }
        }
        return { count };
      },
      deleteMany: async ({ where }) => {
        const ids = new Set((where.id?.in ?? []).map(String));
        let count = 0;
        for (let i = assignments.length - 1; i >= 0; i--) {
          if (ids.has(String(assignments[i].id))) {
            assignments.splice(i, 1);
            count += 1;
          }
        }
        return { count };
      },
    },
    accessGrant: {
      findMany: async ({ where }) =>
        grants.filter(
          (g) =>
            g.principal_type === where.principal_type &&
            g.principal_user_id === where.principal_user_id &&
            g.status === where.status,
        ),
      update: async ({ where, data }) => {
        const g = grants.find((item) => item.id === where.id);
        Object.assign(g, data, { version: g.version + 1 });
        return g;
      },
    },
    accessSession: {
      findMany: async ({ where }) =>
        sessions.filter((s) => s.user_id === where.user_id && s.status === where.status),
      updateMany: async ({ where, data }) => {
        const ids = new Set(where.id?.in ?? []);
        let count = 0;
        for (const s of sessions) {
          if (ids.has(s.id) && s.status === where.status) {
            Object.assign(s, data);
            count += 1;
          }
        }
        return { count };
      },
    },
    $transaction: async (fn) => fn(db),
  };

  const audits = [];
  let invalidatedUsers = 0;
  const authz = {
    effectiveGrants: async () => [{ roleCode: 'SYSTEM_ADMIN', resource: 'USER', action: 'MANAGE' }],
    visibleDepartmentIds: async () => null,
    hasPermission: async () => true,
    assertPermission: async () => {},
    invalidateUser: () => {
      invalidatedUsers += 1;
    },
  };
  const service = new UsersService(
    authz,
    new PasswordService(),
    { record: async (_tx, ev) => audits.push(ev) },
    db,
  );
  const csrf = new CsrfService(new AppConfigService({ CORS_ORIGIN: 'http://localhost:3000' }));
  const token = 'test-placeholder-csrf-clearance-000000000000';
  const controller = new UsersController(service, csrf);
  const authedReq = {
    auth: managerPrincipal,
    ip: '127.0.0.1',
    cookies: { sda_csrf: token },
    headers: { origin: 'http://localhost:3000', 'x-csrf-token': token },
  };

  // 1. List clearance options sorted by rank
  const opts = await controller.clearanceOptions();
  assert.deepEqual(
    opts.data.map((o) => [o.code, o.rank]),
    [
      ['INTERNAL', 1],
      ['CONFIDENTIAL', 2],
      ['SECRET', 3],
    ],
  );

  // 2. Reject cross-attribute option injection when creating user
  await assert.rejects(
    () =>
      service.create(
        managerPrincipal,
        {
          username: 'bad.clearance',
          email: 'bad.clearance@sda.local',
          fullName: 'Bad Clearance',
          departmentId: 1n,
          clearanceOptionId: 99n,
          password: 'fixture-Str0ng#Passphrase!2026$XyZ',
        },
        ctx,
      ),
    BadRequestException,
  );

  // 3. Create user with initial SECRET clearance & verify projection in get/list
  const created = await service.create(
    managerPrincipal,
    {
      username: 'owner.cleared',
      email: 'owner.cleared@sda.local',
      fullName: 'Chủ sở hữu có độ mật',
      departmentId: 1n,
      clearanceOptionId: 3n,
      password: 'fixture-Str0ng#Passphrase!2026$XyZ',
    },
    ctx,
  );
  const createdDetail = await service.get(managerPrincipal, BigInt(created.id));
  assert.equal(createdDetail.clearanceCode, 'SECRET');
  assert.equal(createdDetail.clearanceRank, 3);
  assert.equal(createdDetail.clearanceOptionId, '3');

  const listed = await service.list(managerPrincipal);
  const listedNew = listed.data.find((u) => u.id === created.id);
  assert.equal(listedNew.clearanceCode, 'SECRET');
  assert.equal(listedNew.clearanceRank, 3);

  // 4. Upgrade user #2 to SECRET via PUT /users/:id/clearance, then verify /users/me reflects clearance
  const upgraded = await controller.updateClearance(
    '2',
    { expectedVersion: 0, clearanceOptionId: '3' },
    authedReq,
  );
  assert.equal(upgraded.clearanceCode, 'SECRET');
  assert.equal(upgraded.clearanceRank, 3);
  assert.equal(upgraded.revokedGrantsCount, 0);
  assert.equal(upgraded.terminatedSessionsCount, 0);
  assert.equal(audits.at(-1).action, 'USER_CLEARANCE_UPDATED');

  const meUser2 = await service.currentUser({ ...managerPrincipal, userId: 2n });
  assert.equal(meUser2.clearanceCode, 'SECRET');
  assert.equal(meUser2.clearanceRank, 3);

  // 5. Downgrade user #2 from SECRET (3) -> INTERNAL (1) must cascade-revoke rank-3 grant & session but keep rank-1
  const downgraded = await controller.updateClearance(
    '2',
    { expectedVersion: 1, clearanceOptionId: '1' },
    authedReq,
  );
  assert.equal(downgraded.clearanceCode, 'INTERNAL');
  assert.equal(downgraded.clearanceRank, 1);
  assert.equal(downgraded.revokedGrantsCount, 1);
  assert.equal(downgraded.terminatedSessionsCount, 1);
  assert.equal(grants.find((g) => g.id === 'grant-secret').status, 'REVOKED');
  assert.equal(grants.find((g) => g.id === 'grant-internal').status, 'ACTIVE');
  assert.equal(sessions.find((s) => s.id === 'sess-secret').status, 'TERMINATED');
  assert.equal(sessions.find((s) => s.id === 'sess-internal').status, 'ACTIVE');

  // 6. Revoking clearance to null via PATCH /users/:id drops to Rank 0 & cascades remaining rank-1 grant/session
  const clearedViaPatch = await service.update(
    managerPrincipal,
    2n,
    { expectedVersion: 2, clearanceOptionId: null },
    ctx,
  );
  assert.equal(clearedViaPatch.clearanceCode, null);
  assert.equal(clearedViaPatch.clearanceRank, 0);
  assert.equal(grants.find((g) => g.id === 'grant-internal').status, 'REVOKED');
  assert.equal(sessions.find((s) => s.id === 'sess-internal').status, 'TERMINATED');
  assert.ok(invalidatedUsers >= 3);

  // 7. Stale OCC version rejected with ConflictException
  await assert.rejects(
    () =>
      controller.updateClearance('2', { expectedVersion: 1, clearanceOptionId: '2' }, authedReq),
    ConflictException,
  );

  // 8. Required SUBJECT_DEPARTMENT alignment: reject null/missing department on create & clearing department on update
  await assert.rejects(
    () =>
      service.create(
        managerPrincipal,
        {
          username: 'no.dept.user',
          email: 'no.dept.user@sda.local',
          fullName: 'Thiếu Phòng Ban',
          departmentId: null,
          password: 'fixture-Str0ng#Passphrase!2026$XyZ',
        },
        ctx,
      ),
    BadRequestException,
  );
  await assert.rejects(
    () => service.update(managerPrincipal, 2n, { expectedVersion: 3, departmentId: null }, ctx),
    BadRequestException,
  );

  // 9. BUG-007: Block self-clearance modification via both PUT /users/:ownId/clearance and PATCH /users/:ownId
  await assert.rejects(
    () =>
      controller.updateClearance('1', { expectedVersion: 0, clearanceOptionId: '3' }, authedReq),
    ForbiddenException,
  );
  await assert.rejects(
    () =>
      controller.updateClearance('1', { expectedVersion: 0, clearanceOptionId: null }, authedReq),
    ForbiddenException,
  );
  await assert.rejects(
    () => service.update(managerPrincipal, 1n, { expectedVersion: 0, clearanceOptionId: 3n }, ctx),
    ForbiddenException,
  );
  await assert.rejects(
    () =>
      service.update(managerPrincipal, 1n, { expectedVersion: 0, clearanceOptionId: null }, ctx),
    ForbiddenException,
  );
  // Updating own non-clearance profile fields (without clearanceOptionId) remains allowed
  const selfRenamed = await service.update(
    managerPrincipal,
    1n,
    { expectedVersion: 0, fullName: 'Quản lý Định danh (Cập nhật)' },
    ctx,
  );
  assert.equal(selfRenamed.fullName, 'Quản lý Định danh (Cập nhật)');
});

test('UsersService [BUG-006] — enforces user management privilege hierarchy and preserves at least 1 active global SYSTEM_ADMIN', async () => {
  const departments = new Map([
    [1n, { id: 1n, code: 'HEAD_OFFICE', name: 'Trụ sở chính', parent_id: null, is_active: true }],
    [2n, { id: 2n, code: 'SUB_DEPT', name: 'Phòng trực thuộc', parent_id: 1n, is_active: true }],
  ]);

  const userManagePerm = { id: 10n, code: 'USER_MANAGE', resource_type: 'USER', action: 'MANAGE' };
  const alertManagePerm = {
    id: 11n,
    code: 'ALERT_MANAGE',
    resource_type: 'SECURITY_ALERT',
    action: 'MANAGE',
  };
  const docViewPerm = { id: 12n, code: 'DOCUMENT_VIEW', resource_type: 'DOCUMENT', action: 'VIEW' };

  const users = new Map([
    [1n, makeUserRow(1n, 'dept.mgr', 'dept.mgr@sda.local', 'Dept Mgr', 'E1', departments.get(1n))],
    [2n, makeUserRow(2n, 'sys.admin1', 'sys1@sda.local', 'Sys Admin 1', 'E2', departments.get(1n))],
    [3n, makeUserRow(3n, 'sec.officer', 'soc@sda.local', 'Sec Officer', 'E3', departments.get(1n))],
    [4n, makeUserRow(4n, 'auditor.u', 'aud@sda.local', 'Auditor', 'E4', departments.get(1n))],
    [
      5n,
      makeUserRow(5n, 'global.reader', 'gr@sda.local', 'Global Reader', 'E5', departments.get(1n)),
    ],
    [6n, makeUserRow(6n, 'scoped.soc', 'ssoc@sda.local', 'Scoped SOC', 'E6', departments.get(1n))],
    [7n, makeUserRow(7n, 'peer.mgr', 'peer@sda.local', 'Peer Mgr', 'E7', departments.get(1n))],
    [8n, makeUserRow(8n, 'sub.mgr', 'sub@sda.local', 'Sub Dept Mgr', 'E8', departments.get(2n))],
    [9n, makeUserRow(9n, 'staff.u', 'staff@sda.local', 'Normal Staff', 'E9', departments.get(1n))],
    [
      10n,
      makeUserRow(10n, 'sys.admin2', 'sys2@sda.local', 'Sys Admin 2', 'E10', departments.get(1n), {
        status: 'LOCKED',
      }),
    ],
  ]);

  const past = new Date(Date.now() - 3600_000);
  const roleAssignments = [
    {
      id: 101n,
      user_id: 2n,
      scope_department_id: null,
      valid_from: past,
      valid_to: null,
      roles: {
        code: 'SYSTEM_ADMIN',
        is_active: true,
        role_permissions: [{ permission_id: userManagePerm.id, permissions: userManagePerm }],
      },
    },
    {
      id: 102n,
      user_id: 3n,
      scope_department_id: null,
      valid_from: past,
      valid_to: null,
      roles: {
        code: 'SECURITY_OFFICER',
        is_active: true,
        role_permissions: [{ permission_id: alertManagePerm.id, permissions: alertManagePerm }],
      },
    },
    {
      id: 103n,
      user_id: 4n,
      scope_department_id: 1n,
      valid_from: past,
      valid_to: null,
      roles: { code: 'AUDITOR', is_active: true, role_permissions: [] },
    },
    {
      id: 104n,
      user_id: 5n,
      scope_department_id: null,
      valid_from: past,
      valid_to: null,
      roles: {
        code: 'DOCUMENT_READER',
        is_active: true,
        role_permissions: [{ permission_id: docViewPerm.id, permissions: docViewPerm }],
      },
    },
    {
      id: 105n,
      user_id: 6n,
      scope_department_id: 1n,
      valid_from: past,
      valid_to: null,
      roles: {
        code: 'CUSTOM_SOC',
        is_active: true,
        role_permissions: [{ permission_id: alertManagePerm.id, permissions: alertManagePerm }],
      },
    },
    {
      id: 106n,
      user_id: 7n,
      scope_department_id: 1n,
      valid_from: past,
      valid_to: null,
      roles: {
        code: 'DEPT_USER_MGR',
        is_active: true,
        role_permissions: [{ permission_id: userManagePerm.id, permissions: userManagePerm }],
      },
    },
    {
      id: 107n,
      user_id: 8n,
      scope_department_id: 2n,
      valid_from: past,
      valid_to: null,
      roles: {
        code: 'SUB_USER_MGR',
        is_active: true,
        role_permissions: [{ permission_id: userManagePerm.id, permissions: userManagePerm }],
      },
    },
    {
      id: 108n,
      user_id: 9n,
      scope_department_id: 1n,
      valid_from: past,
      valid_to: null,
      roles: {
        code: 'DOCUMENT_READER',
        is_active: true,
        role_permissions: [{ permission_id: docViewPerm.id, permissions: docViewPerm }],
      },
    },
    {
      id: 109n,
      user_id: 10n,
      scope_department_id: null,
      valid_from: past,
      valid_to: null,
      roles: {
        code: 'SYSTEM_ADMIN',
        is_active: true,
        role_permissions: [{ permission_id: userManagePerm.id, permissions: userManagePerm }],
      },
    },
  ];

  const db = {
    department: {
      findUnique: async ({ where }) => departments.get(where.id) ?? null,
      findFirst: async ({ where }) => {
        const d = departments.get(where.id);
        return d && d.is_active === where.is_active ? d : null;
      },
    },
    user: {
      findUnique: async ({ where }) => users.get(where.id) ?? null,
      findUniqueOrThrow: async ({ where }) => users.get(where.id),
      updateMany: async ({ where, data }) => {
        const cur = users.get(where.id);
        if (!cur || cur.version !== where.version) return { count: 0 };
        const patch = Object.fromEntries(Object.entries(data).filter(([, v]) => v !== undefined));
        users.set(where.id, { ...cur, ...patch, version: cur.version + 1 });
        return { count: 1 };
      },
    },
    userRole: {
      findMany: async ({ where }) =>
        roleAssignments.filter((a) => {
          if (where.user_id !== undefined && a.user_id !== where.user_id) return false;
          if (where.roles?.is_active && !a.roles.is_active) return false;
          return true;
        }),
      count: async ({ where }) =>
        roleAssignments.filter((a) => {
          if (typeof where.user_id === 'bigint' && a.user_id !== where.user_id) return false;
          if (where.user_id?.not !== undefined && a.user_id === where.user_id.not) return false;
          if (where.scope_department_id === null && a.scope_department_id !== null) return false;
          if (where.roles?.code && a.roles.code !== where.roles.code) return false;
          if (where.roles?.is_active && !a.roles.is_active) return false;
          if (where.valid_from?.lte && a.valid_from > where.valid_from.lte) return false;
          if (where.users_user_roles_user_idTousers?.status) {
            const u = users.get(a.user_id);
            if (!u || u.status !== where.users_user_roles_user_idTousers.status) return false;
          }
          return true;
        }).length,
      updateMany: async () => ({ count: 0 }),
    },
    authSession: { updateMany: async () => ({ count: 0 }) },
    refreshToken: { updateMany: async () => ({ count: 0 }) },
    accessSession: { updateMany: async () => ({ count: 0 }) },
    userAttributeAssignment: { findFirst: async () => null, findMany: async () => [] },
    $transaction: async (fn) => fn(db),
  };

  const deptMgrPrincipal = { ...managerPrincipal, userId: 1n, roles: ['DEPT_USER_MGR'] };
  const sysAdmin2Principal = { ...managerPrincipal, userId: 10n, roles: ['SYSTEM_ADMIN'] };

  const grantsByUser = new Map([
    [
      1n,
      [
        {
          permissionId: userManagePerm.id,
          code: 'USER_MANAGE',
          resource: 'USER',
          action: 'MANAGE',
          roleId: 1n,
          roleCode: 'DEPT_USER_MGR',
          scopeDepartmentId: 1n,
          validTo: null,
        },
      ],
    ],
    [
      10n,
      [
        {
          permissionId: userManagePerm.id,
          code: 'USER_MANAGE',
          resource: 'USER',
          action: 'MANAGE',
          roleId: 2n,
          roleCode: 'SYSTEM_ADMIN',
          scopeDepartmentId: null,
          validTo: null,
        },
      ],
    ],
  ]);

  const authz = {
    effectiveGrants: async (uid) => grantsByUser.get(uid) ?? [],
    hasPermission: async () => true,
    assertPermission: async () => {},
    invalidateUser: async () => {},
  };

  const service = new UsersService(authz, new PasswordService(), { record: async () => {} }, db);

  // 1. Department USER:MANAGE manager on HEAD_OFFICE is BLOCKED from acting on SYSTEM_ADMIN, SECURITY_OFFICER, AUDITOR, global-scoped user, scoped SOC, and peer dept manager
  await assert.rejects(() => service.disable(deptMgrPrincipal, 2n, 0, ctx), ForbiddenException);
  await assert.rejects(() => service.lock(deptMgrPrincipal, 2n, 0, ctx), ForbiddenException);
  await assert.rejects(
    () => service.update(deptMgrPrincipal, 2n, { expectedVersion: 0, email: 'hack@evil.com' }, ctx),
    ForbiddenException,
  );
  await assert.rejects(
    () =>
      service.updateClearance(
        deptMgrPrincipal,
        2n,
        { expectedVersion: 0, clearanceOptionId: null },
        ctx,
      ),
    ForbiddenException,
  );
  await assert.rejects(() => service.disable(deptMgrPrincipal, 3n, 0, ctx), ForbiddenException);
  await assert.rejects(() => service.lock(deptMgrPrincipal, 4n, 0, ctx), ForbiddenException);
  await assert.rejects(
    () => service.update(deptMgrPrincipal, 5n, { expectedVersion: 0, fullName: 'Hijacked' }, ctx),
    ForbiddenException,
  );
  await assert.rejects(() => service.disable(deptMgrPrincipal, 6n, 0, ctx), ForbiddenException);
  await assert.rejects(() => service.disable(deptMgrPrincipal, 7n, 0, ctx), ForbiddenException);

  // 2. Department manager CAN manage normal business staff and strictly subordinate sub-department manager
  const updatedStaff = await service.update(
    deptMgrPrincipal,
    9n,
    { expectedVersion: 0, fullName: 'Normal Staff Updated' },
    ctx,
  );
  assert.equal(updatedStaff.fullName, 'Normal Staff Updated');
  const lockedSubMgr = await service.lock(deptMgrPrincipal, 8n, 0, ctx);
  assert.equal(lockedSubMgr.status, 'LOCKED');

  // 3. Even a global SYSTEM_ADMIN cannot lock or disable the last ACTIVE global SYSTEM_ADMIN (user #10 is LOCKED so user #2 is the only ACTIVE one)
  await assert.rejects(() => service.disable(sysAdmin2Principal, 2n, 0, ctx), ConflictException);
  await assert.rejects(() => service.lock(sysAdmin2Principal, 2n, 0, ctx), ConflictException);

  // 4. Once user #10 is ACTIVE, disabling user #2 succeeds while leaving user #10 as the remaining ACTIVE global SYSTEM_ADMIN
  users.set(10n, { ...users.get(10n), status: 'ACTIVE' });
  const disabledAdmin1 = await service.disable(sysAdmin2Principal, 2n, 0, ctx);
  assert.equal(disabledAdmin1.status, 'DISABLED');
});

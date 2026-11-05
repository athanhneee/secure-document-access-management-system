import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { BadRequestException, ConflictException, ForbiddenException } from '@nestjs/common';
import { createEphemeralDatabaseHarness } from '../helpers/postgres-integration-harness.mjs';

const dbHarness = createEphemeralDatabaseHarness('sda_identity', { coerceBigIntId: true });
const ctx = { ip: '10.20.30.40', userAgent: 'integration-test', correlationId: randomUUID() };

let departmentsService;
let usersService;
let authorizationService;
let adminUser;
let hqDept;

function adminPrincipal() {
  return {
    userId: adminUser.id,
    sessionId: randomUUID(),
    username: 'sysadmin.ident',
    roles: ['SYSTEM_ADMIN'],
    mfa: true,
  };
}

before(async () => {
  const ready = await dbHarness.setup();
  if (!ready) return;

  const { sql, insertOne, prisma } = dbHarness;
  hqDept = await insertOne(
    "INSERT INTO departments(code,name) VALUES ('HQ_IDENT','Trụ sở chính') RETURNING id",
  );
  adminUser = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('sysadmin.ident','sysadmin.ident@corp.local','argon2-seed','Quản trị viên',$1,'ACTIVE') RETURNING id`,
    [hqDept.id],
  );

  const sysRole = await insertOne(
    "INSERT INTO roles(code,name,is_system_role,is_active,created_by) VALUES ('SYSTEM_ADMIN','System Admin',true,true,$1) RETURNING id",
    [adminUser.id],
  );
  const perms = [
    ['DEPT_READ', 'DEPARTMENT', 'READ'],
    ['DEPT_MANAGE', 'DEPARTMENT', 'MANAGE'],
    ['USER_READ', 'USER', 'READ'],
    ['USER_MANAGE', 'USER', 'MANAGE'],
  ];
  for (const [code, resType, action] of perms) {
    const p = await insertOne(
      'INSERT INTO permissions(code,name,resource_type,action) VALUES ($1,$1,$2,$3) RETURNING id',
      [code, resType, action],
    );
    await sql.query(
      'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3)',
      [sysRole.id, p.id, adminUser.id],
    );
  }
  await sql.query(
    "INSERT INTO user_roles(user_id,role_id,valid_from,assigned_by) VALUES ($1,$2,now() - interval '1 hour',$1)",
    [adminUser.id, sysRole.id],
  );

  const { AuthorizationCache } = await import('../../dist/modules/rbac/authorization-cache.js');
  const { AuthorizationService } = await import('../../dist/modules/rbac/authorization.service.js');
  const { RbacAuditService } = await import('../../dist/modules/rbac/rbac-audit.service.js');
  const { DepartmentsService } =
    await import('../../dist/modules/departments/departments.service.js');
  const { UsersService } = await import('../../dist/modules/users/users.service.js');
  const { PasswordService } = await import('../../dist/modules/auth/password.service.js');

  const cache = new AuthorizationCache();
  authorizationService = new AuthorizationService(cache);
  const audit = new RbacAuditService({
    get: () => 'integration-audit-hmac-secret-key-0123456789abcdef',
  });
  departmentsService = new DepartmentsService(authorizationService, audit, prisma);
  usersService = new UsersService(authorizationService, new PasswordService(), audit, prisma);
});

after(async () => {
  await dbHarness.teardown();
});

test('DepartmentsService SQL integration — hierarchy creation, cycle rejection (service + DB trigger), leaf deactivation & OCC', async () => {
  const actor = adminPrincipal();
  const finance = await departmentsService.create(
    actor,
    { code: 'FIN_DIV', name: 'Khối Tài chính', parentId: hqDept.id },
    ctx,
  );
  const accounting = await departmentsService.create(
    actor,
    { code: 'ACC_TEAM', name: 'Phòng Kế toán', parentId: BigInt(finance.id) },
    ctx,
  );

  const list = await departmentsService.list(actor);
  assert.ok(list.data.length >= 3);

  // Service-level cycle check blocks making HQ a child of its grandchild Accounting
  await assert.rejects(
    () =>
      departmentsService.update(
        actor,
        hqDept.id,
        { expectedVersion: 0, parentId: BigInt(accounting.id) },
        ctx,
      ),
    ConflictException,
  );

  // Database-level recursive CTE trigger blocks raw SQL cycle injection
  await assert.rejects(
    dbHarness.sql.query('UPDATE departments SET parent_id=$1 WHERE id=$2', [
      BigInt(accounting.id),
      hqDept.id,
    ]),
    /cycle/iu,
  );

  // Cannot deactivate Finance while child Accounting is still active
  await assert.rejects(
    () => departmentsService.deactivate(actor, BigInt(finance.id), 0, ctx),
    ConflictException,
  );

  // Deactivate leaf Accounting, then verify OCC version conflict on stale version
  const deactivatedLeaf = await departmentsService.deactivate(actor, BigInt(accounting.id), 0, ctx);
  assert.equal(deactivatedLeaf.isActive, false);
  assert.equal(deactivatedLeaf.version, 1);

  await assert.rejects(
    () =>
      departmentsService.update(
        actor,
        BigInt(accounting.id),
        { expectedVersion: 0, name: 'Stale' },
        ctx,
      ),
    ConflictException,
  );
});

test('UsersService SQL integration — Argon2id creation, password policy, department transfer role expiry & session revocation on lock/disable', async () => {
  const actor = adminPrincipal();
  const hrDept = await departmentsService.create(
    actor,
    { code: 'HR_DIV', name: 'Khối Nhân sự', parentId: hqDept.id },
    ctx,
  );

  // Rejects password containing username (MEDIUM-01 BadRequestException)
  const weakCandidate = ['nguyen.van.a', 'Strong123!'].join('@');
  const strongCandidate = ['Valid#Pass', '987!XyZ'].join('');
  await assert.rejects(
    () =>
      usersService.create(
        actor,
        {
          username: 'nguyen.van.a',
          email: 'nguyen.van.a@corp.local',
          password: weakCandidate,
          fullName: 'Nguyễn Văn A',
          departmentId: hqDept.id,
        },
        ctx,
      ),
    BadRequestException,
  );

  const created = await usersService.create(
    actor,
    {
      username: 'nguyen.van.a',
      email: 'nguyen.van.a@corp.local',
      password: strongCandidate,
      fullName: 'Nguyễn Văn A',
      departmentId: hqDept.id,
    },
    ctx,
  );
  const targetUserId = BigInt(created.id);

  // Seed a department-scoped role on HQ and an active auth_session + refresh_token
  const readerRole = await dbHarness.insertOne(
    "INSERT INTO roles(code,name,is_active,created_by) VALUES ('DOC_READER_IDENT','Reader',true,$1) RETURNING id",
    [adminUser.id],
  );
  await dbHarness.sql.query(
    "INSERT INTO user_roles(user_id,role_id,scope_department_id,valid_from,assigned_by) VALUES ($1,$2,$3,now() - interval '10 minutes',$4)",
    [targetUserId, readerRole.id, hqDept.id, adminUser.id],
  );
  const authSessId = randomUUID();
  const familyId = randomUUID();
  await dbHarness.sql.query(
    `INSERT INTO auth_sessions(id,user_id,token_family_id,status,mfa_verified_at,ip_address,expires_at)
     VALUES ($1,$2,$3,'ACTIVE',now(),'10.20.30.40',now() + interval '1 hour')`,
    [authSessId, targetUserId, familyId],
  );
  await dbHarness.sql.query(
    `INSERT INTO refresh_tokens(id,auth_session_id,token_family_id,token_hash,expires_at)
     VALUES ($1,$2,$3,$4,now() + interval '1 day')`,
    [randomUUID(), authSessId, familyId, 'f'.repeat(64)],
  );

  // Transfer user to HR_DIV -> old HQ-scoped role must expire automatically in SQL
  const transferred = await usersService.update(
    actor,
    targetUserId,
    { expectedVersion: 0, departmentId: BigInt(hrDept.id) },
    ctx,
  );
  assert.equal(transferred.departmentId, hrDept.id);
  const scopedRoleCheck = await dbHarness.sql.query(
    'SELECT valid_to FROM user_roles WHERE user_id=$1 AND scope_department_id=$2',
    [targetUserId, hqDept.id],
  );
  assert.ok(scopedRoleCheck.rows[0].valid_to !== null, 'Old department role must be expired');

  // Lock user -> active auth_sessions and refresh_tokens must be revoked in SQL
  const locked = await usersService.lock(actor, targetUserId, 1, ctx);
  assert.equal(locked.status, 'LOCKED');
  const sessionState = await dbHarness.sql.query(
    `SELECT
       (SELECT status::text FROM auth_sessions WHERE id=$1) AS sess_status,
       (SELECT revoked_at FROM refresh_tokens WHERE auth_session_id=$1) AS rt_revoked_at`,
    [authSessId],
  );
  assert.equal(sessionState.rows[0].sess_status, 'REVOKED');
  assert.ok(sessionState.rows[0].rt_revoked_at !== null);

  // Unlock -> Disable -> Block self-disable
  const unlocked = await usersService.unlock(actor, targetUserId, 2, ctx);
  assert.equal(unlocked.status, 'ACTIVE');
  const disabled = await usersService.disable(actor, targetUserId, 3, ctx);
  assert.equal(disabled.status, 'DISABLED');

  await assert.rejects(
    async () => usersService.disable(actor, adminUser.id, 0, ctx),
    ForbiddenException,
  );
});

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
let rbacService;
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
  const { RbacService } = await import('../../dist/modules/rbac/rbac.service.js');
  const { UsersService } = await import('../../dist/modules/users/users.service.js');
  const { PasswordService } = await import('../../dist/modules/auth/password.service.js');

  const cache = new AuthorizationCache();
  authorizationService = new AuthorizationService(cache);
  const audit = new RbacAuditService({
    get: () => 'integration-audit-hmac-secret-key-0123456789abcdef',
  });
  departmentsService = new DepartmentsService(authorizationService, audit, prisma);
  usersService = new UsersService(authorizationService, new PasswordService(), audit, prisma);
  rbacService = new RbacService(authorizationService, audit);
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

  // BUG-004: Scoped department admin on FIN_DIV cannot promote child to global root (parentId: null)
  const treasury = await departmentsService.create(
    actor,
    { code: 'TREASURY_TEAM', name: 'Phòng Ngân quỹ', parentId: BigInt(finance.id) },
    ctx,
  );
  const budget = await departmentsService.create(
    actor,
    { code: 'BUDGET_TEAM', name: 'Phòng Ngân sách', parentId: BigInt(finance.id) },
    ctx,
  );
  const finAdminUser = await dbHarness.insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('fin.dept.admin','fin.dept.admin@corp.local','argon2-seed','Quản trị Tài chính',$1,'ACTIVE') RETURNING id`,
    [BigInt(finance.id)],
  );
  const scopedDeptRole = await dbHarness.insertOne(
    "INSERT INTO roles(code,name,is_system_role,is_active,created_by) VALUES ('FIN_DEPT_MGR','Finance Dept Manager',false,true,$1) RETURNING id",
    [adminUser.id],
  );
  const deptManagePerm = await dbHarness.sql.query(
    "SELECT id FROM permissions WHERE resource_type='DEPARTMENT' AND action='MANAGE'",
  );
  await dbHarness.sql.query(
    'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3)',
    [scopedDeptRole.id, BigInt(deptManagePerm.rows[0].id), adminUser.id],
  );
  await dbHarness.sql.query(
    "INSERT INTO user_roles(user_id,role_id,scope_department_id,valid_from,assigned_by) VALUES ($1,$2,$3,now() - interval '1 hour',$4)",
    [finAdminUser.id, scopedDeptRole.id, BigInt(finance.id), adminUser.id],
  );
  await authorizationService.invalidateAll();
  const finScopedPrincipal = {
    userId: finAdminUser.id,
    sessionId: randomUUID(),
    username: 'fin.dept.admin',
    roles: ['FIN_DEPT_MGR'],
    mfa: true,
  };

  // Promoting child TREASURY_TEAM to global root (parentId: null) must be blocked with 403 Forbidden
  await assert.rejects(
    () =>
      departmentsService.update(
        finScopedPrincipal,
        BigInt(treasury.id),
        { expectedVersion: 0, parentId: null },
        ctx,
      ),
    ForbiddenException,
  );
  const treasuryAfterBlocked = await dbHarness.sql.query(
    'SELECT parent_id FROM departments WHERE id=$1',
    [BigInt(treasury.id)],
  );
  assert.equal(BigInt(treasuryAfterBlocked.rows[0].parent_id), BigInt(finance.id));

  // Scoped admin can still reparent TREASURY_TEAM under BUDGET_TEAM within FIN_DIV
  const reparentedInScope = await departmentsService.update(
    finScopedPrincipal,
    BigInt(treasury.id),
    { expectedVersion: 0, parentId: BigInt(budget.id) },
    ctx,
  );
  assert.equal(reparentedInScope.parentId, budget.id);

  // Scoped admin can still rename FIN_DIV while echoing unchanged parentId
  const renamedFin = await departmentsService.update(
    finScopedPrincipal,
    BigInt(finance.id),
    { expectedVersion: 0, name: 'Khối Tài chính & Đầu tư', parentId: hqDept.id },
    ctx,
  );
  assert.equal(renamedFin.name, 'Khối Tài chính & Đầu tư');
  assert.equal(renamedFin.parentId, hqDept.id.toString());

  // Global admin can legitimately promote TREASURY_TEAM to global root (parentId: null)
  const promotedByGlobal = await departmentsService.update(
    actor,
    BigInt(treasury.id),
    { expectedVersion: 1, parentId: null },
    ctx,
  );
  assert.equal(promotedByGlobal.parentId, null);
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

test('UsersService SQL integration — CLEARANCE_LEVEL assignment on create/update/PUT, SCD Type 2 history & cascading downgrade revocation', async () => {
  const actor = adminPrincipal();
  const { sql, insertOne } = dbHarness;

  const clearanceDef = await insertOne(
    `INSERT INTO attribute_definitions(code,name,scope,value_type,is_required,is_active,created_by)
     VALUES ('CLEARANCE_LEVEL','Cấp độ thẩm tra','USER','ENUM',true,true,$1) RETURNING id`,
    [adminUser.id],
  );
  const optInternal = await insertOne(
    `INSERT INTO attribute_options(attribute_definition_id,value_code,display_name,numeric_rank,sort_order,is_active)
     VALUES ($1,'INTERNAL','Nội bộ',1,1,true) RETURNING id`,
    [clearanceDef.id],
  );
  const optSecret = await insertOne(
    `INSERT INTO attribute_options(attribute_definition_id,value_code,display_name,numeric_rank,sort_order,is_active)
     VALUES ($1,'SECRET','Tối mật',3,3,true) RETURNING id`,
    [clearanceDef.id],
  );

  const optionsRes = await usersService.clearanceOptions();
  assert.deepEqual(
    optionsRes.data.map((o) => [o.code, o.rank]),
    [
      ['INTERNAL', 1],
      ['SECRET', 3],
    ],
  );

  // Create user directly with SECRET clearance
  const strongPass = ['Clearance#Pass', '2026!AbC'].join('');
  const created = await usersService.create(
    actor,
    {
      username: 'owner.clearance.sql',
      email: 'owner.clearance.sql@corp.local',
      password: strongPass,
      fullName: 'Chủ tài liệu có độ mật',
      departmentId: hqDept.id,
      clearanceOptionId: optSecret.id,
    },
    ctx,
  );
  const targetUserId = BigInt(created.id);

  const detail = await usersService.get(actor, targetUserId);
  assert.equal(detail.clearanceCode, 'SECRET');
  assert.equal(detail.clearanceRank, 3);

  const listed = await usersService.list(actor);
  const listedUser = listed.data.find((u) => u.id === created.id);
  assert.equal(listedUser.clearanceCode, 'SECRET');
  assert.equal(listedUser.clearanceRank, 3);

  // Seed a SECRET document + ACTIVE USER grant so downgrading clearance must cascade-revoke it
  const clsSecret = await insertOne(
    `INSERT INTO classification_levels(code,name,rank,allow_download,require_watermark,is_active)
     VALUES ('SECRET','Tối mật',3,false,true,true) RETURNING id`,
  );
  const cat = await insertOne(
    `INSERT INTO business_categories(code,name,department_id,is_active)
     VALUES ('CAT_CLR','Danh mục thẩm tra',$1,true) RETURNING id`,
    [hqDept.id],
  );
  const docId = randomUUID();
  await sql.query(
    `INSERT INTO documents(id,document_code,title,owner_id,department_id,status,discoverable)
     VALUES ($1,'DOC-CLR-001','Tài liệu Tối mật',$2,$3,'ACTIVE',true)`,
    [docId, adminUser.id, hqDept.id],
  );
  await sql.query(
    `INSERT INTO document_classification_history(document_id,classification_level_id,business_category_id,classified_by,effective_from,effective_to)
     VALUES ($1,$2,$3,$4,now() - interval '1 hour',NULL)`,
    [docId, clsSecret.id, cat.id, adminUser.id],
  );
  const grantId = randomUUID();
  await sql.query(
    `INSERT INTO access_grants(id,document_id,principal_type,principal_user_id,source,valid_from,valid_until,status,granted_by)
     VALUES ($1,$2,'USER',$3,'DIRECT',now() - interval '5 minutes',now() + interval '1 day','ACTIVE',$4)`,
    [grantId, docId, targetUserId, adminUser.id],
  );

  // Downgrade clearance from SECRET (3) -> INTERNAL (1) via updateClearance
  const downgraded = await usersService.updateClearance(
    actor,
    targetUserId,
    { expectedVersion: 0, clearanceOptionId: optInternal.id },
    ctx,
  );
  assert.equal(downgraded.clearanceCode, 'INTERNAL');
  assert.equal(downgraded.clearanceRank, 1);
  assert.equal(downgraded.revokedGrantsCount, 1);

  const grantAfter = await sql.query('SELECT status::text FROM access_grants WHERE id=$1', [
    grantId,
  ]);
  assert.equal(grantAfter.rows[0].status, 'REVOKED');

  // Verify SCD Type 2 closed previous row or kept exactly 1 open active row
  const openClearances = await sql.query(
    `SELECT option_id FROM user_attribute_assignments
     WHERE user_id=$1 AND attribute_definition_id=$2 AND valid_to IS NULL`,
    [targetUserId, clearanceDef.id],
  );
  assert.equal(openClearances.rows.length, 1);
  assert.equal(BigInt(openClearances.rows[0].option_id), optInternal.id);

  // Revoke clearance to null -> Rank 0
  const revoked = await usersService.updateClearance(
    actor,
    targetUserId,
    { expectedVersion: 1, clearanceOptionId: null },
    ctx,
  );
  assert.equal(revoked.clearanceCode, null);
  assert.equal(revoked.clearanceRank, 0);

  // BUG-007: Self-clearance escalation MUST be blocked with 403 Forbidden via both updateClearance and update
  await assert.rejects(
    () =>
      usersService.updateClearance(
        actor,
        adminUser.id,
        { expectedVersion: 0, clearanceOptionId: optSecret.id },
        ctx,
      ),
    ForbiddenException,
  );
  await assert.rejects(
    () =>
      usersService.update(
        actor,
        adminUser.id,
        { expectedVersion: 0, clearanceOptionId: optSecret.id },
        ctx,
      ),
    ForbiddenException,
  );
  const selfClearanceAfter = await sql.query(
    `SELECT count(*)::int AS cnt FROM user_attribute_assignments
     WHERE user_id=$1 AND attribute_definition_id=$2 AND valid_to IS NULL`,
    [adminUser.id, clearanceDef.id],
  );
  assert.equal(selfClearanceAfter.rows[0].cnt, 0);
});

test('[BUG-006] SQL integration — blocks dept USER:MANAGE manager from mutating global SYSTEM_ADMIN/SOC and enforces >= 1 ACTIVE global SYSTEM_ADMIN under concurrent cross-disable & cross-revoke', async () => {
  const { sql, insertOne } = dbHarness;
  const actor1 = adminPrincipal();

  // Grant ROLE_MANAGE to SYSTEM_ADMIN so global admins can assign/revoke roles cleanly
  const sysRoleRow = await sql.query("SELECT id FROM roles WHERE code='SYSTEM_ADMIN'");
  const sysRoleId = BigInt(sysRoleRow.rows[0].id);
  const roleManagePerm = await insertOne(
    "INSERT INTO permissions(code,name,resource_type,action) VALUES ('ROLE_MANAGE','ROLE_MANAGE','ROLE','MANAGE') RETURNING id",
  );
  await sql.query(
    'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',
    [sysRoleId, roleManagePerm.id, adminUser.id],
  );

  // Create a department-scoped USER:MANAGE manager in HQ_IDENT (same department as adminUser!)
  const hqUserMgrRole = await insertOne(
    "INSERT INTO roles(code,name,is_active,created_by) VALUES ('HQ_USER_MGR','HQ User Manager',true,$1) RETURNING id",
    [adminUser.id],
  );
  const userManagePermRow = await sql.query(
    "SELECT id FROM permissions WHERE resource_type='USER' AND action='MANAGE' LIMIT 1",
  );
  await sql.query(
    'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3)',
    [hqUserMgrRole.id, BigInt(userManagePermRow.rows[0].id), adminUser.id],
  );
  const hqMgrUser = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('hq.dept.mgr','hq.dept.mgr@corp.local','argon2-seed','Quản lý nhân sự HQ',$1,'ACTIVE') RETURNING id`,
    [hqDept.id],
  );
  await sql.query(
    "INSERT INTO user_roles(user_id,role_id,scope_department_id,valid_from,assigned_by) VALUES ($1,$2,$3,now() - interval '1 hour',$4)",
    [hqMgrUser.id, hqUserMgrRole.id, hqDept.id, adminUser.id],
  );

  // Create a SECURITY_OFFICER user in HQ_IDENT
  const socRole = await insertOne(
    "INSERT INTO roles(code,name,is_system_role,is_active,created_by) VALUES ('SECURITY_OFFICER','Security Officer',true,true,$1) RETURNING id",
    [adminUser.id],
  );
  const socUser = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('hq.soc.officer','hq.soc.officer@corp.local','argon2-seed','Cán bộ SOC',$1,'ACTIVE') RETURNING id`,
    [hqDept.id],
  );
  await sql.query(
    "INSERT INTO user_roles(user_id,role_id,scope_department_id,valid_from,assigned_by) VALUES ($1,$2,NULL,now() - interval '1 hour',$3)",
    [socUser.id, socRole.id, adminUser.id],
  );

  await authorizationService.invalidateAll();
  const hqMgrPrincipal = {
    userId: hqMgrUser.id,
    sessionId: randomUUID(),
    username: 'hq.dept.mgr',
    roles: ['HQ_USER_MGR'],
    mfa: true,
  };

  // 1. HQ_IDENT department manager MUST be blocked (403) from disabling, locking, or editing email of global SYSTEM_ADMIN or SECURITY_OFFICER
  await assert.rejects(
    () => usersService.disable(hqMgrPrincipal, adminUser.id, 0, ctx),
    ForbiddenException,
  );
  await assert.rejects(
    () => usersService.lock(hqMgrPrincipal, adminUser.id, 0, ctx),
    ForbiddenException,
  );
  await assert.rejects(
    () =>
      usersService.update(
        hqMgrPrincipal,
        adminUser.id,
        { expectedVersion: 0, email: 'hijacked@evil.local' },
        ctx,
      ),
    ForbiddenException,
  );
  await assert.rejects(
    () => usersService.disable(hqMgrPrincipal, socUser.id, 0, ctx),
    ForbiddenException,
  );
  const admin1AssignRow = await sql.query(
    'SELECT id FROM user_roles WHERE user_id=$1 AND role_id=$2 AND scope_department_id IS NULL LIMIT 1',
    [adminUser.id, sysRoleId],
  );
  const admin1AssignId = BigInt(admin1AssignRow.rows[0].id);
  await assert.rejects(
    () => rbacService.revokeUserRole(hqMgrPrincipal, adminUser.id, admin1AssignId, ctx),
    ForbiddenException,
  );

  // 2. Provision a 2nd global SYSTEM_ADMIN and verify concurrent cross-disable leaves >= 1 ACTIVE global SYSTEM_ADMIN
  const admin2User = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('sysadmin2.ident','sysadmin2.ident@corp.local','argon2-seed','Quản trị viên 2',$1,'ACTIVE') RETURNING id`,
    [hqDept.id],
  );
  const admin2Assign = await insertOne(
    "INSERT INTO user_roles(user_id,role_id,scope_department_id,valid_from,assigned_by) VALUES ($1,$2,NULL,now() - interval '1 hour',$3) RETURNING id",
    [admin2User.id, sysRoleId, adminUser.id],
  );
  await authorizationService.invalidateAll();
  const actor2 = {
    userId: admin2User.id,
    sessionId: randomUUID(),
    username: 'sysadmin2.ident',
    roles: ['SYSTEM_ADMIN'],
    mfa: true,
  };

  const crossDisable = await Promise.allSettled([
    usersService.disable(actor1, admin2User.id, 0, { ...ctx, correlationId: randomUUID() }),
    usersService.disable(actor2, adminUser.id, 0, { ...ctx, correlationId: randomUUID() }),
  ]);
  assert.equal(crossDisable.filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal(crossDisable.filter((r) => r.status === 'rejected').length, 1);
  const remainingAfterDisable = await sql.query(
    `SELECT count(DISTINCT ur.user_id)::int AS cnt
     FROM user_roles ur
     JOIN roles r ON r.id = ur.role_id
     JOIN users u ON u.id = ur.user_id
     WHERE r.code = 'SYSTEM_ADMIN' AND r.is_active = true
       AND ur.scope_department_id IS NULL
       AND ur.valid_from <= now() AND (ur.valid_to IS NULL OR ur.valid_to > now())
       AND u.status = 'ACTIVE'`,
  );
  assert.equal(remainingAfterDisable.rows[0].cnt, 1);

  // Reactivate whichever admin was disabled so both are ACTIVE again
  const adminStatuses = await sql.query(
    'SELECT id, status::text, version FROM users WHERE id IN ($1,$2)',
    [adminUser.id, admin2User.id],
  );
  const disabledAdminRow = adminStatuses.rows.find((row) => row.status === 'DISABLED');
  const activeActor = BigInt(disabledAdminRow.id) === adminUser.id ? actor2 : actor1;
  await usersService.reactivate(
    activeActor,
    BigInt(disabledAdminRow.id),
    Number(disabledAdminRow.version),
    { ...ctx, correlationId: randomUUID() },
  );
  await authorizationService.invalidateAll();

  // 3. Concurrent cross-revoke of SYSTEM_ADMIN role assignments MUST leave >= 1 ACTIVE global SYSTEM_ADMIN
  const crossRevoke = await Promise.allSettled([
    rbacService.revokeUserRole(actor1, admin2User.id, admin2Assign.id, {
      ...ctx,
      correlationId: randomUUID(),
    }),
    rbacService.revokeUserRole(actor2, adminUser.id, admin1AssignId, {
      ...ctx,
      correlationId: randomUUID(),
    }),
  ]);
  assert.equal(crossRevoke.filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal(crossRevoke.filter((r) => r.status === 'rejected').length, 1);
  const remainingAfterRevoke = await sql.query(
    `SELECT count(DISTINCT ur.user_id)::int AS cnt
     FROM user_roles ur
     JOIN roles r ON r.id = ur.role_id
     JOIN users u ON u.id = ur.user_id
     WHERE r.code = 'SYSTEM_ADMIN' AND r.is_active = true
       AND ur.scope_department_id IS NULL
       AND ur.valid_from <= now() AND (ur.valid_to IS NULL OR ur.valid_to > now())
       AND u.status = 'ACTIVE'`,
  );
  assert.equal(remainingAfterRevoke.rows[0].cnt, 1);
});

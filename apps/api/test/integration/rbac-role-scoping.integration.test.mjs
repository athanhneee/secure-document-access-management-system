import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { createRbacIntegrationHarness } from '../helpers/rbac-integration-harness.mjs';

const harness = createRbacIntegrationHarness();
const { dbHarness, state, principal } = harness;

before(async () => {
  await harness.setup();
});

after(async () => {
  await harness.teardown();
});

test('role assignment is scoped, cache is invalidated on role disable, and expired role is ineffective', async (t) => {
  if (!dbHarness.dbAvailable) {
    t.skip('Live PostgreSQL server not reachable at 127.0.0.1:5432 (run pnpm infra:up)');
    return;
  }
  await state.users.update(
    principal(),
    state.target.id,
    { expectedVersion: 0, departmentId: state.newDepartment.id },
    state.context,
  );
  const assignment = await state.rbac.assignUserRole(
    principal(),
    state.target.id,
    {
      roleId: state.delegatedRole.id,
      scopeDepartmentId: state.newDepartment.id,
      validFrom: new Date(Date.now() - 1_000),
      validTo: new Date(Date.now() + 60_000),
    },
    { ...state.context, correlationId: randomUUID() },
  );
  assert.match(assignment.id, /^\d+$/u);
  assert.equal(
    await state.authorization.hasPermission(
      { ...principal(), userId: state.target.id },
      'USER',
      'MANAGE',
      {
        targetDepartmentId: state.newDepartment.id,
      },
    ),
    true,
  );
  await state.rbac.disableRole(principal(), state.delegatedRole.id, 0, {
    ...state.context,
    correlationId: randomUUID(),
  });
  assert.equal(
    await state.authorization.hasPermission(
      { ...principal(), userId: state.target.id },
      'USER',
      'MANAGE',
      {
        targetDepartmentId: state.newDepartment.id,
      },
    ),
    false,
  );

  const expiredRole = await dbHarness.insertOne(
    "INSERT INTO roles(code,name,is_active,created_by) VALUES ('EXPIRED_TEST','Expired',true,$1) RETURNING id",
    [state.actor.id],
  );
  const permission = await dbHarness.insertOne(
    "INSERT INTO permissions(code,name,resource_type,action) VALUES ('EXPIRED_PERMISSION','Expired','EXPIRED','VIEW') RETURNING id",
  );
  await dbHarness.sql.query(
    'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3)',
    [expiredRole.id, permission.id, state.actor.id],
  );
  await dbHarness.sql.query(
    "INSERT INTO user_roles(user_id,role_id,valid_from,valid_to,assigned_by) VALUES ($1,$2,now()-interval '2 hour',now()-interval '1 hour',$3)",
    [state.target.id, expiredRole.id, state.actor.id],
  );
  state.authorization.invalidateUser(state.target.id);
  assert.equal(
    await state.authorization.hasPermission(
      { ...principal(), userId: state.target.id },
      'EXPIRED',
      'VIEW',
      {
        targetDepartmentId: state.newDepartment.id,
      },
    ),
    false,
  );
});

test('administrator cannot map a permission they do not possess', async (t) => {
  if (!dbHarness.dbAvailable) {
    t.skip('Live PostgreSQL server not reachable at 127.0.0.1:5432 (run pnpm infra:up)');
    return;
  }
  const anotherRole = await dbHarness.insertOne(
    "INSERT INTO roles(code,name,is_active,created_by) VALUES ('NO_ESCALATION_TEST','No escalation',true,$1) RETURNING id",
    [state.actor.id],
  );
  await assert.rejects(
    state.rbac.replacePermissions(principal(), anotherRole.id, [state.foreignPermission.id], {
      ...state.context,
      correlationId: randomUUID(),
    }),
    (error) => error.getStatus() === 403,
  );
  const mappings = await dbHarness.sql.query(
    'SELECT count(*)::int AS count FROM role_permissions WHERE role_id=$1',
    [anotherRole.id],
  );
  assert.equal(mappings.rows[0].count, 0);
});

test('[CRITICAL-04] bidirectional Temporal SoD blocks stacking SYSTEM_ADMIN/SECURITY_OFFICER/AUDITOR with business roles', async (t) => {
  if (!dbHarness.dbAvailable) {
    t.skip('Live PostgreSQL server not reachable at 127.0.0.1:5432 (run pnpm infra:up)');
    return;
  }
  const sysAdminRole = await dbHarness.insertOne(
    "INSERT INTO roles(code,name,is_active,created_by) VALUES ('SYSTEM_ADMIN','System Admin',true,$1) RETURNING id",
    [state.actor.id],
  );
  const docReaderRole = await dbHarness.insertOne(
    "INSERT INTO roles(code,name,is_active,created_by) VALUES ('DOCUMENT_READER','Document Reader',true,$1) RETURNING id",
    [state.actor.id],
  );
  const sodUser = await dbHarness.insertOne(
    "INSERT INTO users(username,email,password_hash,full_name,department_id,status) VALUES ('sod.user','sod@example.invalid','fixture','SoD User',$1,'ACTIVE') RETURNING id",
    [state.oldDepartment.id],
  );

  // Assign SYSTEM_ADMIN first -> succeeds
  await state.rbac.assignUserRole(
    principal(),
    sodUser.id,
    {
      roleId: sysAdminRole.id,
      scopeDepartmentId: null,
      validFrom: new Date(Date.now() - 1_000),
      validTo: new Date(Date.now() + 60_000),
    },
    { ...state.context, correlationId: randomUUID() },
  );

  // Attempting to stack DOCUMENT_READER onto SYSTEM_ADMIN must fail with 409 Conflict
  await assert.rejects(
    state.rbac.assignUserRole(
      principal(),
      sodUser.id,
      {
        roleId: docReaderRole.id,
        scopeDepartmentId: state.oldDepartment.id,
        validFrom: new Date(Date.now() - 1_000),
        validTo: new Date(Date.now() + 60_000),
      },
      { ...state.context, correlationId: randomUUID() },
    ),
    (error) => error.getStatus() === 409,
  );
});

test('[BUG-005] blocks disable -> assign conflicting role -> re-enable SoD bypass, disabled-role permission escalation, ROLE grant conflicts, delegation ceiling & revokes unverified MFA sessions on enable', async (t) => {
  if (!dbHarness.dbAvailable) {
    t.skip('Live PostgreSQL server not reachable at 127.0.0.1:5432 (run pnpm infra:up)');
    return;
  }
  const { sql, insertOne } = dbHarness;

  // Promote a dedicated global SYSTEM_ADMIN with ROLE_MANAGE + USER_MANAGE so role lifecycle ops can run cleanly
  const globalAdminUser = await insertOne(
    "INSERT INTO users(username,email,password_hash,full_name,department_id,status) VALUES ('bug005.sysadmin','bug005.sysadmin@example.invalid','fixture','Global Admin',$1,'ACTIVE') RETURNING id",
    [state.rootDepartment.id],
  );
  const sysAdminRoleRow = await sql.query("SELECT id FROM roles WHERE code='SYSTEM_ADMIN'");
  const sysAdminRoleId = BigInt(sysAdminRoleRow.rows[0].id);
  const roleManagePerm = await insertOne(
    "INSERT INTO permissions(code,name,resource_type,action) VALUES ('ROLE_MANAGE','Role manage','ROLE','MANAGE') RETURNING id",
  );
  const alertManagePerm = await insertOne(
    "INSERT INTO permissions(code,name,resource_type,action) VALUES ('ALERT_MANAGE','Alert manage','SECURITY_ALERT','MANAGE') RETURNING id",
  );
  const docUploadPerm = await insertOne(
    "INSERT INTO permissions(code,name,resource_type,action) VALUES ('DOCUMENT_UPLOAD','Document upload','DOCUMENT','UPLOAD') RETURNING id",
  );
  const userManagePermRow = await sql.query(
    "SELECT id FROM permissions WHERE resource_type='USER' AND action='MANAGE' LIMIT 1",
  );
  await sql.query(
    'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3),($1,$4,$3) ON CONFLICT DO NOTHING',
    [sysAdminRoleId, roleManagePerm.id, state.actor.id, BigInt(userManagePermRow.rows[0].id)],
  );
  await sql.query(
    "INSERT INTO user_roles(user_id,role_id,scope_department_id,valid_from,assigned_by) VALUES ($1,$2,NULL,now() - interval '1 hour',$3)",
    [globalAdminUser.id, sysAdminRoleId, state.actor.id],
  );
  // Also grant state.actor global ROLE_MANAGE (non-SYSTEM_ADMIN custom role) to verify assertCanDelegate on enableRole
  const actorRoleRow = await sql.query("SELECT id FROM roles WHERE code='RBAC_TEST_ADMIN'");
  await sql.query(
    'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',
    [BigInt(actorRoleRow.rows[0].id), roleManagePerm.id, state.actor.id],
  );
  await state.authorization.invalidateAll();

  const globalAdminPrincipal = {
    userId: globalAdminUser.id,
    sessionId: randomUUID(),
    username: 'bug005.sysadmin',
    roles: ['SYSTEM_ADMIN'],
    mfa: true,
  };

  // Create CUSTOM_SOC with ALERT_MANAGE and DOCUMENT_OWNER with DOCUMENT_UPLOAD
  const customSoc = await insertOne(
    "INSERT INTO roles(code,name,is_system_role,is_active,created_by) VALUES ('CUSTOM_SOC_BUG005','Custom SOC',false,true,$1) RETURNING id",
    [globalAdminUser.id],
  );
  await sql.query(
    'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3)',
    [customSoc.id, alertManagePerm.id, globalAdminUser.id],
  );
  const docOwnerRole = await insertOne(
    "INSERT INTO roles(code,name,is_system_role,is_active,created_by) VALUES ('DOCUMENT_OWNER','Document Owner',true,true,$1) RETURNING id",
    [globalAdminUser.id],
  );
  await sql.query(
    'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3)',
    [docOwnerRole.id, docUploadPerm.id, globalAdminUser.id],
  );
  const victimUser = await insertOne(
    "INSERT INTO users(username,email,password_hash,full_name,department_id,status) VALUES ('bug005.victim','bug005.victim@example.invalid','fixture','Victim User',$1,'ACTIVE') RETURNING id",
    [state.oldDepartment.id],
  );

  // 1. Assign CUSTOM_SOC_BUG005 to victimUser
  await state.rbac.assignUserRole(
    globalAdminPrincipal,
    victimUser.id,
    {
      roleId: customSoc.id,
      scopeDepartmentId: null,
      validFrom: new Date(Date.now() - 1_000),
      validTo: null,
    },
    { ...state.context, correlationId: randomUUID() },
  );

  // 2. Disable CUSTOM_SOC_BUG005
  await state.rbac.disableRole(globalAdminPrincipal, customSoc.id, 0, {
    ...state.context,
    correlationId: randomUUID(),
  });

  // 3. Assign DOCUMENT_OWNER while CUSTOM_SOC_BUG005 is disabled
  const docOwnerAssign = await state.rbac.assignUserRole(
    globalAdminPrincipal,
    victimUser.id,
    {
      roleId: docOwnerRole.id,
      scopeDepartmentId: state.oldDepartment.id,
      validFrom: new Date(Date.now() - 1_000),
      validTo: null,
    },
    { ...state.context, correlationId: randomUUID() },
  );

  // 4. Attempting to re-enable CUSTOM_SOC_BUG005 MUST fail with 409 Conflict (SoD violation)
  await assert.rejects(
    state.rbac.enableRole(globalAdminPrincipal, customSoc.id, 1, {
      ...state.context,
      correlationId: randomUUID(),
    }),
    (error) => error.getStatus() === 409,
  );
  const roleAfterBlockedEnable = await sql.query('SELECT is_active FROM roles WHERE id=$1', [
    customSoc.id,
  ]);
  assert.equal(roleAfterBlockedEnable.rows[0].is_active, false);

  // 5. Attempting replacePermissions on disabled CUSTOM_SOC_BUG005 with ALERT_MANAGE while victim holds DOCUMENT_OWNER MUST also fail 409 Conflict
  await assert.rejects(
    state.rbac.replacePermissions(globalAdminPrincipal, customSoc.id, [alertManagePerm.id], {
      ...state.context,
      correlationId: randomUUID(),
    }),
    (error) => error.getStatus() === 409,
  );

  // 6. Revoke DOCUMENT_OWNER from victimUser; seed clearance + classification + active USER AccessGrant (passes DB trigger while CUSTOM_SOC_BUG005 is disabled!)
  await state.rbac.revokeUserRole(globalAdminPrincipal, victimUser.id, BigInt(docOwnerAssign.id), {
    ...state.context,
    correlationId: randomUUID(),
  });
  const clearanceDef = await insertOne(
    `INSERT INTO attribute_definitions(code,name,scope,value_type,is_required,is_active,created_by)
     VALUES ('CLEARANCE_LEVEL','Clearance','USER','ENUM',true,true,$1) RETURNING id`,
    [globalAdminUser.id],
  );
  const optInternal = await insertOne(
    `INSERT INTO attribute_options(attribute_definition_id,value_code,display_name,numeric_rank,sort_order,is_active)
     VALUES ($1,'INTERNAL','Internal',1,1,true) RETURNING id`,
    [clearanceDef.id],
  );
  await sql.query(
    `INSERT INTO user_attribute_assignments(user_id,attribute_definition_id,option_id,valid_from,assigned_by)
     VALUES ($1,$2,$3,now() - interval '1 hour',$4)`,
    [victimUser.id, clearanceDef.id, optInternal.id, globalAdminUser.id],
  );
  const clsInternal = await insertOne(
    `INSERT INTO classification_levels(code,name,rank,allow_download,require_watermark,is_active)
     VALUES ('INTERNAL','Internal',1,true,false,true) RETURNING id`,
  );
  const cat = await insertOne(
    `INSERT INTO business_categories(code,name,department_id,is_active)
     VALUES ('CAT_BUG005','Category BUG005',$1,true) RETURNING id`,
    [state.oldDepartment.id],
  );
  const docId = randomUUID();
  await sql.query(
    "INSERT INTO documents(id,document_code,title,owner_id,department_id,status,discoverable) VALUES ($1,'DOC-BUG005','Confidential Doc',$2,$3,'ACTIVE',true)",
    [docId, globalAdminUser.id, state.oldDepartment.id],
  );
  await sql.query(
    `INSERT INTO document_classification_history(document_id,classification_level_id,business_category_id,classified_by,effective_from,effective_to)
     VALUES ($1,$2,$3,$4,now() - interval '1 hour',NULL)`,
    [docId, clsInternal.id, cat.id, globalAdminUser.id],
  );
  const userGrantId = randomUUID();
  await sql.query(
    "INSERT INTO access_grants(id,document_id,principal_type,principal_user_id,source,valid_from,valid_until,status,granted_by) VALUES ($1,$2,'USER',$3,'DIRECT',now() - interval '5 minutes',now() + interval '1 day','ACTIVE',$4)",
    [userGrantId, docId, victimUser.id, globalAdminUser.id],
  );

  // CONFLICT-RESOLVED: Hợp nhất BUG-005 và BUG-047 — người dùng đang đứng tên sở hữu tài liệu (`owner_id`) bị chặn 409 khi bật lại vai trò đặc quyền, còn các USER/ROLE AccessGrant đang ACTIVE được tự động thu hồi dây chuyền đầy đủ bộ ba `(revoked_by, revoked_at, revoke_reason)`.
  const ownedDocId = randomUUID();
  await sql.query(
    "INSERT INTO documents(id,document_code,title,owner_id,department_id,status,discoverable) VALUES ($1,'DOC-OWNED-BUG005','Owned Doc',$2,$3,'ACTIVE',true)",
    [ownedDocId, victimUser.id, state.oldDepartment.id],
  );
  await assert.rejects(
    state.rbac.enableRole(globalAdminPrincipal, customSoc.id, 1, {
      ...state.context,
      correlationId: randomUUID(),
    }),
    (error) => error.getStatus() === 409,
  );
  await sql.query('UPDATE documents SET owner_id=$2 WHERE id=$1', [ownedDocId, globalAdminUser.id]);

  // Verify active USER & ROLE AccessGrants are cascade-revoked (satisfying CHECK 23514) when upgrading a role to privileged ALERT_MANAGE
  const customReader = await insertOne(
    "INSERT INTO roles(code,name,is_system_role,is_active,created_by) VALUES ('CUSTOM_READER_BUG005','Custom Reader',false,true,$1) RETURNING id",
    [globalAdminUser.id],
  );
  const customReaderAssign = await state.rbac.assignUserRole(
    globalAdminPrincipal,
    victimUser.id,
    {
      roleId: customReader.id,
      scopeDepartmentId: state.oldDepartment.id,
      validFrom: new Date(Date.now() - 1_000),
      validTo: null,
    },
    { ...state.context, correlationId: randomUUID() },
  );
  const roleGrantId = randomUUID();
  await sql.query(
    "INSERT INTO access_grants(id,document_id,principal_type,principal_role_id,source,valid_from,valid_until,status,granted_by) VALUES ($1,$2,'ROLE',$3,'DIRECT',now() - interval '5 minutes',now() + interval '1 day','ACTIVE',$4)",
    [roleGrantId, docId, customReader.id, globalAdminUser.id],
  );
  await state.rbac.disableRole(globalAdminPrincipal, customReader.id, 0, {
    ...state.context,
    correlationId: randomUUID(),
  });
  await state.rbac.replacePermissions(globalAdminPrincipal, customReader.id, [alertManagePerm.id], {
    ...state.context,
    correlationId: randomUUID(),
  });

  const cascadedGrants = await sql.query(
    'SELECT id, status::text AS status, revoked_by, revoked_at, revoke_reason FROM access_grants WHERE id IN ($1,$2)',
    [userGrantId, roleGrantId],
  );
  assert.equal(cascadedGrants.rows.length, 2);
  for (const row of cascadedGrants.rows) {
    assert.equal(row.status, 'REVOKED');
    assert.ok(row.revoked_by !== null && row.revoked_at !== null && row.revoke_reason !== null);
  }

  await state.rbac.revokeUserRole(
    globalAdminPrincipal,
    victimUser.id,
    BigInt(customReaderAssign.id),
    {
      ...state.context,
      correlationId: randomUUID(),
    },
  );

  // 7. Non-SYSTEM_ADMIN custom role manager without ALERT_MANAGE MUST be blocked (403 Forbidden) from re-enabling CUSTOM_SOC_BUG005
  await assert.rejects(
    state.rbac.enableRole(principal(), customSoc.id, 1, {
      ...state.context,
      correlationId: randomUUID(),
    }),
    (error) => error.getStatus() === 403,
  );

  // 8. Seed unverified-MFA + verified-MFA sessions for victimUser, then re-enable CUSTOM_SOC_BUG005 as global SYSTEM_ADMIN
  const unverifiedSessId = randomUUID();
  const unverifiedFamilyId = randomUUID();
  const verifiedSessId = randomUUID();
  const verifiedFamilyId = randomUUID();
  await sql.query(
    `INSERT INTO auth_sessions(id,user_id,token_family_id,status,mfa_verified_at,ip_address,expires_at)
     VALUES ($1,$2,$3,'ACTIVE',NULL,'192.0.2.50',now() + interval '1 hour'),
            ($4,$2,$5,'ACTIVE',now(),'192.0.2.50',now() + interval '1 hour')`,
    [unverifiedSessId, victimUser.id, unverifiedFamilyId, verifiedSessId, verifiedFamilyId],
  );
  await sql.query(
    `INSERT INTO refresh_tokens(id,auth_session_id,token_family_id,token_hash,expires_at)
     VALUES ($1,$2,$3,$4,now() + interval '1 day')`,
    [randomUUID(), unverifiedSessId, unverifiedFamilyId, 'a'.repeat(64)],
  );

  const reenabled = await state.rbac.enableRole(globalAdminPrincipal, customSoc.id, 1, {
    ...state.context,
    correlationId: randomUUID(),
  });
  assert.equal(reenabled.isActive, true);

  // Unverified-MFA session & refresh token MUST be revoked; verified-MFA session MUST stay ACTIVE
  const sessionCheck = await sql.query(
    `SELECT
       (SELECT status::text FROM auth_sessions WHERE id=$1) AS unverified_status,
       (SELECT revocation_reason FROM auth_sessions WHERE id=$1) AS unverified_reason,
       (SELECT revoked_at FROM refresh_tokens WHERE auth_session_id=$1) AS rt_revoked_at,
       (SELECT status::text FROM auth_sessions WHERE id=$2) AS verified_status`,
    [unverifiedSessId, verifiedSessId],
  );
  assert.equal(sessionCheck.rows[0].unverified_status, 'REVOKED');
  assert.equal(sessionCheck.rows[0].unverified_reason, 'PRIVILEGED_ROLE_ASSIGNED_REQUIRES_MFA');
  assert.ok(sessionCheck.rows[0].rt_revoked_at !== null);
  assert.equal(sessionCheck.rows[0].verified_status, 'ACTIVE');
});

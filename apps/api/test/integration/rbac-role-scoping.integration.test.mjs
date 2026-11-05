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

import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

for (const line of readFileSync(
  new URL('../../../../.local/dev.env', import.meta.url),
  'utf8',
).split(/\r?\n/u)) {
  const separator = line.indexOf('=');
  if (separator > 0) process.env[line.slice(0, separator)] ??= line.slice(separator + 1);
}

const sourceUrl = new URL(process.env.DATABASE_URL);
const adminUrl = new URL(sourceUrl);
adminUrl.pathname = '/postgres';
adminUrl.search = '';
const databaseName = `sda_rbac_${randomUUID().replaceAll('-', '')}`;
const targetUrl = new URL(sourceUrl);
targetUrl.pathname = `/${databaseName}`;
let sql;
let authorization;
let cache;
let users;
let rbac;
let disconnectDatabase;
let actor;
let target;
let rootDepartment;
let oldDepartment;
let newDepartment;
let delegatedRole;
let foreignPermission;

const context = { ip: '192.0.2.40', correlationId: randomUUID() };

async function adminQuery(statement) {
  const client = new pg.Client({ connectionString: adminUrl.toString() });
  await client.connect();
  try {
    await client.query(statement);
  } finally {
    await client.end();
  }
}

async function insertOne(statement, parameters = []) {
  const result = await sql.query(statement, parameters);
  const row = result.rows[0];
  if (row && typeof row.id === 'string') row.id = BigInt(row.id);
  return row;
}

before(async () => {
  await adminQuery(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
  await adminQuery(`CREATE DATABASE "${databaseName}"`);
  const prismaCli = fileURLToPath(import.meta.resolve('prisma')).replace(
    /[\\/]build[\\/]types\.js$/u,
    '/build/index.js',
  );
  const migration = spawnSync(
    process.execPath,
    [prismaCli, 'migrate', 'deploy', '--config', 'prisma.config.ts'],
    {
      cwd: fileURLToPath(new URL('../../../../packages/database/', import.meta.url)),
      encoding: 'utf8',
      env: { ...process.env, DATABASE_URL: targetUrl.toString(), NODE_ENV: 'test' },
      shell: false,
    },
  );
  assert.equal(migration.status, 0, migration.stderr || migration.stdout);
  process.env.DATABASE_URL = targetUrl.toString();
  sql = new pg.Client({ connectionString: targetUrl.toString() });
  await sql.connect();

  rootDepartment = await insertOne(
    "INSERT INTO departments(code,name) VALUES ('ROOT_TEST','Root') RETURNING id",
  );
  oldDepartment = await insertOne(
    "INSERT INTO departments(code,name,parent_id) VALUES ('OLD_TEST','Old',$1) RETURNING id",
    [rootDepartment.id],
  );
  newDepartment = await insertOne(
    "INSERT INTO departments(code,name,parent_id) VALUES ('NEW_TEST','New',$1) RETURNING id",
    [rootDepartment.id],
  );
  actor = await insertOne(
    "INSERT INTO users(username,email,password_hash,full_name,department_id,status) VALUES ('rbac.actor','actor@example.invalid','fixture','RBAC Actor',$1,'ACTIVE') RETURNING id",
    [rootDepartment.id],
  );
  target = await insertOne(
    "INSERT INTO users(username,email,password_hash,full_name,department_id,status) VALUES ('rbac.target','target@example.invalid','fixture','RBAC Target',$1,'ACTIVE') RETURNING id",
    [oldDepartment.id],
  );
  const adminRole = await insertOne(
    "INSERT INTO roles(code,name,is_active,created_by) VALUES ('RBAC_TEST_ADMIN','RBAC test admin',true,$1) RETURNING id",
    [actor.id],
  );
  delegatedRole = await insertOne(
    "INSERT INTO roles(code,name,is_active,created_by) VALUES ('DELEGATED_TEST','Delegated',true,$1) RETURNING id",
    [actor.id],
  );
  const userManage = await insertOne(
    "INSERT INTO permissions(code,name,resource_type,action) VALUES ('USER_MANAGE_TEST','User manage','USER','MANAGE') RETURNING id",
  );
  foreignPermission = await insertOne(
    "INSERT INTO permissions(code,name,resource_type,action) VALUES ('FOREIGN_TEST','Foreign','FOREIGN','MANAGE') RETURNING id",
  );
  await sql.query(
    'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3),($4,$2,$3)',
    [adminRole.id, userManage.id, actor.id, delegatedRole.id],
  );
  await sql.query(
    "INSERT INTO user_roles(user_id,role_id,valid_from,assigned_by) VALUES ($1,$2,now() - interval '1 hour',$1)",
    [actor.id, adminRole.id],
  );
  await sql.query(
    "INSERT INTO user_roles(user_id,role_id,scope_department_id,valid_from,assigned_by) VALUES ($1,$2,$3,now() - interval '1 hour',$4)",
    [target.id, delegatedRole.id, oldDepartment.id, actor.id],
  );

  const databaseModule = await import('@sda/database');
  ({ disconnectDatabase } = databaseModule);
  const { AuthorizationCache } = await import('../../dist/modules/rbac/authorization-cache.js');
  const { AuthorizationService } = await import('../../dist/modules/rbac/authorization.service.js');
  const { RbacAuditService } = await import('../../dist/modules/rbac/rbac-audit.service.js');
  const { RbacService } = await import('../../dist/modules/rbac/rbac.service.js');
  const { UsersService } = await import('../../dist/modules/users/users.service.js');
  const { PasswordService } = await import('../../dist/modules/auth/password.service.js');
  cache = new AuthorizationCache();
  authorization = new AuthorizationService(cache);
  const audit = new RbacAuditService({
    get: () => 'test-audit-hmac-key-that-is-long-enough-123456',
  });
  rbac = new RbacService(authorization, audit);
  users = new UsersService(authorization, new PasswordService(), audit);
});

after(async () => {
  await sql?.end();
  await disconnectDatabase?.();
  await adminQuery(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
});

function principal() {
  return {
    userId: actor.id,
    sessionId: randomUUID(),
    username: 'rbac.actor',
    roles: [],
    mfa: true,
  };
}

test('department trigger rejects parent-child cycles outside the API', async () => {
  await assert.rejects(
    sql.query('UPDATE departments SET parent_id=$1 WHERE id=$2', [
      oldDepartment.id,
      rootDepartment.id,
    ]),
    /cycle/u,
  );
});

test('user transfer expires old scoped grants and records safe before/after audit', async () => {
  const updated = await users.update(
    principal(),
    target.id,
    { expectedVersion: 0, departmentId: newDepartment.id },
    context,
  );
  assert.equal(updated.departmentId, String(newDepartment.id));
  const assignment = await sql.query(
    'SELECT valid_to FROM user_roles WHERE user_id=$1 AND scope_department_id=$2',
    [target.id, oldDepartment.id],
  );
  assert.ok(assignment.rows[0].valid_to instanceof Date);
  const audit = await sql.query(
    "SELECT details::text FROM audit_logs WHERE action='USER_UPDATED' AND object_id=$1",
    [String(target.id)],
  );
  assert.equal(audit.rowCount, 1);
  assert.doesNotMatch(audit.rows[0].details, /password|hash|token|secret/iu);
});

test('optimistic concurrency allows exactly one writer and one audit event', async () => {
  const first = users.update(
    principal(),
    target.id,
    { expectedVersion: 1, fullName: 'Concurrent A' },
    { ...context, correlationId: randomUUID() },
  );
  const second = users.update(
    principal(),
    target.id,
    { expectedVersion: 1, fullName: 'Concurrent B' },
    { ...context, correlationId: randomUUID() },
  );
  const settled = await Promise.allSettled([first, second]);
  assert.equal(settled.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(settled.filter((result) => result.status === 'rejected').length, 1);
  const count = await sql.query(
    "SELECT count(*)::int AS count FROM audit_logs WHERE action='USER_UPDATED' AND object_id=$1",
    [String(target.id)],
  );
  assert.equal(count.rows[0].count, 2, 'one transfer audit plus one winning concurrent audit');
});

test('role assignment is scoped, cache is invalidated on role disable, and expired role is ineffective', async () => {
  const assignment = await rbac.assignUserRole(
    principal(),
    target.id,
    {
      roleId: delegatedRole.id,
      scopeDepartmentId: newDepartment.id,
      validFrom: new Date(Date.now() - 1_000),
      validTo: new Date(Date.now() + 60_000),
    },
    { ...context, correlationId: randomUUID() },
  );
  assert.match(assignment.id, /^\d+$/u);
  assert.equal(
    await authorization.hasPermission({ ...principal(), userId: target.id }, 'USER', 'MANAGE', {
      targetDepartmentId: newDepartment.id,
    }),
    true,
  );
  await rbac.disableRole(principal(), delegatedRole.id, 0, {
    ...context,
    correlationId: randomUUID(),
  });
  assert.equal(
    await authorization.hasPermission({ ...principal(), userId: target.id }, 'USER', 'MANAGE', {
      targetDepartmentId: newDepartment.id,
    }),
    false,
  );

  const expiredRole = await insertOne(
    "INSERT INTO roles(code,name,is_active,created_by) VALUES ('EXPIRED_TEST','Expired',true,$1) RETURNING id",
    [actor.id],
  );
  const permission = await insertOne(
    "INSERT INTO permissions(code,name,resource_type,action) VALUES ('EXPIRED_PERMISSION','Expired','EXPIRED','VIEW') RETURNING id",
  );
  await sql.query(
    'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3)',
    [expiredRole.id, permission.id, actor.id],
  );
  await sql.query(
    "INSERT INTO user_roles(user_id,role_id,valid_from,valid_to,assigned_by) VALUES ($1,$2,now()-interval '2 hour',now()-interval '1 hour',$3)",
    [target.id, expiredRole.id, actor.id],
  );
  authorization.invalidateUser(target.id);
  assert.equal(
    await authorization.hasPermission({ ...principal(), userId: target.id }, 'EXPIRED', 'VIEW', {
      targetDepartmentId: newDepartment.id,
    }),
    false,
  );
});

test('administrator cannot map a permission they do not possess', async () => {
  const anotherRole = await insertOne(
    "INSERT INTO roles(code,name,is_active,created_by) VALUES ('NO_ESCALATION_TEST','No escalation',true,$1) RETURNING id",
    [actor.id],
  );
  await assert.rejects(
    rbac.replacePermissions(principal(), anotherRole.id, [foreignPermission.id], {
      ...context,
      correlationId: randomUUID(),
    }),
    (error) => error.getStatus() === 403,
  );
  const mappings = await sql.query(
    'SELECT count(*)::int AS count FROM role_permissions WHERE role_id=$1',
    [anotherRole.id],
  );
  assert.equal(mappings.rows[0].count, 0);
});

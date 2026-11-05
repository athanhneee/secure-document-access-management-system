import { randomUUID } from 'node:crypto';
import { createEphemeralDatabaseHarness } from './postgres-integration-harness.mjs';

export function createRbacIntegrationHarness() {
  const dbHarness = createEphemeralDatabaseHarness('sda_rbac', { coerceBigIntId: true });
  const state = {
    context: { ip: '192.0.2.40', correlationId: randomUUID() },
    authorization: null,
    cache: null,
    users: null,
    rbac: null,
    actor: null,
    target: null,
    rootDepartment: null,
    oldDepartment: null,
    newDepartment: null,
    delegatedRole: null,
    foreignPermission: null,
  };

  async function setup() {
    const ready = await dbHarness.setup();
    if (!ready) return false;

    const { sql, insertOne } = dbHarness;
    state.rootDepartment = await insertOne(
      "INSERT INTO departments(code,name) VALUES ('ROOT_TEST','Root') RETURNING id",
    );
    state.oldDepartment = await insertOne(
      "INSERT INTO departments(code,name,parent_id) VALUES ('OLD_TEST','Old',$1) RETURNING id",
      [state.rootDepartment.id],
    );
    state.newDepartment = await insertOne(
      "INSERT INTO departments(code,name,parent_id) VALUES ('NEW_TEST','New',$1) RETURNING id",
      [state.rootDepartment.id],
    );
    state.actor = await insertOne(
      "INSERT INTO users(username,email,password_hash,full_name,department_id,status) VALUES ('rbac.actor','actor@example.invalid','fixture','RBAC Actor',$1,'ACTIVE') RETURNING id",
      [state.rootDepartment.id],
    );
    state.target = await insertOne(
      "INSERT INTO users(username,email,password_hash,full_name,department_id,status) VALUES ('rbac.target','target@example.invalid','fixture','RBAC Target',$1,'ACTIVE') RETURNING id",
      [state.oldDepartment.id],
    );
    const adminRole = await insertOne(
      "INSERT INTO roles(code,name,is_active,created_by) VALUES ('RBAC_TEST_ADMIN','RBAC test admin',true,$1) RETURNING id",
      [state.actor.id],
    );
    state.delegatedRole = await insertOne(
      "INSERT INTO roles(code,name,is_active,created_by) VALUES ('DELEGATED_TEST','Delegated',true,$1) RETURNING id",
      [state.actor.id],
    );
    const userManage = await insertOne(
      "INSERT INTO permissions(code,name,resource_type,action) VALUES ('USER_MANAGE_TEST','User manage','USER','MANAGE') RETURNING id",
    );
    state.foreignPermission = await insertOne(
      "INSERT INTO permissions(code,name,resource_type,action) VALUES ('FOREIGN_TEST','Foreign','FOREIGN','MANAGE') RETURNING id",
    );
    await sql.query(
      'INSERT INTO role_permissions(role_id,permission_id,granted_by) VALUES ($1,$2,$3),($4,$2,$3)',
      [adminRole.id, userManage.id, state.actor.id, state.delegatedRole.id],
    );
    await sql.query(
      "INSERT INTO user_roles(user_id,role_id,valid_from,assigned_by) VALUES ($1,$2,now() - interval '1 hour',$1)",
      [state.actor.id, adminRole.id],
    );
    await sql.query(
      "INSERT INTO user_roles(user_id,role_id,scope_department_id,valid_from,assigned_by) VALUES ($1,$2,$3,now() - interval '1 hour',$4)",
      [state.target.id, state.delegatedRole.id, state.oldDepartment.id, state.actor.id],
    );

    const { AuthorizationCache } = await import('../../dist/modules/rbac/authorization-cache.js');
    const { AuthorizationService } =
      await import('../../dist/modules/rbac/authorization.service.js');
    const { RbacAuditService } = await import('../../dist/modules/rbac/rbac-audit.service.js');
    const { RbacService } = await import('../../dist/modules/rbac/rbac.service.js');
    const { UsersService } = await import('../../dist/modules/users/users.service.js');
    const { PasswordService } = await import('../../dist/modules/auth/password.service.js');

    state.cache = new AuthorizationCache();
    state.authorization = new AuthorizationService(state.cache);
    const audit = new RbacAuditService({
      get: () => 'test-audit-hmac-key-that-is-long-enough-123456',
    });
    state.rbac = new RbacService(state.authorization, audit);
    state.users = new UsersService(state.authorization, new PasswordService(), audit);
    return true;
  }

  function principal() {
    return {
      userId: state.actor.id,
      sessionId: randomUUID(),
      username: 'rbac.actor',
      roles: [],
      mfa: true,
    };
  }

  return {
    dbHarness,
    state,
    setup,
    teardown: () => dbHarness.teardown(),
    principal,
  };
}

import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import pg from 'pg';
import {
  businessTableCount,
  businessTableNames,
  databaseUrl,
  dropDatabase,
  expectedTables,
  isDatabaseReachable,
  recreateDatabase,
  runPrisma,
} from './helpers/migration-test-harness.mjs';

test('Prisma migration deploy, idempotent seed, and ABAC version triggers are valid', async (t) => {
  if (!(await isDatabaseReachable())) {
    t.skip('Live PostgreSQL server not reachable at 127.0.0.1:5432 (run pnpm infra:up)');
    return;
  }
  const dbName = `sda_migration_${randomUUID().replaceAll('-', '')}`;
  await recreateDatabase(dbName);

  let database;
  t.after(async () => {
    if (database) await database.end();
    await dropDatabase(dbName);
  });

  const targetUrl = databaseUrl(dbName);
  database = new pg.Client({ connectionString: targetUrl });
  await database.connect();

  const serverVersion = await database.query(
    "SELECT current_setting('server_version_num')::int AS version",
  );
  assert.ok(
    serverVersion.rows[0].version >= 180000 && serverVersion.rows[0].version < 190000,
    'migration acceptance requires PostgreSQL 18',
  );

  assert.equal(await businessTableCount(database), 0, 'migration test must start empty');
  runPrisma(['migrate', 'deploy'], targetUrl);
  assert.deepEqual(await businessTableNames(database), expectedTables);

  const migrationCount = await database.query(
    'SELECT count(*)::int AS count FROM _prisma_migrations WHERE finished_at IS NOT NULL',
  );
  assert.equal(migrationCount.rows[0].count, 12);

  const abacEvolution = await database.query(
    `SELECT table_name,column_name FROM information_schema.columns
     WHERE table_schema='public'
       AND ((table_name='attribute_definitions' AND column_name='version')
         OR (table_name='policy_rules' AND column_name IN ('version','obligations')))
     ORDER BY table_name,column_name`,
  );
  assert.deepEqual(abacEvolution.rows, [
    { table_name: 'attribute_definitions', column_name: 'version' },
    { table_name: 'policy_rules', column_name: 'obligations' },
    { table_name: 'policy_rules', column_name: 'version' },
  ]);

  const enums = await database.query(
    "SELECT count(*)::int AS count FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' AND t.typtype='e'",
  );
  assert.equal(enums.rows[0].count, 18);

  const nativeFeatures = await database.query(
    "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname='public' AND indexname IN ('uq_document_current_classification','idx_audit_details_gin','uq_audit_chain_position')",
  );
  assert.equal(nativeFeatures.rows.length, 3);
  assert.match(
    nativeFeatures.rows.find((row) => row.indexname === 'uq_document_current_classification')
      .indexdef,
    /UNIQUE.*WHERE \(effective_to IS NULL\)/u,
  );
  assert.match(
    nativeFeatures.rows.find((row) => row.indexname === 'idx_audit_details_gin').indexdef,
    /USING gin/u,
  );

  const circularForeignKeys = await database.query(`
    SELECT conname, confdeltype
    FROM pg_constraint
    WHERE contype='f' AND conname IN ('fk_documents_current_version','document_versions_document_id_fkey')
    ORDER BY conname
  `);
  assert.deepEqual(circularForeignKeys.rows, [
    { conname: 'document_versions_document_id_fkey', confdeltype: 'r' },
    { conname: 'fk_documents_current_version', confdeltype: 'r' },
  ]);

  runPrisma(['db', 'seed'], targetUrl);
  const authColumns = await database.query(
    "SELECT table_name,column_name FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('auth_sessions','refresh_tokens','mfa_methods','password_reset_tokens') ORDER BY table_name,column_name",
  );
  assert.ok(
    authColumns.rows.some(
      (row) => row.table_name === 'refresh_tokens' && row.column_name === 'token_hash',
    ),
  );
  assert.equal(
    authColumns.rows.some((row) => row.column_name === 'token'),
    false,
  );

  const authUser = await database.query("SELECT id FROM users WHERE username='reader.demo'");
  const authSessionId = randomUUID();
  const tokenFamilyId = randomUUID();
  await database.query(
    `INSERT INTO auth_sessions(id,user_id,token_family_id,expires_at)
     VALUES ($1,$2,$3,now()+interval '1 hour')`,
    [authSessionId, authUser.rows[0].id, tokenFamilyId],
  );
  await assert.rejects(
    database.query(
      `INSERT INTO refresh_tokens(id,auth_session_id,token_family_id,token_hash,expires_at)
       VALUES ($1,$2,$3,$4,now()+interval '1 hour')`,
      [randomUUID(), authSessionId, randomUUID(), 'a'.repeat(64)],
    ),
    /family does not match/u,
  );
  await assert.rejects(
    database.query(
      `INSERT INTO refresh_tokens(id,auth_session_id,token_family_id,token_hash,expires_at)
       VALUES ($1,$2,$3,'plaintext-token',now()+interval '1 hour')`,
      [randomUUID(), authSessionId, tokenFamilyId],
    ),
    { code: '23514' },
  );

  const seededOnce = await database.query(`
    SELECT
      (SELECT count(*)::int FROM classification_levels) AS classifications,
      (SELECT count(*)::int FROM roles WHERE is_system_role) AS roles,
      (SELECT count(*)::int FROM permissions) AS permissions,
      (SELECT count(*)::int FROM attribute_definitions) AS attribute_definitions,
      (SELECT count(*)::int FROM attribute_options ao JOIN attribute_definitions ad ON ad.id=ao.attribute_definition_id WHERE ad.code='CLEARANCE_LEVEL') AS clearance_options,
      (SELECT count(*)::int FROM attribute_options ao JOIN attribute_definitions ad ON ad.id=ao.attribute_definition_id WHERE ad.code='EMPLOYMENT_STATUS') AS employment_status_options,
      (SELECT count(*)::int FROM departments) AS departments,
      (SELECT count(*)::int FROM business_categories) AS categories,
      (SELECT count(*)::int FROM users) AS users
  `);
  // CONFLICT-RESOLVED: Đồng bộ bộ đếm kiểm thử tích hợp với 34 quyền RBAC hạt nhân và lọc tường minh các tập tùy chọn CLEARANCE_LEVEL (4) + EMPLOYMENT_STATUS (3).
  assert.deepEqual(seededOnce.rows[0], {
    classifications: 4,
    roles: 5,
    permissions: 34,
    attribute_definitions: 15,
    clearance_options: 4,
    employment_status_options: 3,
    departments: 2,
    categories: 2,
    users: 6,
  });
  runPrisma(['db', 'seed'], targetUrl);
  const seededTwice = await database.query(`
    SELECT
      (SELECT count(*)::int FROM classification_levels) AS classifications,
      (SELECT count(*)::int FROM roles WHERE is_system_role) AS roles,
      (SELECT count(*)::int FROM permissions) AS permissions,
      (SELECT count(*)::int FROM attribute_definitions) AS attribute_definitions,
      (SELECT count(*)::int FROM attribute_options ao JOIN attribute_definitions ad ON ad.id=ao.attribute_definition_id WHERE ad.code='CLEARANCE_LEVEL') AS clearance_options,
      (SELECT count(*)::int FROM attribute_options ao JOIN attribute_definitions ad ON ad.id=ao.attribute_definition_id WHERE ad.code='EMPLOYMENT_STATUS') AS employment_status_options,
      (SELECT count(*)::int FROM departments) AS departments,
      (SELECT count(*)::int FROM business_categories) AS categories,
      (SELECT count(*)::int FROM users) AS users
  `);
  assert.deepEqual(seededTwice.rows[0], seededOnce.rows[0]);

  const clearanceVersion = await database.query(
    "SELECT id,version FROM attribute_definitions WHERE code='CLEARANCE_LEVEL'",
  );
  await database.query(
    "UPDATE attribute_definitions SET description='version trigger fixture' WHERE id=$1",
    [clearanceVersion.rows[0].id],
  );
  const definitionAfter = await database.query(
    'SELECT version FROM attribute_definitions WHERE id=$1',
    [clearanceVersion.rows[0].id],
  );
  assert.ok(BigInt(definitionAfter.rows[0].version) > BigInt(clearanceVersion.rows[0].version));
  await database.query(
    "UPDATE attribute_options SET display_name=display_name || ' updated' WHERE attribute_definition_id=$1 AND value_code='INTERNAL'",
    [clearanceVersion.rows[0].id],
  );
  const optionAfter = await database.query(
    'SELECT version FROM attribute_definitions WHERE id=$1',
    [clearanceVersion.rows[0].id],
  );
  assert.ok(BigInt(optionAfter.rows[0].version) > BigInt(definitionAfter.rows[0].version));

  const policyVersion = await database.query(
    `INSERT INTO policy_rules(code,name,effect,created_by,obligations)
     VALUES ('VERSION_TRIGGER_TEST','Version trigger','DENY',(SELECT id FROM users WHERE username='system.seed'),'["NO_CACHE"]')
     RETURNING id,version`,
  );
  await database.query(
    `INSERT INTO policy_rule_conditions(policy_rule_id,context_key,operator,expected_value)
     VALUES ($1,'environment.mfa','EQ','true')`,
    [policyVersion.rows[0].id],
  );
  const conditionAfter = await database.query('SELECT version FROM policy_rules WHERE id=$1', [
    policyVersion.rows[0].id,
  ]);
  assert.ok(BigInt(conditionAfter.rows[0].version) > BigInt(policyVersion.rows[0].version));
  await database.query('UPDATE policy_rules SET version=1 WHERE id=$1', [policyVersion.rows[0].id]);
  const tamperAfter = await database.query('SELECT version FROM policy_rules WHERE id=$1', [
    policyVersion.rows[0].id,
  ]);
  assert.ok(BigInt(tamperAfter.rows[0].version) > BigInt(conditionAfter.rows[0].version));
  await assert.rejects(
    database.query(`UPDATE policy_rules SET obligations='{"type":"NO_CACHE"}' WHERE id=$1`, [
      policyVersion.rows[0].id,
    ]),
    { code: '23514' },
  );
});

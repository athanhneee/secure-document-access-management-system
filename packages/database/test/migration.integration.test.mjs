import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { config as loadEnvironment } from 'dotenv';
import pg from 'pg';

loadEnvironment({ path: new URL('../../../.local/dev.env', import.meta.url), quiet: true });

const sourceUrl = new URL(process.env['DATABASE_URL']);
const adminUrl = new URL(sourceUrl);
adminUrl.pathname = '/postgres';
adminUrl.search = '';
const databaseNames = [
  `sda_migration_${randomUUID().replaceAll('-', '')}`,
  `sda_rollback_${randomUUID().replaceAll('-', '')}`,
];
const migrationUrl = new URL(
  '../prisma/migrations/20260917160000_initial_secure_schema/migration.sql',
  import.meta.url,
);
const rollbackUrl = new URL(
  '../prisma/migrations/20260917160000_initial_secure_schema/rollback.sql',
  import.meta.url,
);
const authMigrationUrl = new URL(
  '../prisma/migrations/20260919120000_hardened_authentication/migration.sql',
  import.meta.url,
);
const authRollbackUrl = new URL(
  '../prisma/migrations/20260919120000_hardened_authentication/rollback.sql',
  import.meta.url,
);
const rbacMigrationUrl = new URL(
  '../prisma/migrations/20260919180000_scoped_rbac_administration/migration.sql',
  import.meta.url,
);
const rbacRollbackUrl = new URL(
  '../prisma/migrations/20260919180000_scoped_rbac_administration/rollback.sql',
  import.meta.url,
);
const abacMigrationUrl = new URL(
  '../prisma/migrations/20260922120000_deterministic_abac/migration.sql',
  import.meta.url,
);
const abacRollbackUrl = new URL(
  '../prisma/migrations/20260922120000_deterministic_abac/rollback.sql',
  import.meta.url,
);
const expectedTables = [
  'access_grant_permissions',
  'access_grants',
  'access_request_decisions',
  'access_request_permissions',
  'access_requests',
  'access_sessions',
  'alert_audit_links',
  'attribute_definitions',
  'attribute_options',
  'audit_logs',
  'auth_sessions',
  'business_categories',
  'classification_levels',
  'departments',
  'document_classification_history',
  'document_versions',
  'documents',
  'incident_actions',
  'incident_reports',
  'mfa_methods',
  'notifications',
  'password_reset_tokens',
  'permissions',
  'policy_rule_conditions',
  'policy_rules',
  'refresh_tokens',
  'role_permissions',
  'roles',
  'security_alerts',
  'system_health_snapshots',
  'user_attribute_assignments',
  'user_roles',
  'users',
  'watermark_configs',
  'watermark_instances',
];

function databaseUrl(name) {
  const url = new URL(sourceUrl);
  url.pathname = `/${name}`;
  return url.toString();
}

async function adminQuery(sql) {
  const client = new pg.Client({ connectionString: adminUrl.toString() });
  await client.connect();
  try {
    return await client.query(sql);
  } finally {
    await client.end();
  }
}

async function recreateDatabase(name) {
  assert.match(name, /^sda_(?:migration|rollback)_[a-f0-9]{32}$/u);
  await adminQuery(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
  await adminQuery(`CREATE DATABASE "${name}"`);
}

async function dropDatabase(name) {
  assert.match(name, /^sda_(?:migration|rollback)_[a-f0-9]{32}$/u);
  await adminQuery(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
}

function runPrisma(args, targetUrl) {
  const prismaCli = fileURLToPath(import.meta.resolve('prisma')).replace(
    /[\\/]build[\\/]types\.js$/u,
    '/build/index.js',
  );
  const result = spawnSync(process.execPath, [prismaCli, ...args, '--config', 'prisma.config.ts'], {
    cwd: fileURLToPath(new URL('../', import.meta.url)),
    encoding: 'utf8',
    env: { ...process.env, DATABASE_URL: targetUrl, NODE_ENV: 'test' },
    shell: false,
  });
  if (result.error) throw result.error;
  assert.equal(
    result.status,
    0,
    [result.stdout, result.stderr].filter(Boolean).join('\n').replaceAll(targetUrl, '[REDACTED]'),
  );
}

async function businessTableCount(client) {
  const result = await client.query(
    "SELECT count(*)::int AS count FROM pg_tables WHERE schemaname='public' AND tablename <> '_prisma_migrations'",
  );
  return result.rows[0].count;
}

async function businessTableNames(client) {
  const result = await client.query(
    "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> '_prisma_migrations' ORDER BY tablename",
  );
  return result.rows.map((row) => row.tablename);
}

test('Prisma migration, idempotent seed, constraints, and initial rollback are valid', async (t) => {
  for (const name of databaseNames) await recreateDatabase(name);
  let database;
  t.after(async () => {
    if (database) await database.end();
    for (const name of databaseNames) await dropDatabase(name);
  });

  const targetUrl = databaseUrl(databaseNames[0]);
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
  assert.equal(migrationCount.rows[0].count, 4);

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
      (SELECT count(*)::int FROM departments) AS departments,
      (SELECT count(*)::int FROM business_categories) AS categories,
      (SELECT count(*)::int FROM users) AS users
  `);
  assert.deepEqual(seededOnce.rows[0], {
    classifications: 4,
    roles: 5,
    permissions: 32,
    attribute_definitions: 15,
    clearance_options: 4,
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
      (SELECT count(*)::int FROM attribute_options) AS clearance_options,
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

  const fixture = await database.query(`
    SELECT
      (SELECT id FROM users WHERE username='owner.demo') AS owner_id,
      (SELECT id FROM users WHERE username='reader.demo') AS reader_id,
      (SELECT id FROM departments WHERE code='HEAD_OFFICE') AS department_id,
      (SELECT id FROM classification_levels WHERE code='TOP_SECRET') AS classification_id,
      (SELECT id FROM business_categories WHERE code='GENERAL_OPERATIONS') AS category_id
  `);
  const { owner_id, reader_id, department_id, classification_id, category_id } = fixture.rows[0];
  const firstDocumentId = randomUUID();
  const secondDocumentId = randomUUID();
  await database.query(
    'INSERT INTO documents(id, document_code, title, owner_id, department_id) VALUES ($1,$2,$3,$4,$5),($6,$7,$8,$4,$5)',
    [
      firstDocumentId,
      'DOC-MIGRATION-001',
      'Migration fixture one',
      owner_id,
      department_id,
      secondDocumentId,
      'DOC-MIGRATION-002',
      'Migration fixture two',
    ],
  );
  const version = await database.query(
    `INSERT INTO document_versions(document_id,version_no,original_filename,storage_key,mime_type,file_size_bytes,sha256_hash,encryption_key_ref,scan_status,uploaded_by)
     VALUES ($1,1,'fixture.pdf','fixture/one','application/pdf',128,$2,'local-test-key','CLEAN',$3) RETURNING id`,
    [firstDocumentId, 'a'.repeat(64), owner_id],
  );
  await database.query('UPDATE documents SET current_version_id=$1 WHERE id=$2', [
    version.rows[0].id,
    firstDocumentId,
  ]);
  await assert.rejects(
    database.query('UPDATE documents SET current_version_id=$1 WHERE id=$2', [
      version.rows[0].id,
      secondDocumentId,
    ]),
    /current_version_id does not belong to document/u,
  );

  await database.query(
    `INSERT INTO document_classification_history(document_id,classification_level_id,business_category_id,classified_by)
     VALUES ($1,$2,$3,$4)`,
    [firstDocumentId, classification_id, category_id, owner_id],
  );
  await assert.rejects(
    database.query(
      `INSERT INTO document_classification_history(document_id,classification_level_id,business_category_id,classified_by)
       VALUES ($1,$2,$3,$4)`,
      [firstDocumentId, classification_id, category_id, owner_id],
    ),
    (error) => error.code === '23505',
  );

  await assert.rejects(
    database.query(
      `INSERT INTO access_grants(id,document_id,principal_type,principal_user_id,source,valid_from,valid_until,granted_by)
       VALUES ($1,$2,'USER',$3,'DIRECT',now(),now()+interval '1 day',$4)`,
      [randomUUID(), firstDocumentId, reader_id, owner_id],
    ),
    /Clearance level is insufficient/u,
  );

  const accessRequestId = randomUUID();
  await database.query(
    `INSERT INTO access_requests(id,document_id,requester_id,reason,requested_from,requested_until)
     VALUES ($1,$2,$3,'Need controlled access for migration testing',now(),now()+interval '1 day')`,
    [accessRequestId, firstDocumentId, reader_id],
  );
  await database.query(
    `UPDATE attribute_options ao
     SET numeric_rank=4
     FROM user_attribute_assignments uaa, attribute_definitions ad
     WHERE uaa.option_id=ao.id AND uaa.attribute_definition_id=ad.id
       AND uaa.user_id=$1 AND uaa.valid_to IS NULL AND ad.code='CLEARANCE_LEVEL'`,
    [reader_id],
  );
  const accessGrantId = randomUUID();
  await database.query(
    `INSERT INTO access_grants(id,document_id,principal_type,principal_user_id,source,valid_from,valid_until,granted_by)
     VALUES ($1,$2,'USER',$3,'DIRECT',now(),now()+interval '1 day',$4)`,
    [accessGrantId, firstDocumentId, reader_id, owner_id],
  );

  for (const [table, id] of [
    ['documents', firstDocumentId],
    ['access_requests', accessRequestId],
    ['access_grants', accessGrantId],
  ]) {
    const winner = await database.query(
      `UPDATE ${table} SET version=version+1 WHERE id=$1 AND version=0 RETURNING version`,
      [id],
    );
    const staleWriter = await database.query(
      `UPDATE ${table} SET version=version+1 WHERE id=$1 AND version=0 RETURNING version`,
      [id],
    );
    assert.equal(winner.rows[0].version, 1, `${table} winning write increments version`);
    assert.equal(staleWriter.rowCount, 0, `${table} rejects a stale expected version`);
  }

  const audit = await database.query(
    `INSERT INTO audit_logs(actor_username,action,object_type,outcome,correlation_id,entry_hash,chain_partition,chain_sequence)
     VALUES ('migration-test','TEST','DATABASE','SUCCESS',$1,$2,'integration',1) RETURNING id`,
    [randomUUID(), 'b'.repeat(64)],
  );
  await assert.rejects(
    database.query('UPDATE audit_logs SET reason_code=$1 WHERE id=$2', [
      'MUTATION',
      audit.rows[0].id,
    ]),
    /append-only/u,
  );
  await assert.rejects(
    database.query('DELETE FROM audit_logs WHERE id=$1', [audit.rows[0].id]),
    /append-only/u,
  );
  await assert.rejects(
    database.query(
      `INSERT INTO audit_logs(actor_username,action,object_type,outcome,correlation_id,previous_hash,entry_hash,chain_partition,chain_sequence)
       VALUES ('migration-test','TEST','DATABASE','SUCCESS',$1,$2,$3,'integration',2)`,
      [randomUUID(), 'c'.repeat(64), 'd'.repeat(64)],
    ),
    /previous_hash mismatch/u,
  );

  const rollbackDatabase = new pg.Client({ connectionString: databaseUrl(databaseNames[1]) });
  await rollbackDatabase.connect();
  try {
    await rollbackDatabase.query(await readFile(migrationUrl, 'utf8'));
    assert.equal(await businessTableCount(rollbackDatabase), 31);
    await rollbackDatabase.query(await readFile(authMigrationUrl, 'utf8'));
    assert.equal(await businessTableCount(rollbackDatabase), 35);
    await rollbackDatabase.query(await readFile(rbacMigrationUrl, 'utf8'));
    await rollbackDatabase.query(await readFile(abacMigrationUrl, 'utf8'));
    assert.equal(await businessTableCount(rollbackDatabase), 35);
    await rollbackDatabase.query(await readFile(abacRollbackUrl, 'utf8'));
    await rollbackDatabase.query(await readFile(rbacRollbackUrl, 'utf8'));
    await rollbackDatabase.query(await readFile(authRollbackUrl, 'utf8'));
    assert.equal(await businessTableCount(rollbackDatabase), 31);
    await rollbackDatabase.query(await readFile(rollbackUrl, 'utf8'));
    assert.equal(await businessTableCount(rollbackDatabase), 0);
    const remainingEnums = await rollbackDatabase.query(
      "SELECT count(*)::int AS count FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' AND t.typtype='e'",
    );
    assert.equal(remainingEnums.rows[0].count, 0);
  } finally {
    await rollbackDatabase.end();
  }
});

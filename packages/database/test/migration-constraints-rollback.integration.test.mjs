import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import pg from 'pg';
import {
  businessTableCount,
  databaseUrl,
  dropDatabase,
  isDatabaseReachable,
  recreateDatabase,
  runPrisma,
} from './helpers/migration-test-harness.mjs';

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

test('Database domain constraints, OCC, append-only audit triggers, and SQL rollbacks hold', async (t) => {
  if (!(await isDatabaseReachable())) {
    t.skip('Live PostgreSQL server not reachable at 127.0.0.1:5432 (run pnpm infra:up)');
    return;
  }
  const databaseNames = [
    `sda_migration_${randomUUID().replaceAll('-', '')}`,
    `sda_rollback_${randomUUID().replaceAll('-', '')}`,
  ];
  for (const name of databaseNames) await recreateDatabase(name);

  let database;
  t.after(async () => {
    if (database) await database.end();
    for (const name of databaseNames) await dropDatabase(name);
  });

  const targetUrl = databaseUrl(databaseNames[0]);
  database = new pg.Client({ connectionString: targetUrl });
  await database.connect();

  runPrisma(['migrate', 'deploy'], targetUrl);
  runPrisma(['db', 'seed'], targetUrl);

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

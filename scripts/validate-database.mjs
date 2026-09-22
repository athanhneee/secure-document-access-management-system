import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { PGlite } from '@electric-sql/pglite';

const schemaUrl = new URL('../docs/reference/database_secure_document_system.sql', import.meta.url);

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
  'business_categories',
  'classification_levels',
  'departments',
  'document_classification_history',
  'document_versions',
  'documents',
  'incident_actions',
  'incident_reports',
  'notifications',
  'permissions',
  'policy_rule_conditions',
  'policy_rules',
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

/** Execute the unchanged reference SQL against a new, ephemeral PostgreSQL WASM instance. */
export async function validateDatabaseBaseline() {
  const database = await PGlite.create('memory://');
  const checks = [];
  try {
    const before = await database.query(
      "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
    );
    assert.equal(before.rows.length, 0, 'Validation must begin with an empty schema');
    await database.exec(await readFile(schemaUrl, 'utf8'));
    const tables = await database.query(
      "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
    );
    assert.deepEqual(
      tables.rows.map((row) => row.tablename),
      expectedTables,
    );
    checks.push('original SQL creates exactly the 31 named business tables');

    const enums = await database.query(
      "SELECT count(*)::int AS count FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' AND t.typtype='e'",
    );
    assert.equal(enums.rows[0].count, 16);
    const indexes = await database.query(
      "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname='public' AND indexname IN ('uq_document_current_classification','idx_audit_details_gin') ORDER BY indexname",
    );
    assert.equal(indexes.rows.length, 2);
    assert.match(indexes.rows[0].indexdef, /USING gin \(details\)/);
    assert.match(indexes.rows[1].indexdef, /UNIQUE.*WHERE \(effective_to IS NULL\)/);
    const foreignKey = await database.query(
      "SELECT conname FROM pg_constraint WHERE conname='fk_documents_current_version' AND contype='f'",
    );
    assert.equal(foreignKey.rows.length, 1);
    const triggers = await database.query(
      'SELECT tgname FROM pg_trigger WHERE NOT tgisinternal ORDER BY tgname',
    );
    assert.equal(triggers.rows.length, 11);
    for (const required of [
      'trg_audit_no_update',
      'trg_validate_current_document_version',
      'trg_validate_user_clearance_for_grant',
      'trg_users_updated',
    ]) {
      assert.ok(
        triggers.rows.some((row) => row.tgname === required),
        required,
      );
    }
    checks.push('enum types, partial unique/GIN indexes, circular FK and triggers exist');

    const audit = await database.query(
      `INSERT INTO audit_logs (actor_username, action, object_type, outcome, correlation_id, entry_hash)
       VALUES ($1, 'BASELINE_VALIDATION', 'TEST', 'SUCCESS', $2, $3) RETURNING id`,
      ['schema-validation-fixture', '10000000-0000-4000-8000-000000000001', '0'.repeat(64)],
    );
    const auditId = audit.rows[0].id;
    await assert.rejects(
      database.query("UPDATE audit_logs SET outcome='FAILED' WHERE id=$1", [auditId]),
      /audit_logs is append-only/,
    );
    await assert.rejects(
      database.query('DELETE FROM audit_logs WHERE id=$1', [auditId]),
      /audit_logs is append-only/,
    );
    const auditAfter = await database.query('SELECT outcome FROM audit_logs WHERE id=$1', [
      auditId,
    ]);
    assert.equal(auditAfter.rows[0].outcome, 'SUCCESS');
    checks.push('audit update/delete rejected and original row preserved');

    await assert.rejects(
      database.transaction(async (transaction) => {
        await transaction.query(
          "INSERT INTO departments (code,name) VALUES ('ROLLBACK_TEST','Rollback test')",
        );
        await transaction.query(
          "INSERT INTO system_health_snapshots (service_name,status,response_time_ms) VALUES ('test','HEALTHY',-1)",
        );
      }),
      { code: '23514' },
    );
    const rolledBack = await database.query(
      "SELECT id FROM departments WHERE code='ROLLBACK_TEST'",
    );
    assert.equal(rolledBack.rows.length, 0);
    checks.push('check constraint failure rolls back the entire transaction');

    // Synthetic records exist only in this ephemeral database; no usable credentials are created.
    const department = await database.query(
      "INSERT INTO departments (code,name) VALUES ('VALIDATION','Validation') RETURNING id",
    );
    const departmentId = department.rows[0].id;
    const user = await database.query(
      `INSERT INTO users (username,email,password_hash,full_name,department_id)
       VALUES ('schema-fixture','schema-fixture@example.invalid',$1,'Schema fixture',$2) RETURNING id`,
      ['not-an-authentication-hash', departmentId],
    );
    const userId = user.rows[0].id;
    const firstDocumentId = '20000000-0000-4000-8000-000000000001';
    const secondDocumentId = '20000000-0000-4000-8000-000000000002';
    for (const [id, code] of [
      [firstDocumentId, 'VALIDATION_A'],
      [secondDocumentId, 'VALIDATION_B'],
    ]) {
      await database.query(
        'INSERT INTO documents (id,document_code,title,owner_id,department_id) VALUES ($1,$2,$3,$4,$5)',
        [id, code, 'Synthetic schema validation', userId, departmentId],
      );
    }
    const version = await database.query(
      `INSERT INTO document_versions
       (document_id,version_no,original_filename,storage_key,mime_type,file_size_bytes,sha256_hash,encryption_key_ref,uploaded_by)
       VALUES ($1,1,'fixture.txt','validation/fixture','text/plain',1,$2,'nonexistent-fixture-reference',$3) RETURNING id`,
      [firstDocumentId, '1'.repeat(64), userId],
    );
    const versionId = version.rows[0].id;
    await database.query('UPDATE documents SET current_version_id=$1 WHERE id=$2', [
      versionId,
      firstDocumentId,
    ]);
    await assert.rejects(
      database.query('UPDATE documents SET current_version_id=$1 WHERE id=$2', [
        versionId,
        secondDocumentId,
      ]),
      /current_version_id does not belong to document/,
    );
    checks.push('current version accepts own document and rejects another document');

    const classification = await database.query(
      "INSERT INTO classification_levels (code,name,rank) VALUES ('VALIDATION_HIGH','Validation high',2) RETURNING id",
    );
    const category = await database.query(
      "INSERT INTO business_categories (code,name) VALUES ('VALIDATION','Validation') RETURNING id",
    );
    const classificationParameters = [
      firstDocumentId,
      classification.rows[0].id,
      category.rows[0].id,
      userId,
    ];
    const classificationSql = `INSERT INTO document_classification_history
      (document_id,classification_level_id,business_category_id,classified_by) VALUES ($1,$2,$3,$4)`;
    await database.query(classificationSql, classificationParameters);
    await assert.rejects(database.query(classificationSql, classificationParameters), {
      code: '23505',
    });
    checks.push('a document cannot have two current classifications');

    const definition = await database.query(
      "INSERT INTO attribute_definitions (code,name,scope,value_type) VALUES ('CLEARANCE_LEVEL','Clearance','USER','ENUM') RETURNING id",
    );
    const option = await database.query(
      "INSERT INTO attribute_options (attribute_definition_id,value_code,display_name,numeric_rank) VALUES ($1,'LOW','Low',1) RETURNING id",
      [definition.rows[0].id],
    );
    await database.query(
      'INSERT INTO user_attribute_assignments (user_id,attribute_definition_id,option_id,assigned_by) VALUES ($1,$2,$3,$1)',
      [userId, definition.rows[0].id, option.rows[0].id],
    );
    const grantSql = `INSERT INTO access_grants
      (id,document_id,principal_type,principal_user_id,source,valid_from,valid_until,granted_by)
      VALUES ($1,$2,'USER',$3,'DIRECT',now(),now()+interval '1 hour',$3)`;
    const grantParameters = ['30000000-0000-4000-8000-000000000001', firstDocumentId, userId];
    await assert.rejects(
      database.query(grantSql, grantParameters),
      /Clearance level is insufficient/,
    );
    await database.query('UPDATE attribute_options SET numeric_rank=2 WHERE id=$1', [
      option.rows[0].id,
    ]);
    await database.query(grantSql, grantParameters);
    checks.push('insufficient clearance denied; sufficient clearance accepted');

    await database.query(
      "UPDATE departments SET name='Changed',updated_at='2000-01-01T00:00:00Z' WHERE id=$1",
      [departmentId],
    );
    const updated = await database.query(
      "SELECT updated_at > '2000-01-02T00:00:00Z' AS refreshed FROM departments WHERE id=$1",
      [departmentId],
    );
    assert.equal(updated.rows[0].refreshed, true);
    checks.push('updated_at trigger overrides supplied stale timestamp');
    const engine = await database.query('SELECT version() AS version');
    return { tableCount: tables.rows.length, checks, engine: engine.rows[0].version };
  } finally {
    await database.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await validateDatabaseBaseline();
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    // Do not print query parameters or SQL error details containing business data.
    console.error(
      'Database baseline validation failed:',
      error instanceof Error ? error.message : 'unknown error',
    );
    process.exitCode = 1;
  }
}

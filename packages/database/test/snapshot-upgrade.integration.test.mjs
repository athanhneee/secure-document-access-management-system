import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { PGlite } from '@electric-sql/pglite';

const schemaUrl = new URL(
  '../../../docs/reference/database_secure_document_system.sql',
  import.meta.url,
);

const expected31Tables = [
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

test('Database Upgrade [NFR-REL01] — initializes from empty database and applies baseline schema', async () => {
  const db = await PGlite.create('memory://');

  // Verify DB begins completely empty
  const before = await db.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public'");
  assert.equal(before.rows.length, 0, 'Must begin with zero tables');

  // Apply baseline schema
  const sql = await readFile(schemaUrl, 'utf8');
  await db.exec(sql);

  // Verify all 31 business tables created
  const tables = await db.query(
    "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
  );
  assert.deepEqual(
    tables.rows.map((r) => r.tablename),
    expected31Tables,
  );
});

test('Database Upgrade [NFR-REL01] — preserves data across incremental snapshot upgrades', async () => {
  const db = await PGlite.create('memory://');
  await db.exec(await readFile(schemaUrl, 'utf8'));

  // Seed baseline data using system-generated identity columns
  const dept = await db.query(
    "INSERT INTO departments (code, name) VALUES ('BGD', 'Ban Giam Doc') RETURNING id",
  );
  const deptId = dept.rows[0].id;

  await db.query(
    `INSERT INTO users (username, email, password_hash, full_name, department_id, status)
     VALUES ('ceo_boss', 'ceo@corp.test', 'mock-password-hash', 'Tong Giam Doc', $1, 'ACTIVE')`,
    [deptId],
  );

  // Verify seeded record count
  const userCount = await db.query('SELECT COUNT(*) as count FROM users');
  assert.equal(Number(userCount.rows[0].count), 1);

  // Simulate applying incremental schema migration (e.g. adding index or auxiliary column)
  await db.exec(`
    CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users (LOWER(email));
    CREATE INDEX IF NOT EXISTS idx_documents_retention_check ON documents (retention_until);
  `);

  // Verify existing data was untouched and intact
  const verifiedUser = await db.query(
    "SELECT username, email, status FROM users WHERE username = 'ceo_boss'",
  );
  assert.equal(verifiedUser.rows[0].username, 'ceo_boss');
  assert.equal(verifiedUser.rows[0].status, 'ACTIVE');
});

test('Database Upgrade [NFR-REL01] — verifies audit log immutability trigger after full upgrade', async () => {
  const db = await PGlite.create('memory://');
  await db.exec(await readFile(schemaUrl, 'utf8'));

  // Insert audit record
  const audit = await db.query(
    `INSERT INTO audit_logs (actor_username, action, object_type, outcome, correlation_id, entry_hash)
     VALUES ($1, 'BASELINE_VALIDATION', 'TEST', 'SUCCESS', $2, $3) RETURNING id`,
    ['schema-validation-fixture', '10000000-0000-4000-8000-000000000001', '0'.repeat(64)],
  );
  const auditId = audit.rows[0].id;

  // Attempt to UPDATE audit log must be rejected by trigger
  await assert.rejects(
    async () => db.query("UPDATE audit_logs SET outcome='FAILED' WHERE id=$1", [auditId]),
    /audit_logs is append-only/,
  );

  // Attempt to DELETE audit log must be rejected by trigger
  await assert.rejects(
    async () => db.query('DELETE FROM audit_logs WHERE id=$1', [auditId]),
    /audit_logs is append-only/,
  );

  // Original row remains pristine
  const logRow = await db.query('SELECT outcome FROM audit_logs WHERE id = $1', [auditId]);
  assert.equal(logRow.rows[0].outcome, 'SUCCESS');
});

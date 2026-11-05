import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PGlite } from '@electric-sql/pglite';
import { pg_trgm } from '@electric-sql/pglite/contrib/pg_trgm';
import {
  EXPECTED_BUSINESS_TABLES,
  loadPrismaMigrations,
} from '../../../scripts/lib/schema-catalog.mjs';

const migrationsDirUrl = new URL('../prisma/migrations', import.meta.url);

const expectedInitial31Tables = [
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

/**
 * Algorithm: Incremental Snapshot Upgrade Replay.
 * Applies initial baseline migration (31 tables), inserts live domain records, and replays all
 * subsequent migrations (reaching 39 RLS-hardened tables) to verify zero data loss.
 */
test('Database Upgrade [NFR-REL01] — initializes from empty database and applies baseline schema', async () => {
  const migrations = await loadPrismaMigrations(migrationsDirUrl);
  const db = await PGlite.create('memory://', { extensions: { pg_trgm } });
  try {
    const before = await db.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public'");
    assert.equal(before.rows.length, 0, 'Must begin with zero tables');

    await db.exec(migrations[0].sql);
    const tables = await db.query(
      "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
    );
    assert.deepEqual(
      tables.rows.map((r) => r.tablename),
      expectedInitial31Tables,
    );
  } finally {
    await db.close();
  }
});

test('Database Upgrade [NFR-REL01] — preserves data across all incremental Prisma migrations (31 -> 39 tables)', async () => {
  const migrations = await loadPrismaMigrations(migrationsDirUrl);
  const db = await PGlite.create('memory://', { extensions: { pg_trgm } });
  try {
    // CONFLICT-RESOLVED: Chạy thực tế toàn bộ các bản nâng cấp migration #2..#10 trên dữ liệu đang có thay vì chỉ tạo index giả lập
    await db.exec(migrations[0].sql);

    const dept = await db.query(
      "INSERT INTO departments (code, name) VALUES ('BGD', 'Ban Giam Doc') RETURNING id",
    );
    const deptId = dept.rows[0].id;

    await db.query(
      `INSERT INTO users (username, email, password_hash, full_name, department_id, status)
       VALUES ('ceo_boss', 'ceo@corp.test', 'mock-password-hash', 'Tong Giam Doc', $1, 'ACTIVE')`,
      [deptId],
    );

    for (const migration of migrations.slice(1)) {
      await db.exec(migration.sql);
    }

    const upgradedTables = await db.query(
      "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
    );
    assert.deepEqual(
      upgradedTables.rows.map((r) => r.tablename),
      EXPECTED_BUSINESS_TABLES,
    );

    const verifiedUser = await db.query(
      "SELECT username, email, status, version FROM users WHERE username = 'ceo_boss'",
    );
    assert.equal(verifiedUser.rows[0].username, 'ceo_boss');
    assert.equal(verifiedUser.rows[0].status, 'ACTIVE');
    assert.equal(verifiedUser.rows[0].version, 0);
  } finally {
    await db.close();
  }
});

test('Database Upgrade [NFR-REL01] — verifies audit log immutability and TRUNCATE guard after full 10-migration upgrade', async () => {
  const migrations = await loadPrismaMigrations(migrationsDirUrl);
  const db = await PGlite.create('memory://', { extensions: { pg_trgm } });
  try {
    for (const migration of migrations) {
      await db.exec(migration.sql);
    }

    const audit = await db.query(
      `INSERT INTO audit_logs (actor_username, action, object_type, outcome, correlation_id, entry_hash, chain_sequence)
       VALUES ($1, 'BASELINE_VALIDATION', 'TEST', 'SUCCESS', $2, $3, 1) RETURNING id`,
      ['schema-validation-fixture', '10000000-0000-4000-8000-000000000001', '0'.repeat(64)],
    );
    const auditId = audit.rows[0].id;

    await assert.rejects(
      async () => db.query("UPDATE audit_logs SET outcome = 'FAILED' WHERE id = $1", [auditId]),
      /audit_logs is append-only/,
    );
    await assert.rejects(
      async () => db.query('DELETE FROM audit_logs WHERE id = $1', [auditId]),
      /audit_logs is append-only/,
    );
    await assert.rejects(
      async () => db.exec('TRUNCATE TABLE audit_logs CASCADE'),
      /audit_logs is append-only/,
    );

    const logRow = await db.query('SELECT outcome FROM audit_logs WHERE id = $1', [auditId]);
    assert.equal(logRow.rows[0].outcome, 'SUCCESS');
  } finally {
    await db.close();
  }
});

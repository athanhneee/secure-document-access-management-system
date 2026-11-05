import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { access, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const EXPECTED_BUSINESS_TABLES = [
  'access_grant_permissions',
  'access_grants',
  'access_request_decisions',
  'access_request_permissions',
  'access_requests',
  'access_sessions',
  'alert_audit_links',
  'async_export_jobs',
  'attribute_definitions',
  'attribute_options',
  'audit_anchors',
  'audit_logs',
  'auth_sessions',
  'business_categories',
  'classification_levels',
  'departments',
  'detection_rule_configs',
  'document_classification_history',
  'document_versions',
  'documents',
  'incident_actions',
  'incident_reports',
  'mfa_methods',
  'notification_outbox',
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

/**
 * Algorithm: Lexicographical Migration Chain Discovery & SHA-256 Checksum Indexing.
 * Scans Prisma migration directories, sorts them chronologically by timestamp prefix,
 * and computes raw SHA-256 digests matching Prisma Migrate's _prisma_migrations checksums.
 */
export async function loadPrismaMigrations(migrationsDirUrl) {
  const migrationsRoot = fileURLToPath(migrationsDirUrl);
  const entries = await readdir(migrationsRoot, { withFileTypes: true });
  const directories = entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort((left, right) => left.localeCompare(right));

  const migrations = [];
  for (const name of directories) {
    const sqlPath = path.join(migrationsRoot, name, 'migration.sql');
    const buffer = await readFile(sqlPath);
    migrations.push({
      name,
      checksum: createHash('sha256').update(buffer).digest('hex'),
      sql: buffer.toString('utf8'),
    });
  }
  return migrations;
}

/**
 * Algorithm: Deterministic PostgreSQL System-Catalog Introspection.
 * Queries pg_catalog and information_schema in deterministic sort order (excluding Prisma's
 * internal _prisma_migrations bookkeeping table) so two independent SQL sources can be
 * compared for exact structural equivalence via deep equality.
 */
export async function captureCatalogSnapshot(database) {
  const tables = (
    await database.query(
      "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> '_prisma_migrations' ORDER BY tablename",
    )
  ).rows.map((row) => row.tablename);

  const columns = (
    await database.query(
      `SELECT table_name, column_name, data_type, udt_name, is_nullable, column_default, character_maximum_length
       FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name <> '_prisma_migrations'
       ORDER BY table_name, column_name`,
    )
  ).rows;

  const enums = (
    await database.query(
      `SELECT t.typname, string_agg(e.enumlabel, ',' ORDER BY e.enumsortorder) AS labels
       FROM pg_type t
       JOIN pg_namespace n ON n.oid = t.typnamespace
       JOIN pg_enum e ON e.enumtypid = t.oid
       WHERE n.nspname = 'public' AND t.typtype = 'e'
       GROUP BY t.typname
       ORDER BY t.typname`,
    )
  ).rows;

  const constraints = (
    await database.query(
      `SELECT rel.relname AS table_name, con.contype, pg_get_constraintdef(con.oid) AS def
       FROM pg_constraint con
       JOIN pg_class rel ON rel.oid = con.conrelid
       JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
       WHERE nsp.nspname = 'public' AND rel.relname <> '_prisma_migrations'
       ORDER BY rel.relname, con.contype, pg_get_constraintdef(con.oid)`,
    )
  ).rows;

  const indexes = (
    await database.query(
      "SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND tablename <> '_prisma_migrations' ORDER BY indexname",
    )
  ).rows.map((row) => row.indexname);

  const triggers = (
    await database.query('SELECT tgname FROM pg_trigger WHERE NOT tgisinternal ORDER BY tgname')
  ).rows.map((row) => row.tgname);

  const rlsTables = (
    await database.query(
      `SELECT c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity AND c.relname <> '_prisma_migrations'
       ORDER BY c.relname`,
    )
  ).rows.map((row) => row.relname);

  const forceRlsTables = (
    await database.query(
      `SELECT c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relforcerowsecurity AND c.relname <> '_prisma_migrations'
       ORDER BY c.relname`,
    )
  ).rows.map((row) => row.relname);

  const rlsPolicies = (
    await database.query(
      `SELECT tablename, policyname, permissive, cmd
       FROM pg_policies
       WHERE schemaname = 'public' AND tablename <> '_prisma_migrations'
       ORDER BY tablename, policyname`,
    )
  ).rows;

  return {
    tables,
    columns,
    enums,
    constraints,
    indexes,
    triggers,
    rlsTables,
    forceRlsTables,
    rlsPolicies,
  };
}

/**
 * Algorithm: Field-by-Field Catalog Equivalence Verification.
 * Compares each normalized catalog dimension independently to pinpoint any schema drift
 * between Prisma migrations and standalone SQL definitions.
 */
export function assertCatalogParity(referenceSnapshot, candidateSnapshot, candidateLabel) {
  for (const dimension of Object.keys(referenceSnapshot)) {
    assert.deepEqual(
      candidateSnapshot[dimension],
      referenceSnapshot[dimension],
      `Schema drift detected in ${dimension} between Prisma migrations and ${candidateLabel}`,
    );
  }
}

export async function fileExists(fileUrl) {
  try {
    await access(fileUrl);
    return true;
  } catch {
    return false;
  }
}

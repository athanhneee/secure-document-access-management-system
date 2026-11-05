import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { config as loadEnvironment } from 'dotenv';
import pg from 'pg';

loadEnvironment({ path: new URL('../../../../.local/dev.env', import.meta.url), quiet: true });

export const sourceUrl = new URL(
  process.env['DATABASE_URL'] ?? 'postgresql://127.0.0.1:5432/secure_docs?schema=public',
);
const adminUrl = new URL(sourceUrl);
adminUrl.pathname = '/postgres';
adminUrl.search = '';

export const expectedTables = [
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

export function databaseUrl(name) {
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

export async function isDatabaseReachable() {
  const client = new pg.Client({
    connectionString: adminUrl.toString(),
    connectionTimeoutMillis: 1000,
  });
  try {
    await client.connect();
    await client.end();
    return true;
  } catch {
    return false;
  }
}

/**
 * Algorithm: Ephemeral isolated test database lifecycle provisioning.
 * Validates the generated database identifier against a strict hex allowlist before issuing
 * `DROP DATABASE ... WITH (FORCE)` and `CREATE DATABASE` on the administrative connection.
 */
export async function recreateDatabase(name) {
  assert.match(name, /^sda_(?:migration|rollback)_[a-f0-9]{32}$/u);
  await adminQuery(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
  await adminQuery(`CREATE DATABASE "${name}"`);
}

export async function dropDatabase(name) {
  assert.match(name, /^sda_(?:migration|rollback)_[a-f0-9]{32}$/u);
  await adminQuery(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
}

export function runPrisma(args, targetUrl) {
  const prismaCli = fileURLToPath(import.meta.resolve('prisma')).replace(
    /[\\/]build[\\/]types\.js$/u,
    '/build/index.js',
  );
  const result = spawnSync(process.execPath, [prismaCli, ...args, '--config', 'prisma.config.ts'], {
    cwd: fileURLToPath(new URL('../../', import.meta.url)),
    encoding: 'utf8',
    env: { ...process.env, DATABASE_URL: targetUrl, DIRECT_URL: targetUrl, NODE_ENV: 'test' },
    shell: false,
  });
  if (result.error) throw result.error;
  assert.equal(
    result.status,
    0,
    [result.stdout, result.stderr].filter(Boolean).join('\n').replaceAll(targetUrl, '[REDACTED]'),
  );
}

export async function businessTableCount(client) {
  const result = await client.query(
    "SELECT count(*)::int AS count FROM pg_tables WHERE schemaname='public' AND tablename <> '_prisma_migrations'",
  );
  return result.rows[0].count;
}

export async function businessTableNames(client) {
  const result = await client.query(
    "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> '_prisma_migrations' ORDER BY tablename",
  );
  return result.rows.map((row) => row.tablename);
}

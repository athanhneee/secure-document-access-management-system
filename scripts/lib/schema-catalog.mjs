/**
 * Module: Khám Phá Chuỗi Di Trú Prisma & Chụp Ảnh Tương Đương Danh Mục Hệ Thống PostgreSQL (`SchemaCatalog`)
 * Thuật toán: Sắp Xếp Từ Điển Di Trú Kèm Băm SHA-256 & Nội Soi Danh Mục Hệ Thống Tất Định (`Deterministic Catalog Introspection`).
 *   - Đọc tuần tự các thư mục di trú Prisma theo thứ tự dấu thời gian, tính mã băm SHA-256 nguyên bản khớp chuẩn `_prisma_migrations`.
 *   - Truy vấn `pg_catalog` và `information_schema` với `ORDER BY` tất định trên 9 chiều cấu trúc (bảng, cột, enum, ràng buộc, chỉ mục, trigger, RLS, FORCE RLS, chính sách RLS) để phát hiện lệch lược đồ.
 */
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
 * Thuật toán: Khám Phá Chuỗi Di Trú Theo Thứ Tự Từ Điển & Lập Chỉ Mục Băm SHA-256 (`Lexicographical Migration Chain Discovery`).
 * Quét thư mục `migrations`, sắp xếp tăng dần theo tiền tố dấu thời gian và tính SHA-256 khớp với bảng `_prisma_migrations`.
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
 * Thuật toán: Nội Soi Danh Mục Hệ Thống PostgreSQL Tất Định (`Deterministic System-Catalog Introspection`).
 * Truy vấn `pg_catalog` và `information_schema` theo thứ tự sắp xếp cố định (loại trừ bảng quản trị `_prisma_migrations`)
 * để đối chiếu tương đương cấu trúc tuyệt đối giữa hai nguồn SQL độc lập.
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
 * Thuật toán: Đối Chiếu Tương Đương Từng Chiều Danh Mục (`Field-by-Field Catalog Equivalence Verification`).
 * So sánh sâu từng chiều cấu trúc độc lập để định vị chính xác mọi sai lệch lược đồ giữa chuỗi di trú Prisma và định nghĩa SQL chuẩn.
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

/**
 * Thuật toán: Kiểm tra sự tồn tại của tệp cấu hình/di trú qua lời gọi hệ thống `fs.access` không ném ngoại lệ ra ngoài.
 */
export async function fileExists(fileUrl) {
  try {
    await access(fileUrl);
    return true;
  } catch {
    return false;
  }
}

/**
 * Thuật toán: Xác Minh Tương Đương Đa Nguồn Lược Đồ & Bất Biến Bảo Mật Trên Máy Ảo PostgreSQL WASM (`PGlite`)
 * Mục đích: Đảm bảo tính nhất quán tuyệt đối giữa chuỗi Prisma migrations, kịch bản tích hợp Supabase SQL và tệp DDL chuẩn tham chiếu trên không gian nhớ cô lập.
 * Cơ chế hoạt động:
 *   - Khởi tạo các phiên bản PostgreSQL WASM tạm thời có nạp phần mở rộng `pg_trgm`, chụp ảnh danh mục hệ thống (`pg_tables`, `pg_type`, `pg_trigger`, RLS) và kiểm chứng các bất biến bảo mật động cùng tính lũy đẳng (idempotency) của kịch bản SQL.
 */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { pg_trgm } from '@electric-sql/pglite/contrib/pg_trgm';
import {
  EXPECTED_BUSINESS_TABLES,
  assertCatalogParity,
  captureCatalogSnapshot,
  fileExists,
  loadPrismaMigrations,
} from './lib/schema-catalog.mjs';
import { verifyDatabaseInvariants } from './lib/schema-invariants.mjs';

const migrationsDirUrl = new URL('../packages/database/prisma/migrations', import.meta.url);
const supabaseSqlUrl = new URL('../supabase/01_supabase_full_schema_and_seed.sql', import.meta.url);
const referenceSqlUrl = new URL('../../database_secure_document_system.sql', import.meta.url);

/**
 * Thuật toán: Khởi Tạo Thực Thể PostgreSQL WASM Cô Lập Trong Bộ Nhớ (`memory://` + `pg_trgm`)
 * Mục đích: Tạo không gian cơ sở dữ liệu sạch tuyệt đối không lưu trạng thái đĩa phục vụ kiểm chứng độc lập từng nguồn DDL.
 * Cơ chế hoạt động:
 *   - Cấp phát phiên bản `PGlite` chạy hoàn toàn trên RAM kèm phần mở rộng tìm kiếm tam tự `pg_trgm`.
 */
async function createEphemeralPostgres() {
  return PGlite.create('memory://', { extensions: { pg_trgm } });
}

/**
 * Algorithm: Multi-Source Schema Replay & Cross-Definition Equivalence Verification.
 * // CONFLICT-RESOLVED: Thay vì chỉ chạy migration đầu tiên (31 bảng), hàm này thực thi tuần tự
 * toàn bộ chuỗi Prisma migrations (39 bảng) và đối chiếu đồng nhất 100% cấu trúc + SHA-256
 * checksum với kịch bản Supabase SQL và tệp DDL chuẩn database_secure_document_system.sql.
 *
 * Thuật toán: Phát Lại Chuỗi Migration, Kiểm Chứng Tính Lũy Đẳng & Đối Chiếu Đẳng Cấu Lược Đồ Đa Nguồn
 * Mục đích: Chứng minh toàn bộ migrations áp dụng sạch sẽ, bật đủ Row-Level Security (RLS), thỏa mãn mọi trigger bất biến và đồng nhất 100% mã băm `SHA-256` với bản SQL hợp nhất.
 * Cơ chế hoạt động:
 *   - Pha 1: Nạp tuần tự tất cả tệp Prisma migration trên `migrationDb`, chụp ảnh danh mục (`captureCatalogSnapshot`) đối chiếu 39 bảng bật RLS, 18 kiểu `ENUM`, 19 `trigger` và thực thi bộ kiểm tra bất biến `verifyDatabaseInvariants`.
 *   - Pha 2: Chạy lặp 2 lần liên tiếp tệp `01_supabase_full_schema_and_seed.sql` trên `supabaseDb` để chứng minh tính lũy đẳng (idempotency), so khớp cấu trúc qua `assertCatalogParity` và đối chiếu bảng băm `_prisma_migrations` `SHA-256`.
 *   - Pha 3: Nếu có mặt tệp tham chiếu `database_secure_document_system.sql`, kiểm chứng tiếp sự đẳng cấu danh mục 100% với ảnh chụp chuẩn.
 */
export async function validateDatabaseBaseline() {
  const migrations = await loadPrismaMigrations(migrationsDirUrl);
  assert.ok(migrations.length >= 10, `Expected at least 10 migrations, found ${migrations.length}`);

  const checks = [];
  const migrationDb = await createEphemeralPostgres();
  let migrationSnapshot;
  let engineVersion = '';

  try {
    const before = await migrationDb.query(
      "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
    );
    assert.equal(before.rows.length, 0, 'Validation must begin with an empty schema');

    for (const migration of migrations) {
      await migrationDb.exec(migration.sql);
    }

    migrationSnapshot = await captureCatalogSnapshot(migrationDb);
    assert.deepEqual(migrationSnapshot.tables, EXPECTED_BUSINESS_TABLES);
    assert.equal(migrationSnapshot.enums.length, 18);
    assert.equal(migrationSnapshot.triggers.length, 21);
    assert.deepEqual(migrationSnapshot.rlsTables, EXPECTED_BUSINESS_TABLES);
    assert.deepEqual(migrationSnapshot.forceRlsTables, EXPECTED_BUSINESS_TABLES);
    assert.equal(migrationSnapshot.rlsPolicies.length, EXPECTED_BUSINESS_TABLES.length * 2);
    checks.push(
      `all ${migrations.length} Prisma migrations apply cleanly (${migrationSnapshot.tables.length} FORCE-RLS tables, ${migrationSnapshot.rlsPolicies.length} RLS policies, 18 enums, 21 triggers)`,
    );

    const rulesCount = await migrationDb.query(
      'SELECT count(*)::int AS count FROM detection_rule_configs',
    );
    assert.equal(rulesCount.rows[0].count, 6);
    const invariantChecks = await verifyDatabaseInvariants(migrationDb);
    checks.push(...invariantChecks);

    const engine = await migrationDb.query('SELECT version() AS version');
    engineVersion = engine.rows[0].version;
  } finally {
    await migrationDb.close();
  }

  // Verify Supabase all-in-one idempotent SQL parity & Prisma migration SHA-256 checksums when present on disk
  let supabaseParity = null;
  if (await fileExists(supabaseSqlUrl)) {
    const supabaseDb = await createEphemeralPostgres();
    try {
      const supabaseSql = await readFile(supabaseSqlUrl, 'utf8');
      await supabaseDb.exec(supabaseSql);
      await supabaseDb.exec(supabaseSql); // Second pass proves script idempotency

      const supabaseSnapshot = await captureCatalogSnapshot(supabaseDb);
      assertCatalogParity(
        migrationSnapshot,
        supabaseSnapshot,
        'supabase/01_supabase_full_schema_and_seed.sql',
      );

      const recordedMigrations = (
        await supabaseDb.query(
          'SELECT migration_name, checksum FROM _prisma_migrations ORDER BY migration_name',
        )
      ).rows;
      assert.deepEqual(
        recordedMigrations,
        migrations.map(({ name, checksum }) => ({ migration_name: name, checksum })),
        'Supabase _prisma_migrations SHA-256 checksums must match Prisma migration files',
      );
      supabaseParity = true;
      checks.push(
        'Supabase SQL is idempotent and matches Prisma migrations + SHA-256 checksums 100%',
      );
    } finally {
      await supabaseDb.close();
    }
  }

  // Verify standalone workspace reference SQL parity when present on disk
  let referenceSqlParity = null;
  if (await fileExists(referenceSqlUrl)) {
    const referenceDb = await createEphemeralPostgres();
    try {
      await referenceDb.exec(await readFile(referenceSqlUrl, 'utf8'));
      const referenceSnapshot = await captureCatalogSnapshot(referenceDb);
      assertCatalogParity(
        migrationSnapshot,
        referenceSnapshot,
        'database_secure_document_system.sql',
      );
      referenceSqlParity = true;
      checks.push('database_secure_document_system.sql matches Prisma migrations 100%');
    } finally {
      await referenceDb.close();
    }
  }

  return {
    tableCount: migrationSnapshot.tables.length,
    migrationCount: migrations.length,
    enumCount: migrationSnapshot.enums.length,
    triggerCount: migrationSnapshot.triggers.length,
    supabaseParity,
    referenceSqlParity,
    checks,
    engine: engineVersion,
  };
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

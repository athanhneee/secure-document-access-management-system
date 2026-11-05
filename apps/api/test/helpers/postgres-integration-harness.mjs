import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

/**
 * Thuật toán: Nạp Biến Môi trường Cục bộ Không Ghi đè (`loadLocalDevEnv`)
 * Mục đích: Đọc tệp `.local/dev.env` vào `process.env` theo toán tử gán rỗng `??=` để giữ nguyên các biến do CI hoặc dòng lệnh truyền vào.
 * Cơ chế hoạt động:
 *   - Tách từng dòng và cắt tại dấu `=` đầu tiên (`indexOf('=')`) để bảo toàn các chuỗi kết nối chứa nhiều dấu `=` trong tham số truy vấn.
 */
export function loadLocalDevEnv() {
  const devEnvUrl = new URL('../../../../.local/dev.env', import.meta.url);
  if (existsSync(devEnvUrl)) {
    for (const line of readFileSync(devEnvUrl, 'utf8').split(/\r?\n/u)) {
      const separator = line.indexOf('=');
      if (separator > 0) process.env[line.slice(0, separator)] ??= line.slice(separator + 1);
    }
  }
}

/**
 * Algorithm: Ephemeral PostgreSQL Test Database Provisioner & Migration Runner
 * Description: Allocates a unique UUID-suffixed PostgreSQL database per integration suite via
 *              administrative connection to `/postgres`, deploys Prisma schema migrations in a
 *              shell-free child process, and force-drops the ephemeral database during teardown.
 * Time Complexity: O(M) where M is the number of Prisma migrations applied.
 * Space Complexity: O(1) process memory; isolated temporary database catalog on PostgreSQL server.
 */
/**
 * Thuật toán: Cấp phát & Dọn dẹp Cơ sở Dữ liệu Kiểm thử Tích hợp Tạm thời (`createEphemeralDatabaseHarness`)
 * Mục đích: Tạo không gian cơ sở dữ liệu PostgreSQL độc lập gắn hậu tố UUID ngẫu nhiên cho mỗi tệp kiểm thử tích hợp và tự động thu hồi sau khi chạy xong.
 * Cơ chế hoạt động:
 *   - Thăm dò khả năng kết nối tới cơ sở dữ liệu quản trị `/postgres` với ngưỡng chờ `1000ms` (`isDatabaseReachable`).
 *   - Khởi tạo DB mới (`CREATE DATABASE`), thực thi `prisma migrate deploy` qua tiến trình con không dùng shell (`shell: false`), và hủy cưỡng bức bằng `DROP DATABASE ... WITH (FORCE)` trong pha `teardown`.
 */
export function createEphemeralDatabaseHarness(prefix, { coerceBigIntId = false } = {}) {
  loadLocalDevEnv();

  const sourceUrl = new URL(
    process.env.DATABASE_URL ?? 'postgresql://127.0.0.1:5432/secure_docs?schema=public',
  );
  const adminUrl = new URL(sourceUrl);
  adminUrl.pathname = '/postgres';
  adminUrl.search = '';
  const databaseName = `${prefix}_${randomUUID().replaceAll('-', '')}`;
  const targetUrl = new URL(sourceUrl);
  targetUrl.pathname = `/${databaseName}`;

  let sql = null;
  let prisma = null;
  let pgliteHandle = null;
  let disconnectDatabase = null;
  let dbAvailable = false;
  let usingPglite = false;

  async function isDatabaseReachable() {
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

  async function adminQuery(statement) {
    const client = new pg.Client({ connectionString: adminUrl.toString() });
    await client.connect();
    try {
      await client.query(statement);
    } finally {
      await client.end();
    }
  }

  async function insertOne(statement, parameters = []) {
    const result = await sql.query(statement, parameters);
    const row = result.rows[0];
    if (
      coerceBigIntId &&
      row &&
      (typeof row.id === 'number' || (typeof row.id === 'string' && /^\d+$/u.test(row.id)))
    ) {
      row.id = BigInt(row.id);
    }
    return row;
  }

  async function setup() {
    const liveReachable = await isDatabaseReachable();
    if (!liveReachable) {
      const { createPGlitePrismaInstance } = await import('./pglite-prisma-harness.mjs');
      pgliteHandle = await createPGlitePrismaInstance();
      sql = pgliteHandle.sql;
      prisma = pgliteHandle.prisma;
      globalThis.__secureDocumentPrismaClient = prisma;
      dbAvailable = true;
      usingPglite = true;
      return true;
    }
    dbAvailable = true;
    usingPglite = false;

    await adminQuery(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
    await adminQuery(`CREATE DATABASE "${databaseName}"`);
    const prismaCli = fileURLToPath(import.meta.resolve('prisma')).replace(
      /[\\/]build[\\/]types\.js$/u,
      '/build/index.js',
    );
    const migration = spawnSync(
      process.execPath,
      [prismaCli, 'migrate', 'deploy', '--config', 'prisma.config.ts'],
      {
        cwd: fileURLToPath(new URL('../../../../packages/database/', import.meta.url)),
        encoding: 'utf8',
        env: {
          ...process.env,
          DATABASE_URL: targetUrl.toString(),
          DIRECT_URL: targetUrl.toString(),
          NODE_ENV: 'test',
        },
        shell: false,
      },
    );
    assert.equal(migration.status, 0, migration.stderr || migration.stdout);
    process.env.DATABASE_URL = targetUrl.toString();
    process.env.DIRECT_URL = targetUrl.toString();
    sql = new pg.Client({ connectionString: targetUrl.toString() });
    await sql.connect();

    const databaseModule = await import('@sda/database');
    ({ disconnectDatabase } = databaseModule);
    prisma = databaseModule.getDatabaseClient();
    return true;
  }

  async function teardown() {
    if (!dbAvailable) return;
    if (usingPglite) {
      delete globalThis.__secureDocumentPrismaClient;
      await pgliteHandle?.close();
      pgliteHandle = null;
      prisma = null;
      sql = null;
      return;
    }
    await sql?.end();
    await disconnectDatabase?.();
    await adminQuery(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
  }

  return {
    get dbAvailable() {
      return dbAvailable;
    },
    get sql() {
      return sql;
    },
    get prisma() {
      return prisma;
    },
    insertOne,
    setup,
    teardown,
  };
}

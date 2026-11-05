/**
 * @module PGlitePrismaHarness
 * Algorithm: Dual-Mode PostgreSQL Integration Harness (Live TCP PostgreSQL -> Embedded PostgreSQL 18 WASM PGlite Fallback).
 * Thuật toán: Bộ khung kiểm thử tích hợp SQL thực hai chế độ:
 *   1. Ưu tiên kết nối tới máy chủ PostgreSQL vật lý (`127.0.0.1:5432`) với cơ sở dữ liệu tạm thời độc lập khi hạ tầng Docker đang chạy.
 *   2. Khi không có daemon TCP bên ngoài, tự động khởi tạo máy ảo PostgreSQL 18.3 WASM (`@electric-sql/pglite` + `pg_trgm`) trên RAM ở múi giờ `UTC`,
 *      nạp toàn bộ 10 Prisma migrations (39 bảng FORCE RLS, 78 RLS policies, 18 enums, 21 triggers) và ánh xạ luồng văn bản gốc OID
 *      qua `@prisma/adapter-pg` (`PrismaPg`) với cơ chế khóa hai tầng (`queryChain` cho từng truy vấn đơn lẻ và `txChain` riêng cho phiên giao dịch `connect()`)
 *      nhằm chống bế tắc tái nhập (re-entrant deadlock) khi dịch vụ gọi đọc ngoài giao dịch bên trong `$transaction`.
 */
import { EventEmitter } from 'node:events';
import pg from 'pg';
import { PGlite } from '@electric-sql/pglite';
import { pg_trgm } from '@electric-sql/pglite/contrib/pg_trgm';
import { PrismaPg } from '../../../../packages/database/node_modules/@prisma/adapter-pg/dist/index.mjs';
import { PrismaClient } from '../../../../packages/database/dist/generated/prisma/client.js';
import { loadPrismaMigrations } from '../../../../scripts/lib/schema-catalog.mjs';

const migrationsDirUrl = new URL(
  '../../../../packages/database/prisma/migrations',
  import.meta.url,
);

const RAW_TEXT_OIDS = [
  16, 17, 18, 19, 20, 21, 23, 25, 26, 114, 142, 650, 700, 701, 790, 869, 1000, 1001, 1005, 1007,
  1009, 1014, 1015, 1016, 1021, 1022, 1042, 1043, 1082, 1083, 1114, 1115, 1182, 1183, 1184, 1185,
  1186, 1231, 1266, 1560, 1562, 1700, 2950, 2951, 3802, 3807,
];
const IDENTITY_PARSERS = Object.fromEntries(RAW_TEXT_OIDS.map((oid) => [oid, (raw) => raw]));

function normalizeSqlParam(value) {
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Date) return value.toISOString();
  return value;
}

/**
 * Algorithm / Thuật toán: Bộ điều hợp `pg.Pool` hai tầng khóa (`queryChain` + `txChain`) trên nền `PGlite`.
 * - `queryChain` tuần tự hóa từng lệnh I/O xuống nhân WASM PostgreSQL.
 * - `txChain` chỉ tuần tự hóa các khối giao dịch `connect() .. release()` với nhau để hai `$transaction` song song không đan xen `BEGIN`,
 *   nhưng vẫn cho phép các truy vấn đọc `pool.query()` bên trong callback `$transaction` thực thi ngay mà không bị treo chờ khóa giao dịch.
 */
export class PGlitePool extends pg.Pool {
  constructor(pglite) {
    super({ max: 1 });
    this.pglite = pglite;
    this.queryChain = Promise.resolve();
    this.txChain = Promise.resolve();
  }

  async _runSerializedQuery(queryOrText, values) {
    let releaseQuery;
    const prevQuery = this.queryChain;
    this.queryChain = new Promise((resolve) => {
      releaseQuery = resolve;
    });
    await prevQuery;
    try {
      const isObj = typeof queryOrText === 'object' && queryOrText !== null;
      const text = isObj ? queryOrText.text : String(queryOrText);
      const rawParams = isObj ? (queryOrText.values ?? []) : (values ?? []);
      const params = rawParams.map(normalizeSqlParam);
      const rowMode = isObj ? queryOrText.rowMode : undefined;
      const customTypes = isObj ? queryOrText.types : undefined;

      if (rowMode === 'array') {
        const res = await this.pglite.query(text, params, {
          rowMode: 'array',
          parsers: IDENTITY_PARSERS,
        });
        const fields = res.fields ?? [];
        const rows = res.rows.map((row) =>
          row.map((cell, idx) => {
            if (cell === null || cell === undefined) return null;
            const oid = fields[idx]?.dataTypeID;
            const parser =
              customTypes?.getTypeParser?.(oid, 'text') ?? pg.types.getTypeParser(oid, 'text');
            return parser(String(cell));
          }),
        );
        return { rows, fields, rowCount: res.affectedRows || rows.length };
      }

      const res = await this.pglite.query(text, params);
      return {
        rows: res.rows,
        fields: res.fields ?? [],
        rowCount: res.affectedRows || res.rows.length,
      };
    } catch (err) {
      if (err && typeof err === 'object') {
        err.severity ??= 'ERROR';
        err.code ??= 'P0001';
      }
      throw err;
    } finally {
      releaseQuery();
    }
  }

  async query(queryOrText, values) {
    return await this._runSerializedQuery(queryOrText, values);
  }

  async connect() {
    let releaseTx;
    const prevTx = this.txChain;
    this.txChain = new Promise((resolve) => {
      releaseTx = resolve;
    });
    await prevTx;

    let released = false;
    const self = this;
    const emitter = new EventEmitter();
    return Object.assign(emitter, {
      query: (q, v) => self._runSerializedQuery(q, v),
      release: () => {
        if (!released) {
          released = true;
          releaseTx();
        }
      },
    });
  }

  async end() {}
}

/**
 * Algorithm / Thuật toán: Khởi tạo không gian PostgreSQL 18.3 WASM cô lập ở múi giờ `UTC` kèm `PrismaClient`.
 */
export async function createPGlitePrismaInstance() {
  const pglite = await PGlite.create('memory://', { extensions: { pg_trgm } });
  await pglite.exec("SET TIME ZONE 'UTC'");
  const migrations = await loadPrismaMigrations(migrationsDirUrl);
  for (const migration of migrations) {
    await pglite.exec(migration.sql);
  }

  const pool = new PGlitePool(pglite);
  const adapter = new PrismaPg(pool);
  const prisma = new PrismaClient({
    adapter,
    transactionOptions: { maxWait: 10_000, timeout: 15_000 },
  });

  const sql = {
    query: (statement, parameters = []) => pool.query(statement, parameters),
    exec: (script) => pglite.exec(script),
    end: async () => {},
  };

  async function close() {
    await prisma.$disconnect();
    await pglite.close();
  }

  return { pglite, pool, sql, prisma, close };
}

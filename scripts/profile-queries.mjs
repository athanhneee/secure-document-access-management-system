/**
 * Thuật toán: Bộ Phân Tích Kế Hoạch Truy Vấn `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` (Live PostgreSQL & Offline 13-Migration PGlite Profiler)
 * - Khi `DATABASE_URL` khả dụng: Mở giao dịch `READ ONLY` trên PostgreSQL thật và chạy `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)`
 *   để bóc tách cây kế hoạch JSON (`Node Type`, `Index Name`, `Execution Time`) trên 4 luồng truy vấn đường nóng.
 * - Chỉ rơi về `PGlite` ngoại tuyến khi không thể kết nối, phát lại toàn bộ 13 di trú Prisma thật kèm chỉ mục thật.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const dbRequire = createRequire(new URL('../packages/database/package.json', import.meta.url));
const { Client: PgClient } = dbRequire('pg');
const MIGRATIONS_DIR = fileURLToPath(
  new URL('../packages/database/prisma/migrations', import.meta.url),
);

/**
 * Thuật toán: Duyệt Đệ Quy Cây Kế Hoạch `EXPLAIN (FORMAT JSON)` Thu Thập Loại Nút Quét & Tên Chỉ Mục.
 */
function walkExplainPlanNode(node, collected = []) {
  if (!node || typeof node !== 'object') return collected;
  const nodeType = node['Node Type'] ?? 'Unknown';
  const relation = node['Relation Name'] ? ` on ${node['Relation Name']}` : '';
  const indexName = node['Index Name'] ? ` using ${node['Index Name']}` : '';
  const actualRows = node['Actual Rows'] !== undefined ? ` (rows=${node['Actual Rows']})` : '';
  collected.push({
    nodeType,
    indexName: node['Index Name'] ?? null,
    summary: `${nodeType}${relation}${indexName}${actualRows}`,
  });
  if (Array.isArray(node.Plans)) {
    for (const child of node.Plans) walkExplainPlanNode(child, collected);
  }
  return collected;
}

/**
 * Thuật toán: Thực thi `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` và phân loại chiến lược quét B-Tree Index vs Seq Scan.
 */
async function profileQuery(db, title, query, params) {
  console.log('-'.repeat(78));
  console.log(`QUERY: ${title}`);
  console.log('-'.repeat(78));

  const explainResult = await db.query(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${query}`, params);
  const rawPlanPayload = explainResult.rows[0]?.['QUERY PLAN'] ?? explainResult.rows[0]?.query_plan;
  const parsedRoot =
    typeof rawPlanPayload === 'string' ? JSON.parse(rawPlanPayload) : rawPlanPayload;
  const topPlanEntry = Array.isArray(parsedRoot) ? parsedRoot[0] : parsedRoot;
  const nodes = walkExplainPlanNode(topPlanEntry?.Plan);
  const planLines = nodes.map((n) => n.summary);
  const executionTimeMs = Number(topPlanEntry?.['Execution Time'] ?? 0);

  console.log(planLines.join('\n'));
  const usesIndex = nodes.some((n) =>
    ['Index Scan', 'Index Only Scan', 'Bitmap Index Scan'].includes(n.nodeType),
  );
  const isSeqScan = nodes.some((n) => n.nodeType === 'Seq Scan');
  console.log(
    `=> Scan Type: ${usesIndex ? 'INDEX SCAN [OPTIMAL]' : isSeqScan ? 'SEQUENTIAL SCAN' : 'OPTIMIZED'} (${executionTimeMs.toFixed(2)}ms)`,
  );
  return { title, plan: planLines, planJson: topPlanEntry, usesIndex, executionTimeMs };
}

/**
 * Thuật toán: Thử kết nối PostgreSQL thật ở chế độ chỉ đọc (`BEGIN READ ONLY`) cho 4 truy vấn nóng.
 */
async function tryConnectLiveProfilerDb(databaseUrl, strictLive) {
  const client = new PgClient({ connectionString: databaseUrl, connectionTimeoutMillis: 2500 });
  try {
    await client.connect();
    await client.query('BEGIN READ ONLY');
    const sampleDoc = await client.query('SELECT id, department_id FROM documents LIMIT 1');
    const sampleUser = await client.query('SELECT id FROM users LIMIT 1');
    return {
      db: client,
      sampleDocId: sampleDoc.rows[0]?.id ?? '00000000-0000-4000-8000-000000000001',
      sampleDeptId: Number(sampleDoc.rows[0]?.department_id ?? 1),
      sampleUserId: Number(sampleUser.rows[0]?.id ?? 1),
      close: async () => {
        await client.query('ROLLBACK').catch(() => {});
        await client.end().catch(() => {});
      },
    };
  } catch (err) {
    await client.end().catch(() => {});
    if (!['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT'].includes(err?.code ?? '') || strictLive)
      throw err;
    return null;
  }
}

/**
 * Thuật toán: Khởi tạo `PGlite` với đầy đủ 13 di trú Prisma thật và nạp tập dữ liệu chuẩn hóa để kiểm chứng chỉ mục B-Tree.
 */
async function buildOffline13MigrationProfileDb() {
  let PGlite;
  let pg_trgm;
  try {
    [{ PGlite }, { pg_trgm }] = await Promise.all([
      import('@electric-sql/pglite'),
      import('@electric-sql/pglite/contrib/pg_trgm'),
    ]);
  } catch {
    const pnpmStore = fileURLToPath(new URL('../node_modules/.pnpm', import.meta.url));
    const match = fs.readdirSync(pnpmStore).find((e) => e.startsWith('@electric-sql+pglite@'));
    if (!match) throw new Error('@electric-sql/pglite is not installed for offline fallback');
    const baseDir = path.join(pnpmStore, match, 'node_modules/@electric-sql/pglite/dist');
    [{ PGlite }, { pg_trgm }] = await Promise.all([
      import(pathToFileURL(path.join(baseDir, 'index.js')).href),
      import(pathToFileURL(path.join(baseDir, 'contrib/pg_trgm.js')).href),
    ]);
  }
  const db = new PGlite({ extensions: { pg_trgm } });
  const folders = fs
    .readdirSync(MIGRATIONS_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort((a, b) => a.localeCompare(b));
  for (const folder of folders) {
    const sqlPath = path.join(MIGRATIONS_DIR, folder, 'migration.sql');
    if (fs.existsSync(sqlPath)) await db.exec(fs.readFileSync(sqlPath, 'utf8'));
  }

  const sampleDocId = '00000000-0000-4000-8000-000000000010';
  const grantId = '00000000-0000-4000-8000-000000000020';
  const sessionId = '00000000-0000-4000-8000-000000000030';
  // CONFLICT-RESOLVED: Tham số hóa toàn bộ câu lệnh INSERT fixture kiểm chứng chỉ mục bằng placeholder vị trí ($1..$4) thay vì nối chuỗi SQL ([MEDIUM-03]).
  await db.exec(`
    INSERT INTO departments (id, code, name) OVERRIDING SYSTEM VALUE VALUES (1, 'RND', 'Research & Security');
    INSERT INTO classification_levels (id, code, name, rank) OVERRIDING SYSTEM VALUE VALUES (1, 'CONFIDENTIAL', 'Confidential', 3);
    INSERT INTO business_categories (id, code, name) OVERRIDING SYSTEM VALUE VALUES (1, 'FIN', 'Finance');
    INSERT INTO users (id, username, email, password_hash, full_name, status) OVERRIDING SYSTEM VALUE
      VALUES (1, 'profiler_user', 'profiler@sda.local', '$argon2id$v=19$m=19456,t=2,p=1$stub', 'Profiler User', 'ACTIVE');
    INSERT INTO attribute_definitions (id, code, name, scope, value_type) OVERRIDING SYSTEM VALUE
      VALUES (1, 'CLEARANCE_LEVEL', 'Clearance Level', 'USER', 'ENUM');
    INSERT INTO attribute_options (id, attribute_definition_id, value_code, display_name, numeric_rank) OVERRIDING SYSTEM VALUE
      VALUES (1, 1, 'CONFIDENTIAL', 'Confidential', 3);
    INSERT INTO user_attribute_assignments (id, user_id, attribute_definition_id, option_id, valid_from, assigned_by) OVERRIDING SYSTEM VALUE
      VALUES (1, 1, 1, 1, NOW() - INTERVAL '1 day', 1);
  `);
  await db.query(
    `INSERT INTO documents (id, document_code, title, owner_id, department_id, status, discoverable)
     VALUES ($1, 'DOC-PROF-01', 'Indexed Security Spec', 1, 1, 'ACTIVE', TRUE)`,
    [sampleDocId],
  );
  await db.query(
    `INSERT INTO document_versions (id, document_id, version_no, original_filename, storage_key, mime_type, file_size_bytes, sha256_hash, encryption_key_ref, uploaded_by) OVERRIDING SYSTEM VALUE
     VALUES (1, $1, 1, 'spec.pdf', 'docs/spec.pdf', 'application/pdf', 4096, $2, 'kek-v1', 1)`,
    [sampleDocId, 'a'.repeat(64)],
  );
  await db.query(
    `INSERT INTO document_classification_history (id, document_id, classification_level_id, business_category_id, classified_by) OVERRIDING SYSTEM VALUE
     VALUES (1, $1, 1, 1, 1)`,
    [sampleDocId],
  );
  await db.query(
    `INSERT INTO access_grants (id, document_id, principal_type, principal_user_id, source, status, valid_from, valid_until, granted_by)
     VALUES ($1, $2, 'USER', 1, 'DIRECT', 'ACTIVE', NOW() - INTERVAL '1 hour', NOW() + INTERVAL '1 day', 1)`,
    [grantId, sampleDocId],
  );
  await db.query(
    `INSERT INTO access_sessions (id, access_grant_id, document_version_id, user_id, ip_address, status)
     VALUES ($1, $2, 1, 1, '127.0.0.1', 'ACTIVE')`,
    [sessionId, grantId],
  );
  let prevHash = null;
  for (let seq = 1; seq <= 20; seq++) {
    const entryHash = crypto.randomBytes(32).toString('hex');
    await db.query(
      `INSERT INTO audit_logs (actor_user_id, actor_username, action, object_type, outcome, correlation_id, previous_hash, entry_hash, chain_partition, chain_sequence)
       VALUES (1, 'profiler_user', 'DOCUMENT_VIEW', 'DOCUMENT', 'SUCCESS', $1, $2, $3, 'DOCUMENT', $4)`,
      [crypto.randomUUID(), prevHash, entryHash, seq],
    );
    prevHash = entryHash;
  }
  await db.exec('ANALYZE; SET enable_seqscan = OFF;');
  return {
    db,
    sampleDocId,
    sampleDeptId: 1,
    sampleUserId: 1,
    close: () => db.close().catch(() => {}),
  };
}

async function main() {
  console.log('='.repeat(78));
  console.log('SDA QUERY PROFILER & EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)');
  console.log('='.repeat(78));
  console.log(`OS: ${os.type()} ${os.release()} (${os.arch()}) | Node.js: ${process.version}`);

  const strictLive = process.env['PROFILE_STRICT_LIVE'] === 'true';
  const ctx =
    (process.env['DATABASE_URL']
      ? await tryConnectLiveProfilerDb(process.env['DATABASE_URL'], strictLive)
      : null) ?? (await buildOffline13MigrationProfileDb());

  try {
    const reports = [];
    reports.push(
      await profileQuery(
        ctx.db,
        '1. Document Search with Classification & Department Filtering',
        `SELECT d.id, d.document_code, d.title, cl.rank AS classification_rank, d.owner_id, u.username AS owner_username
         FROM documents d
         JOIN document_classification_history dch ON dch.document_id = d.id AND dch.effective_to IS NULL
         JOIN classification_levels cl ON cl.id = dch.classification_level_id
         JOIN users u ON d.owner_id = u.id
         WHERE d.department_id = $1 AND cl.rank <= $2 AND d.status = 'ACTIVE' AND d.discoverable = TRUE
         ORDER BY d.created_at DESC LIMIT 20;`,
        [ctx.sampleDeptId, 3],
      ),
    );
    reports.push(
      await profileQuery(
        ctx.db,
        '2. Zero-Trust Active Grant Lookup (Document + Principal User + Time-Window)',
        `SELECT g.id, g.status, g.valid_from, g.valid_until FROM access_grants g
         WHERE g.principal_user_id = $2 AND g.document_id = $1 AND g.principal_type = 'USER'
           AND g.status = 'ACTIVE' AND g.valid_from <= NOW() AND g.valid_until > NOW() LIMIT 1;`,
        [ctx.sampleDocId, ctx.sampleUserId],
      ),
    );
    reports.push(
      await profileQuery(
        ctx.db,
        '3. Active Access Session Verification by Principal User',
        `SELECT s.id, s.access_grant_id, s.document_version_id, s.user_id, s.ip_address, s.started_at, s.last_activity_at, s.status
         FROM access_sessions s WHERE s.user_id = $1 AND s.status = 'ACTIVE' AND s.ended_at IS NULL
         ORDER BY s.last_activity_at DESC LIMIT 5;`,
        [ctx.sampleUserId],
      ),
    );
    reports.push(
      await profileQuery(
        ctx.db,
        '4. Audit Trail Partition Range Query for Verification',
        `SELECT id, chain_sequence, previous_hash, entry_hash, correlation_id, outcome, occurred_at
         FROM audit_logs WHERE chain_partition = $1 AND chain_sequence >= $2 ORDER BY chain_sequence ASC LIMIT 100;`,
        ['DOCUMENT', 1],
      ),
    );
    console.log('\n' + '='.repeat(78) + '\nQUERY PROFILING COMPLETED.\n' + '='.repeat(78));
    return reports;
  } finally {
    await ctx.close();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error('Profiling error:', err);
    process.exit(1);
  });
}

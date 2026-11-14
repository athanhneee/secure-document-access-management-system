/**
 * Thuật toán: Bộ Kiểm Định Tải Đa Luồng Đồng Thời & Phân Vị Độ Trễ Thực Nghiệm (`p50`/`p95`/`p99`)
 * - Khi `API_BASE_URL` kết nối được: Thực thi kiểm thử tải HTTP đồng thời thật qua `fetch` trên `/api/v1/health/live`,
 *   `/api/v1/health/ready`, `/api/v1/documents` & `/api/v1/auth/me`, đo `p50`/`p90`/`p95`/`p99` và `RPS`.
 * - Chỉ rơi về `PGlite` ngoại tuyến khi không thể kết nối, phát lại 13 di trú Prisma thật + ký xác thực `Ed25519` (`EdDSA`).
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const apiRequire = createRequire(new URL('../apps/api/package.json', import.meta.url));
const { generateKeyPair, SignJWT, jwtVerify } = await import(
  pathToFileURL(apiRequire.resolve('jose')).href
);
const MIGRATIONS_DIR = fileURLToPath(
  new URL('../packages/database/prisma/migrations', import.meta.url),
);

const DEFAULT_CONCURRENCY = parseInt(process.env['LOAD_CONCURRENCY'] || '20', 10);
const DEFAULT_ITERATIONS = parseInt(process.env['LOAD_ITERATIONS'] || '50', 10);

/**
 * Thuật toán: Thống Kê Thứ Tự & Nội Suy Phân Vị Độ Trễ Thực Nghiệm (`min`, `mean`, `p50`, `p90`, `p95`, `p99`, `max`).
 */
function calculatePercentiles(latenciesMs) {
  if (latenciesMs.length === 0) {
    return { min: 0, mean: 0, p50: 0, p90: 0, p95: 0, p99: 0, max: 0 };
  }
  const sorted = [...latenciesMs].sort((a, b) => a - b);
  const n = sorted.length;
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  return {
    min: Math.round(sorted[0] * 100) / 100,
    mean: Math.round((sum / n) * 100) / 100,
    p50: Math.round(sorted[Math.floor(n * 0.5)] * 100) / 100,
    p90: Math.round(sorted[Math.floor(n * 0.9)] * 100) / 100,
    p95: Math.round(sorted[Math.floor(n * 0.95)] * 100) / 100,
    p99: Math.round(sorted[Math.floor(n * 0.99)] * 100) / 100,
    max: Math.round(sorted[n - 1] * 100) / 100,
  };
}

/**
 * Thuật toán: Điều Phối Hồ Công Tác Giới Hạn Đồng Thời Không Khóa (`Bounded-Concurrency Worker Pool Scheduler`).
 */
async function runScenarioPool(name, fn, totalCount, concurrency) {
  const latencies = [];
  let errors = 0;
  let cursor = 0;
  const startTime = performance.now();
  const worker = async () => {
    while (true) {
      const idx = cursor++;
      if (idx >= totalCount) break;
      const opStart = performance.now();
      try {
        await fn(idx);
        latencies.push(performance.now() - opStart);
      } catch {
        errors++;
      }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  const totalTimeSec = Math.max(0.001, (performance.now() - startTime) / 1000);
  return {
    scenario: name,
    totalOps: totalCount,
    successCount: latencies.length,
    errorCount: errors,
    errorRatePct: Math.round((errors / totalCount) * 1000) / 10,
    throughputRps: Math.round((latencies.length / totalTimeSec) * 10) / 10,
    ...calculatePercentiles(latencies),
  };
}

/**
 * Thuật toán: Xây dựng tập kịch bản HTTP đồng thời thực tế khi `API_BASE_URL` trực tuyến sẵn sàng.
 */
async function tryBuildLiveHttpScenarios(rawBaseUrl, totalOps, concurrency, strictLive) {
  const trimmed = rawBaseUrl.trim().replace(/\/+$/u, '');
  const apiV1 = trimmed.endsWith('/api/v1') ? trimmed : `${trimmed}/api/v1`;
  let liveHealthUrl = `${apiV1}/health/live`;
  try {
    const probe = await fetch(liveHealthUrl, { signal: AbortSignal.timeout(2500) });
    if (probe.status === 404) {
      liveHealthUrl = `${apiV1}/health`;
      const alt = await fetch(liveHealthUrl, { signal: AbortSignal.timeout(2500) });
      if (!alt.ok) throw new Error(`HTTP ${alt.status} on ${liveHealthUrl}`);
    } else if (!probe.ok) {
      throw new Error(`HTTP ${probe.status} on ${liveHealthUrl}`);
    }
  } catch (err) {
    const code = err?.cause?.code ?? err?.code ?? '';
    const unreachable =
      ['ECONNREFUSED', 'ENOTFOUND'].includes(code) || err?.name === 'TimeoutError';
    if (!unreachable || strictLive) throw err;
    return null;
  }

  const bearerToken = process.env['LOAD_TEST_BEARER_TOKEN']?.trim();
  const authHeaders = bearerToken ? { authorization: `Bearer ${bearerToken}` } : {};
  const readyUrl = liveHealthUrl.endsWith('/health/live') ? `${apiV1}/health/ready` : liveHealthUrl;
  const checkGet = (url, expectOk) => async () => {
    const res = await fetch(url, { headers: authHeaders, signal: AbortSignal.timeout(5000) });
    if (!(expectOk ? res.ok : res.status === 401 || res.status === 403))
      throw new Error(`Status ${res.status}`);
    await res.arrayBuffer();
  };
  return [
    {
      name: '1. Live HTTP Liveness Probe (/health/live)',
      totalOps,
      concurrency,
      execute: checkGet(liveHealthUrl, true),
    },
    {
      name: '2. Live HTTP Readiness Gate (/health/ready)',
      totalOps: Math.max(10, Math.floor(totalOps / 2)),
      concurrency,
      execute: checkGet(readyUrl, true),
    },
    {
      name: bearerToken
        ? '3. Live Auth Document Search (/documents)'
        : '3. Live Zero-Trust Guard (/documents)',
      totalOps,
      concurrency,
      execute: (idx) =>
        checkGet(`${apiV1}/documents?page=1&pageSize=10&q=doc-${idx % 20}`, Boolean(bearerToken))(),
    },
    {
      name: bearerToken
        ? '4. Live Auth Session (/auth/me)'
        : '4. Live Zero-Trust Token Guard (/auth/me)',
      totalOps,
      concurrency,
      execute: checkGet(`${apiV1}/auth/me`, Boolean(bearerToken)),
    },
  ];
}

/**
 * Thuật toán: Xây dựng kịch bản chuẩn ngoại tuyến trên 13 di trú Prisma thật + xác thực chữ ký bất đối xứng `Ed25519`.
 */
async function buildOffline13MigrationScenarios(totalOps, concurrency) {
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
    const base = path.join(pnpmStore, match, 'node_modules/@electric-sql/pglite/dist');
    [{ PGlite }, { pg_trgm }] = await Promise.all([
      import(pathToFileURL(path.join(base, 'index.js')).href),
      import(pathToFileURL(path.join(base, 'contrib/pg_trgm.js')).href),
    ]);
  }
  const db = new PGlite({ extensions: { pg_trgm } });
  const folders = fs
    .readdirSync(MIGRATIONS_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
  for (const f of folders) {
    const p = path.join(MIGRATIONS_DIR, f, 'migration.sql');
    if (fs.existsSync(p)) await db.exec(fs.readFileSync(p, 'utf8'));
  }
  await db.exec(`
    INSERT INTO departments (id, code, name) OVERRIDING SYSTEM VALUE VALUES (1, 'SEC', 'Security');
    INSERT INTO users (id, username, email, password_hash, full_name, status) OVERRIDING SYSTEM VALUE
      VALUES (1, 'bench_user', 'bench@sda.local', '$argon2id$v=19$m=19456,t=2,p=1$stub', 'Bench User', 'ACTIVE');
    INSERT INTO documents (id, document_code, title, owner_id, department_id, status, discoverable)
      VALUES ('00000000-0000-4000-8000-000000000001', 'DOC-LOAD-01', 'Zero-Trust Benchmark Asset', 1, 1, 'ACTIVE', TRUE);
  `);

  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const token = await new SignJWT({ username: 'bench_user', role: 'SECURITY_OFFICER' })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
    .setSubject('1')
    .setIssuedAt()
    .setExpirationTime('15m')
    .sign(privateKey);
  const kek = crypto.randomBytes(32);

  return {
    db,
    scenarios: [
      {
        name: '1. Ed25519 (EdDSA) JWT Signature Verification',
        totalOps,
        concurrency,
        execute: async () => {
          await jwtVerify(token, publicKey, { algorithms: ['EdDSA'] });
        },
      },
      {
        name: '2. 13-Migration ABAC Document Discovery Query',
        totalOps,
        concurrency,
        execute: async () => {
          await db.query(
            `SELECT id, document_code, title FROM documents WHERE department_id = $1 AND status = 'ACTIVE' AND discoverable = TRUE LIMIT 10`,
            [1],
          );
        },
      },
      {
        name: '3. AES-256-GCM Envelope Encrypt/Decrypt Roundtrip',
        totalOps,
        concurrency,
        execute: async () => {
          const iv = crypto.randomBytes(12);
          const dek = crypto.randomBytes(32);
          const c = crypto.createCipheriv('aes-256-gcm', kek, iv);
          const enc = Buffer.concat([c.update(dek), c.final()]);
          const d = crypto.createDecipheriv('aes-256-gcm', kek, iv, { authTagLength: 16 });
          d.setAuthTag(c.getAuthTag());
          Buffer.concat([d.update(enc), d.final()]);
        },
      },
    ],
  };
}

async function main() {
  const concurrency = parseInt(process.env['LOAD_CONCURRENCY'] || String(DEFAULT_CONCURRENCY), 10);
  const iterations = parseInt(process.env['LOAD_ITERATIONS'] || String(DEFAULT_ITERATIONS), 10);
  const totalOps = concurrency * iterations;
  console.log('='.repeat(78));
  console.log(`SDA PERFORMANCE & LOAD TEST HARNESS | Concurrency=${concurrency} | Ops=${totalOps}`);
  console.log('='.repeat(78));

  const strictLive = process.env['LOAD_STRICT_LIVE'] === 'true';
  let scenarios = process.env['API_BASE_URL']
    ? await tryBuildLiveHttpScenarios(
        process.env['API_BASE_URL'],
        totalOps,
        concurrency,
        strictLive,
      )
    : null;
  let offlineDb = null;
  if (!scenarios) {
    console.log('[MODE] OFFLINE 13-MIGRATION PGLITE + Ed25519 BENCHMARK');
    const built = await buildOffline13MigrationScenarios(totalOps, concurrency);
    offlineDb = built.db;
    scenarios = built.scenarios;
  } else {
    console.log(`[MODE] LIVE CONCURRENT HTTP BENCHMARK against ${process.env['API_BASE_URL']}`);
  }

  try {
    const results = [];
    for (const s of scenarios) {
      results.push(await runScenarioPool(s.name, s.execute, s.totalOps, s.concurrency));
    }
    console.table(
      results.map((r) => ({
        Scenario: r.scenario,
        'Throughput (RPS)': r.throughputRps,
        'p50 (ms)': r.p50,
        'p95 (ms)': r.p95,
        'p99 (ms)': r.p99,
        'Errors (%)': `${r.errorRatePct}%`,
      })),
    );
    return results;
  } finally {
    if (offlineDb) await offlineDb.close().catch(() => {});
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error('Fatal load test error:', err);
    process.exit(1);
  });
}

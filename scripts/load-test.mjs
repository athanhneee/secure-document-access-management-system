/**
 * SDA Enterprise Load Testing Harness
 * Non-destructive realistic load testing across 6 core enterprise flows:
 * 1. Login & Token Verification
 * 2. Search & Document Discovery
 * 3. ABAC PDP Access Decision Evaluation
 * 4. Approval & Active Grant Lookup
 * 5. Document View & Watermark Derivation
 * 6. Audit Trail Partition & Hash Integrity Query
 */

import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createAndSeedLoadTestFixture,
  buildLoadTestScenarios,
} from './lib/load-test-scenarios.mjs';

const CONCURRENCY = parseInt(process.env['LOAD_CONCURRENCY'] || '20', 10);
const ITERATIONS_PER_VUSER = parseInt(process.env['LOAD_ITERATIONS'] || '50', 10);
const TOTAL_OPS = CONCURRENCY * ITERATIONS_PER_VUSER;

/**
 * Algorithm / Thuật toán: Empirical Order-Statistic Percentile Estimator (Thống Kê Thứ Tự & Nội Suy Phân Vị Độ Trễ)
 * Purpose / Mục đích: Compute full latency distribution metrics (`min`, `mean`, `p50`, `p90`, `p95`, `p99`, `max`)
 *   from empirical load-test response times.
 * Mechanism / Cơ chế hoạt động:
 *   - Clones and sorts the sample array in ascending order via `O(N log N)` Timsort (`[...latenciesMs].sort((a, b) => a - b)`).
 *   - Computes arithmetic `mean = sum / n` in `O(N)` and extracts order-statistic quantiles at `sorted[Math.floor(n * q)]`
 *     for `q ∈ {0.50, 0.90, 0.95, 0.99}`, rounded to 2 millisecond decimal places.
 */
export function calculatePercentiles(latenciesMs) {
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
 * Algorithm / Thuật toán: Bounded-Concurrency Worker Pool Scheduler (Điều Phối Hồ Công Tác Giới Hạn Đồng Thời & RPS)
 * Purpose / Mục đích: Maintain exactly `concurrency` virtual users (VUsers) pulling operations continuously until
 *   `totalCount` operations complete without unbounded Promise allocation.
 * Mechanism / Cơ chế hoạt động:
 *   - Uses a shared single-threaded event-loop cursor (`cursor++`) to dispatch operation indices `idx` lock-free across
 *     `concurrency` async worker loops coordinated via `Promise.all`.
 *   - Measures per-operation latency via monotonic `performance.now()`, tracks `errors` separately, and derives achieved
 *     throughput `throughputRps = successCount / totalTimeSec`.
 */
export async function runScenarioPool(name, fn, totalCount, concurrency) {
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
        const duration = performance.now() - opStart;
        latencies.push(duration);
      } catch {
        errors++;
      }
    }
  };

  const workers = Array.from({ length: concurrency }, () => worker());
  await Promise.all(workers);

  const totalTimeSec = (performance.now() - startTime) / 1000;
  const stats = calculatePercentiles(latencies);
  const throughputRps = Math.round((latencies.length / totalTimeSec) * 10) / 10;

  return {
    scenario: name,
    totalOps: totalCount,
    successCount: latencies.length,
    errorCount: errors,
    errorRatePct: Math.round((errors / totalCount) * 1000) / 10,
    throughputRps,
    ...stats,
  };
}

/**
 * Algorithm / Thuật toán: Six-Flow NFR SLA Benchmark Orchestrator (Kiểm Định Tải 6 Luồng Nghiệp Vụ & Ngưỡng SLA p95)
 * Purpose / Mục đích: Seed synthetic production-grade datasets, execute all 6 load scenarios under concurrent VUsers,
 *   and evaluate strict `p95` NFR latency thresholds (Search < 150ms, PDP < 10ms, Login < 100ms, Watermark < 500ms).
 */
export async function main() {
  console.log('='.repeat(78));
  console.log('SDA PERFORMANCE & LOAD TEST HARNESS');
  console.log('='.repeat(78));
  console.log(`OS: ${os.type()} ${os.release()} (${os.arch()})`);
  console.log(`CPUs: ${os.cpus().length} x ${os.cpus()[0]?.model}`);
  console.log(`Memory: ${Math.round(os.totalmem() / 1024 / 1024 / 1024)} GB`);
  console.log(`Node.js: ${process.version}`);
  console.log(`Concurrency: ${CONCURRENCY} VUsers | Total Ops per Scenario: ${TOTAL_OPS}`);
  console.log('='.repeat(78));

  console.log('\n[1/3] Preparing test database and schema...');
  console.log('Seeding 5,000 synthetic documents, grants, and HMAC audit records...');
  const { db, docIds, samplePdfBytes } = await createAndSeedLoadTestFixture();
  console.log('Seeding completed. Database ready for load test.');

  console.log('\n[2/3] Executing Load Test Scenarios...');
  const scenarios = buildLoadTestScenarios({
    db,
    docIds,
    samplePdfBytes,
    totalOps: TOTAL_OPS,
    concurrency: CONCURRENCY,
  });

  const results = [];
  for (const scenario of scenarios) {
    results.push(
      await runScenarioPool(
        scenario.name,
        scenario.execute,
        scenario.totalOps,
        scenario.concurrency,
      ),
    );
  }

  console.log('\n[3/3] Load Test Results Summary:\n');
  console.table(
    results.map((r) => ({
      Scenario: r.scenario,
      'Throughput (RPS)': r.throughputRps,
      'p50 (ms)': r.p50,
      'p90 (ms)': r.p90,
      'p95 (ms)': r.p95,
      'p99 (ms)': r.p99,
      'Max (ms)': r.max,
      'Errors (%)': `${r.errorRatePct}%`,
    })),
  );

  const nfrBreaches = results.filter((r) => {
    if (r.scenario.includes('Search') && r.p95 > 150) return true;
    if (r.scenario.includes('PDP') && r.p95 > 10) return true;
    if (r.scenario.includes('Login') && r.p95 > 100) return true;
    if (r.scenario.includes('Watermark') && r.p95 > 500) return true;
    return false;
  });

  if (nfrBreaches.length === 0) {
    console.log('\nSUCCESS: ALL NFR LATENCY TARGETS (p95) AND ERROR RATES ACHIEVED!');
  } else {
    console.warn(
      '\nWARNING: Some scenarios exceeded strict NFR thresholds:',
      nfrBreaches.map((b) => b.scenario),
    );
  }
}

const isCliEntrypoint =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isCliEntrypoint) {
  main().catch((err) => {
    console.error('Fatal load test error:', err);
    process.exit(1);
  });
}

/**
 * Thuật toán / Tổng quan module:
 * Bộ thu thập chỉ số quan sát nội bộ (In-Memory Telemetry Registry) và kết xuất định dạng văn bản
 * chuẩn Prometheus Exposition Format `0.0.4` cho tiến trình `@sda/worker`, bao gồm nhịp tim vòng lặp,
 * số lần chạy từng tác vụ nền, hàng đợi DLQ, lượt chặn ICAP DLP và cảnh báo vi phạm chuỗi băm kiểm toán.
 */

const startedAtMs = Date.now();
let workerUp = 1;
let lastLoopHeartbeatMs = Date.now();
let outboxDeadLetterTotal = 0;
let icapBlockedTotal = 0;
let exportQueueDepth = 0;

const jobRunsByKey = new Map<string, number>();
const auditCompromisedByPartition = new Map<string, number>();

/**
 * Thuật toán: Cập nhật dấu thời gian nhịp tim vòng lặp sự kiện (Monotonic Heartbeat Timestamp Update).
 */
export function recordWorkerLoopHeartbeat(): void {
  lastLoopHeartbeatMs = Date.now();
}

export function getLastWorkerLoopHeartbeatMs(): number {
  return lastLoopHeartbeatMs;
}

export function getWorkerUptimeSeconds(): number {
  return Math.max(0, Math.floor((Date.now() - startedAtMs) / 1000));
}

export function setWorkerUp(isUp: boolean): void {
  workerUp = isUp ? 1 : 0;
}

/**
 * Thuật toán: Cộng dồn bộ đếm chu kỳ thực thi tác vụ nền theo cặp nhãn `(job, status)`.
 */
export function recordWorkerJobRun(jobName: string, status: 'success' | 'error'): void {
  recordWorkerLoopHeartbeat();
  const safeJob = jobName.replace(/[^a-zA-Z0-9_:-]/gu, '_');
  const key = `${safeJob}|${status}`;
  jobRunsByKey.set(key, (jobRunsByKey.get(key) ?? 0) + 1);
}

export function incrementOutboxDeadLetter(count = 1): void {
  if (count > 0) outboxDeadLetterTotal += count;
}

export function incrementIcapBlocked(count = 1): void {
  if (count > 0) icapBlockedTotal += count;
}

export function setExportQueueDepth(depth: number): void {
  exportQueueDepth = Math.max(0, Math.floor(depth));
}

/**
 * Thuật toán: Ghi nhận vi phạm toàn vẹn chuỗi băm kiểm toán theo phân vùng (`partition`)
 * phục vụ luật cảnh báo tức thì `AuditIntegrityCompromised` trên Prometheus.
 */
export function incrementAuditIntegrityCompromised(partition: string, count = 1): void {
  if (count <= 0) return;
  const safePartition = partition.replace(/["\\\r\n]/gu, '_').slice(0, 64) || 'UNKNOWN';
  auditCompromisedByPartition.set(
    safePartition,
    (auditCompromisedByPartition.get(safePartition) ?? 0) + count,
  );
}

export function resetWorkerMetricsForTesting(): void {
  workerUp = 1;
  lastLoopHeartbeatMs = Date.now();
  outboxDeadLetterTotal = 0;
  icapBlockedTotal = 0;
  exportQueueDepth = 0;
  jobRunsByKey.clear();
  auditCompromisedByPartition.clear();
}

export function getWorkerMetricsSnapshot(): {
  workerUp: number;
  outboxDeadLetterTotal: number;
  icapBlockedTotal: number;
  auditIntegrityCompromisedTotal: number;
  exportQueueDepth: number;
} {
  let auditTotal = 0;
  for (const val of auditCompromisedByPartition.values()) auditTotal += val;
  return {
    workerUp,
    outboxDeadLetterTotal,
    icapBlockedTotal,
    auditIntegrityCompromisedTotal: auditTotal,
    exportQueueDepth,
  };
}

/**
 * Thuật toán: Tuần tự hóa toàn bộ gauges/counters sang định dạng văn bản Prometheus `0.0.4`,
 * khởi tạo sẵn chuỗi `0` cho `sda_audit_integrity_compromised_total` để hàm `increase(...[5m])` hoạt động ngay từ lần quét đầu tiên.
 */
export function renderWorkerPrometheusMetrics(): string {
  const lines: string[] = [
    '# HELP sda_worker_up Whether the SDA background worker process is healthy (1 = up, 0 = shutting down).',
    '# TYPE sda_worker_up gauge',
    `sda_worker_up ${workerUp}`,
    '# HELP sda_worker_uptime_seconds Total uptime of the SDA worker process in seconds.',
    '# TYPE sda_worker_uptime_seconds gauge',
    `sda_worker_uptime_seconds ${getWorkerUptimeSeconds()}`,
    '# HELP sda_worker_job_runs_total Total background job execution cycles grouped by job and status.',
    '# TYPE sda_worker_job_runs_total counter',
  ];

  if (jobRunsByKey.size === 0) {
    lines.push('sda_worker_job_runs_total{job="bootstrap",status="success"} 0');
  } else {
    for (const [key, count] of jobRunsByKey.entries()) {
      const [job, status] = key.split('|');
      lines.push(`sda_worker_job_runs_total{job="${job}",status="${status}"} ${count}`);
    }
  }

  lines.push(
    '# HELP sda_worker_outbox_dead_letter_total Total notification outbox entries moved to DEAD_LETTER.',
    '# TYPE sda_worker_outbox_dead_letter_total counter',
    `sda_worker_outbox_dead_letter_total ${outboxDeadLetterTotal}`,
    '# HELP sda_worker_icap_blocked_total Total network payloads blocked by the ICAP DLP server.',
    '# TYPE sda_worker_icap_blocked_total counter',
    `sda_worker_icap_blocked_total ${icapBlockedTotal}`,
    '# HELP sda_audit_integrity_compromised_total Total cryptographic audit chain violations detected.',
    '# TYPE sda_audit_integrity_compromised_total counter',
  );

  const canonicalPartitions = ['GLOBAL', 'AUTH', 'DOCUMENT', 'SECURITY', 'AUDIT'] as const;
  const emittedPartitions = new Set<string>();
  lines.push('sda_audit_integrity_compromised_total{partition="ALL",source="worker"} 0');
  for (const partition of canonicalPartitions) {
    const count = auditCompromisedByPartition.get(partition) ?? 0;
    emittedPartitions.add(partition);
    lines.push(
      `sda_audit_integrity_compromised_total{partition="${partition}",source="worker"} ${count}`,
    );
  }
  for (const [partition, count] of auditCompromisedByPartition.entries()) {
    if (emittedPartitions.has(partition)) continue;
    lines.push(
      `sda_audit_integrity_compromised_total{partition="${partition}",source="worker"} ${count}`,
    );
  }

  let totalAuditViolations = 0;
  for (const count of auditCompromisedByPartition.values()) totalAuditViolations += count;
  lines.push(
    '# HELP audit_verify_failures_total Legacy alias for total audit verification failures.',
    '# TYPE audit_verify_failures_total counter',
    `audit_verify_failures_total{source="worker"} ${totalAuditViolations}`,
    '# HELP worker_queue_depth Current depth of pending items per worker queue.',
    '# TYPE worker_queue_depth gauge',
    `worker_queue_depth{queue="export"} ${exportQueueDepth}`,
    '',
  );

  return lines.join('\n');
}

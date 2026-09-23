import { Injectable } from '@nestjs/common';

/**
 * Strict Low-Cardinality Label Policy:
 * Under NO circumstances should high-cardinality identifiers (UUIDs, user emails, document titles,
 * tokens, session IDs, passwords, IPs) be emitted as metric labels.
 */

interface MetricLabels {
  [key: string]: string | number;
}

interface HistogramData {
  buckets: number[];
  bucketCounts: Map<string, number[]>; // labelKey -> counts array
  sums: Map<string, number>;
  counts: Map<string, number>;
}

const DEFAULT_HTTP_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];
const DEFAULT_PDP_BUCKETS = [0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25];
const DEFAULT_SCAN_BUCKETS = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5];
const DEFAULT_WATERMARK_BUCKETS = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5];
const DEFAULT_REVOKE_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5];

// Deny-list for label keys
const DISALLOWED_LABEL_KEYS = new Set([
  'document_title',
  'title',
  'user_email',
  'email',
  'token',
  'session_id',
  'password',
  'secret',
  'jwt',
  'ip',
  'user_id',
  'document_id',
]);

@Injectable()
export class MetricsService {
  private static instance: MetricsService;

  // Counters: metricName -> Map<labelKey, value>
  private readonly counters = new Map<string, Map<string, number>>();
  // Gauges: metricName -> Map<labelKey, value>
  private readonly gauges = new Map<string, Map<string, number>>();
  // Histograms: metricName -> HistogramData
  private readonly histograms = new Map<string, HistogramData>();

  constructor() {
    this.initDefaultHistograms();
    MetricsService.instance = this;
  }

  static getInstance(): MetricsService {
    if (!this.instance) {
      this.instance = new MetricsService();
    }
    return this.instance;
  }

  private initDefaultHistograms(): void {
    this.registerHistogram('http_request_duration_seconds', DEFAULT_HTTP_BUCKETS);
    this.registerHistogram('pdp_evaluation_duration_seconds', DEFAULT_PDP_BUCKETS);
    this.registerHistogram('antivirus_scan_duration_seconds', DEFAULT_SCAN_BUCKETS);
    this.registerHistogram('watermark_render_duration_seconds', DEFAULT_WATERMARK_BUCKETS);
    this.registerHistogram('grant_revocation_duration_seconds', DEFAULT_REVOKE_BUCKETS);
    this.registerHistogram(
      'database_query_duration_seconds',
      [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1],
    );
    this.registerHistogram(
      'redis_command_duration_seconds',
      [0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05],
    );
  }

  private registerHistogram(name: string, buckets: number[]): void {
    this.histograms.set(name, {
      buckets: [...buckets].sort((a, b) => a - b),
      bucketCounts: new Map(),
      sums: new Map(),
      counts: new Map(),
    });
  }

  // Sanitizes route path to eliminate high-cardinality values like UUIDs or IDs
  static sanitizeRoute(path: string): string {
    if (!path) return 'unknown';
    // Remove query string
    const cleanPath = path.split('?')[0] || '/';

    return (
      cleanPath
        // Replace UUIDs
        .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, ':id')
        // Replace watermark tokens
        .replace(/WM-[0-9a-fA-F]+/g, ':token')
        // Replace numeric segments
        .replace(/\/\d+(?=\/|$)/g, '/:id')
        // Replace long hex/hash strings (16+ chars)
        .replace(/\/[0-9a-f]{16,}(?=\/|$)/gi, '/:hash')
    );
  }

  // Sanitizes labels and formats label string: key1="val1",key2="val2"
  private serializeLabels(labels: MetricLabels = {}): string {
    const entries = Object.entries(labels)
      .filter(([k]) => !DISALLOWED_LABEL_KEYS.has(k.toLowerCase()))
      .map(([k, v]) => {
        const valStr = String(v)
          .slice(0, 64)
          .replace(/\\/g, '\\\\')
          .replace(/"/g, '\\"')
          .replace(/\n/g, '');
        return `${k}="${valStr}"`;
      })
      .sort();

    return entries.join(',');
  }

  // 1. Counter increment
  incrementCounter(name: string, labels: MetricLabels = {}, value = 1): void {
    if (value <= 0) return;
    let labelMap = this.counters.get(name);
    if (!labelMap) {
      labelMap = new Map();
      this.counters.set(name, labelMap);
    }
    const key = this.serializeLabels(labels);
    labelMap.set(key, (labelMap.get(key) ?? 0) + value);
  }

  // 2. Gauge set
  setGauge(name: string, value: number, labels: MetricLabels = {}): void {
    let labelMap = this.gauges.get(name);
    if (!labelMap) {
      labelMap = new Map();
      this.gauges.set(name, labelMap);
    }
    const key = this.serializeLabels(labels);
    labelMap.set(key, value);
  }

  // 3. Histogram observe
  observeHistogram(name: string, valueSeconds: number, labels: MetricLabels = {}): void {
    let histo = this.histograms.get(name);
    if (!histo) {
      this.registerHistogram(name, DEFAULT_HTTP_BUCKETS);
      histo = this.histograms.get(name)!;
    }

    const key = this.serializeLabels(labels);
    const count = (histo.counts.get(key) ?? 0) + 1;
    const sum = (histo.sums.get(key) ?? 0) + Math.max(0, valueSeconds);

    histo.counts.set(key, count);
    histo.sums.set(key, sum);

    let bucketCounts = histo.bucketCounts.get(key);
    if (!bucketCounts) {
      bucketCounts = new Array(histo.buckets.length).fill(0);
      histo.bucketCounts.set(key, bucketCounts);
    }

    for (let i = 0; i < histo.buckets.length; i++) {
      if (valueSeconds <= histo.buckets[i]!) {
        bucketCounts[i]! += 1;
      }
    }
  }

  // Domain-specific metric helper methods:
  recordHttpRequest(
    method: string,
    rawRoute: string,
    statusCode: number,
    durationSeconds: number,
  ): void {
    const route = MetricsService.sanitizeRoute(rawRoute);
    const labels = {
      method: method.toUpperCase(),
      route,
      status_code: String(statusCode),
    };
    this.incrementCounter('http_requests_total', labels);
    this.observeHistogram('http_request_duration_seconds', durationSeconds, labels);

    if (statusCode >= 400) {
      this.incrementCounter('http_request_errors_total', labels);
    }
  }

  recordPdpEvaluation(decision: 'PERMIT' | 'DENY', durationSeconds: number, cached: boolean): void {
    this.incrementCounter('pdp_evaluations_total', { decision, cached: String(cached) });
    this.observeHistogram('pdp_evaluation_duration_seconds', durationSeconds, { decision });
  }

  recordDocumentUpload(bytes: number, rawExtension: string): void {
    const ext = rawExtension.replace(/^\./, '').toLowerCase().slice(0, 10) || 'unknown';
    this.incrementCounter('document_upload_bytes_total', { extension: ext }, bytes);
  }

  recordAntivirusScan(result: 'CLEAN' | 'INFECTED' | 'ERROR', durationSeconds: number): void {
    this.observeHistogram('antivirus_scan_duration_seconds', durationSeconds, { result });
  }

  recordWatermarkRender(durationSeconds: number, success: boolean, failureReason?: string): void {
    this.observeHistogram('watermark_render_duration_seconds', durationSeconds, {
      status: success ? 'success' : 'failure',
    });
    if (!success) {
      this.incrementCounter('watermark_failures_total', {
        reason: (failureReason || 'unknown').slice(0, 32),
      });
    }
  }

  recordGrantRevocation(durationSeconds: number, success: boolean): void {
    this.observeHistogram('grant_revocation_duration_seconds', durationSeconds, {
      status: success ? 'success' : 'failure',
    });
  }

  setActiveSessions(count: number): void {
    this.setGauge('active_access_sessions', Math.max(0, count));
  }

  setQueueDepth(queue: string, depth: number): void {
    this.setGauge('worker_queue_depth', Math.max(0, depth), { queue: queue.slice(0, 32) });
  }

  recordSecurityAlert(severity: string, rule: string): void {
    this.incrementCounter('security_alerts_total', {
      severity: severity.toUpperCase().slice(0, 16),
      rule: rule.toLowerCase().slice(0, 32),
    });
  }

  recordAuditVerifyFailure(partition: string): void {
    this.incrementCounter('audit_verify_failures_total', {
      partition: partition.toUpperCase().slice(0, 32),
    });
  }

  /**
   * Generates Prometheus exposition format output (v0.0.4 text format).
   */
  exportPrometheusText(): string {
    const lines: string[] = [];

    // 1. Export Counters
    for (const [name, labelMap] of this.counters.entries()) {
      lines.push(`# HELP ${name} Total count of ${name}`);
      lines.push(`# TYPE ${name} counter`);
      for (const [labels, val] of labelMap.entries()) {
        const labelPart = labels.length > 0 ? `{${labels}}` : '';
        lines.push(`${name}${labelPart} ${val}`);
      }
    }

    // 2. Export Gauges
    for (const [name, labelMap] of this.gauges.entries()) {
      lines.push(`# HELP ${name} Current value of ${name}`);
      lines.push(`# TYPE ${name} gauge`);
      for (const [labels, val] of labelMap.entries()) {
        const labelPart = labels.length > 0 ? `{${labels}}` : '';
        lines.push(`${name}${labelPart} ${val}`);
      }
    }

    // 3. Export Histograms
    for (const [name, histo] of this.histograms.entries()) {
      lines.push(`# HELP ${name} Latency histogram of ${name}`);
      lines.push(`# TYPE ${name} histogram`);

      for (const [labelKey] of histo.counts.entries()) {
        const count = histo.counts.get(labelKey) ?? 0;
        const sum = histo.sums.get(labelKey) ?? 0;
        const bucketCounts = histo.bucketCounts.get(labelKey) ?? [];

        let cumulative = 0;
        for (let i = 0; i < histo.buckets.length; i++) {
          cumulative += bucketCounts[i] ?? 0;
          const le = histo.buckets[i];
          const labelPrefix = labelKey.length > 0 ? `${labelKey},` : '';
          lines.push(`${name}_bucket{${labelPrefix}le="${le}"} ${cumulative}`);
        }
        const labelPrefix = labelKey.length > 0 ? `${labelKey},` : '';
        lines.push(`${name}_bucket{${labelPrefix}le="+Inf"} ${count}`);
        lines.push(`${name}_sum{${labelKey ? `${labelKey}` : ''}} ${sum}`);
        lines.push(`${name}_count{${labelKey ? `${labelKey}` : ''}} ${count}`);
      }
    }

    return lines.join('\n') + '\n';
  }
}

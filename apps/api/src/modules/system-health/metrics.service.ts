/**
 * Module: MetricsService — Bộ thu thập chỉ số đo lường hiệu năng & an ninh chuẩn Prometheus trong bộ nhớ (In-Memory Prometheus Telemetry Registry).
 *
 * Thuật toán tổng thể:
 *   - Quản lý 3 cấu trúc dữ liệu chỉ số cốt lõi: Bộ đếm đơn điệu tăng (`Counter`), Đồng hồ đo tức thời (`Gauge`) và Biểu đồ tần suất độ trễ phân nhóm (`Histogram`).
 *   - Mọi tổ hợp nhãn (`MetricLabels`) đều được chuẩn hóa từ điển và lọc bỏ khóa định danh phân tán cao (UUID, email, IP, phiên) để chống bùng nổ tổ hợp chuỗi thời gian (Cardinality Explosion).
 */
import { Injectable } from '@nestjs/common';
import {
  sanitizeMetricRoute,
  serializeMetricLabels,
  serializePrometheusText,
  type HistogramData,
  type MetricLabels,
} from './prometheus-exporter.helper.js';

export type { HistogramData, MetricLabels };

const DEFAULT_HTTP_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];
const DEFAULT_PDP_BUCKETS = [0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25];
const DEFAULT_SCAN_BUCKETS = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5];
const DEFAULT_WATERMARK_BUCKETS = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5];
const DEFAULT_REVOKE_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5];

@Injectable()
export class MetricsService {
  private static instance: MetricsService;

  // shortcut: ~2,000 UUID-scrubbed metric label series (<2 MB) per process, scrape per-pod /metrics or push via OTLP Collector
  private readonly counters = new Map<string, Map<string, number>>();
  private readonly gauges = new Map<string, Map<string, number>>();
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

  /**
   * Thuật toán: Khởi tạo cấu trúc Histogram với ranh giới nhóm sắp xếp tăng dần (Sorted-Boundary Histogram Initialization)
   * Mục đích: Đảm bảo mảng ngưỡng trên `buckets` luôn đơn điệu tăng (`le_0 <= le_1 <= ...`) trước khi ghi nhận mẫu độ trễ.
   * Cơ chế hoạt động:
   *   - Sao chép và sắp xếp số học `buckets` theo thứ tự tăng dần `O(B log B)`, khởi tạo các bảng băm rỗng cho `bucketCounts`, `sums` và `counts` theo khóa nhãn chuẩn hóa.
   */
  private registerHistogram(name: string, buckets: number[]): void {
    this.histograms.set(name, {
      buckets: [...buckets].sort((a, b) => a - b),
      bucketCounts: new Map(),
      sums: new Map(),
      counts: new Map(),
    });
  }

  static sanitizeRoute(path: string): string {
    return sanitizeMetricRoute(path);
  }

  /**
   * Thuật toán: Tích lũy bộ đếm đơn điệu theo khóa nhãn chuẩn hóa (Monotonic Counter Accumulation by Canonical Label Key)
   * Mục đích: Đếm tổng số sự kiện (HTTP requests, quyết định PDP, cảnh báo an ninh, lỗi kiểm toán) bảo toàn tính đơn điệu không giảm.
   * Cơ chế hoạt động:
   *   - Bỏ qua các giá trị không dương (`value <= 0`), tuần tự hóa tập nhãn qua `serializeMetricLabels` làm khóa tra cứu `O(1)` và cộng dồn `current + value`.
   *
   * Algorithm: Monotonic Counter Accumulation by Canonical Label Key.
   */
  incrementCounter(name: string, labels: MetricLabels = {}, value = 1): void {
    if (value <= 0) return;
    let labelMap = this.counters.get(name);
    if (!labelMap) {
      labelMap = new Map();
      this.counters.set(name, labelMap);
    }
    const key = serializeMetricLabels(labels);
    labelMap.set(key, (labelMap.get(key) ?? 0) + value);
  }

  /**
   * Thuật toán: Gán giá trị tức thời Gauge theo khóa nhãn chuẩn hóa (Instantaneous Gauge Assignment)
   * Mục đích: Phản ánh số lượng tài nguyên biến thiên tăng/giảm tại thời điểm lấy mẫu (số phiên truy cập đang mở, độ sâu hàng đợi xuất báo cáo).
   * Cơ chế hoạt động:
   *   - Ánh xạ tập nhãn về chuỗi khóa chuẩn hóa `key` và ghi đè trực tiếp giá trị hiện hành trong `Map` `O(1)`.
   *
   * Algorithm: Instantaneous Gauge Assignment by Canonical Label Key.
   */
  setGauge(name: string, value: number, labels: MetricLabels = {}): void {
    let labelMap = this.gauges.get(name);
    if (!labelMap) {
      labelMap = new Map();
      this.gauges.set(name, labelMap);
    }
    const key = serializeMetricLabels(labels);
    labelMap.set(key, value);
  }

  /**
   * Thuật toán: Ghi nhận mẫu quan sát vào các nhóm ngưỡng trên Histogram (Upper-Bound `le` Bucket Histogram Observation)
   * Mục đích: Phân bổ thời gian thực thi (tính bằng giây) vào các ranh giới độ trễ định sẵn để ước lượng phân vị (p50, p95, p99) trên Prometheus.
   * Cơ chế hoạt động:
   *   - Tự động khởi tạo histogram với `DEFAULT_HTTP_BUCKETS` nếu tên chỉ số chưa đăng ký.
   *   - Tăng tổng số mẫu `counts` thêm 1, cộng dồn tổng thời gian không âm `Math.max(0, valueSeconds)` vào `sums`, và duyệt các ranh giới `buckets[i]` để tăng bộ đếm tại các ô thỏa `valueSeconds <= buckets[i]`.
   *
   * Algorithm: Non-Cumulative Bucket Histogram Observation.
   * Updates observation count, clamped non-negative sum, and matching bucket slot;
   * cumulative summation is deferred to scrape serialization time.
   */
  observeHistogram(name: string, valueSeconds: number, labels: MetricLabels = {}): void {
    let histo = this.histograms.get(name);
    if (!histo) {
      this.registerHistogram(name, DEFAULT_HTTP_BUCKETS);
      histo = this.histograms.get(name)!;
    }

    const key = serializeMetricLabels(labels);
    histo.counts.set(key, (histo.counts.get(key) ?? 0) + 1);
    histo.sums.set(key, (histo.sums.get(key) ?? 0) + Math.max(0, valueSeconds));

    let bucketCounts = histo.bucketCounts.get(key);
    if (!bucketCounts) {
      bucketCounts = new Array(histo.buckets.length).fill(0);
      histo.bucketCounts.set(key, bucketCounts);
    }

    for (let i = 0; i < histo.buckets.length; i++) {
      if (valueSeconds <= histo.buckets[i]!) {
        bucketCounts[i]! += 1;
        break;
      }
    }
  }

  /**
   * Thuật toán: Ghi nhận tổ hợp chỉ số RED (Rate, Errors, Duration) cho yêu cầu HTTP
   * Mục đích: Đồng thời cập nhật lưu lượng truy cập, phân phối độ trễ và tỷ lệ lỗi HTTP (`statusCode >= 400`) với đường dẫn đã khử tham số động.
   * Cơ chế hoạt động:
   *   - Làm sạch `rawRoute` qua `MetricsService.sanitizeRoute`, tăng `http_requests_total`, đẩy `durationSeconds` vào `http_request_duration_seconds` và tăng `http_request_errors_total` nếu mã phản hồi >= 400.
   */
  recordHttpRequest(
    method: string,
    rawRoute: string,
    statusCode: number,
    durationSeconds: number,
  ): void {
    const labels = {
      method: method.toUpperCase(),
      route: MetricsService.sanitizeRoute(rawRoute),
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
   * Thuật toán: Xuất bản toàn bộ kho chỉ số sang định dạng văn bản Prometheus Exposition v0.0.4
   * Mục đích: Kết xuất chuỗi văn bản chuẩn `# HELP` / `# TYPE` kèm chuỗi thời gian tích lũy `+Inf` cho trình thu thập Prometheus scraper.
   * Cơ chế hoạt động:
   *   - Ủy quyền cho `serializePrometheusText` duyệt qua 3 tập `counters`, `gauges`, `histograms` và định dạng kết quả.
   */
  exportPrometheusText(): string {
    return serializePrometheusText(this.counters, this.gauges, this.histograms);
  }
}

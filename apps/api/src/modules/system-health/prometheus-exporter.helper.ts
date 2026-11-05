/**
 * Module: PrometheusExporterHelper — Khử định danh đường dẫn động, chuẩn hóa nhãn độ phân tán thấp (Low-Cardinality Labels) và tuần tự hóa định dạng văn bản Prometheus v0.0.4.
 *
 * Strict Low-Cardinality Label Policy:
 * Under NO circumstances should high-cardinality identifiers (UUIDs, user emails, document titles,
 * tokens, session IDs, passwords, IPs) be emitted as metric labels.
 */

export interface MetricLabels {
  [key: string]: string | number;
}

export interface HistogramData {
  buckets: number[];
  bucketCounts: Map<string, number[]>;
  sums: Map<string, number>;
  counts: Map<string, number>;
}

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

/**
 * Thuật toán: Chuẩn hóa đường dẫn HTTP chống bùng nổ nhãn (High-Cardinality Route Path Sanitization)
 * Mục đích: Gom các URL chứa tham số động (UUID, mã thủy vân `WM-...`, vé tải `DT-...`, số nguyên ID, chuỗi băm hex) về mẫu route cố định.
 * Cơ chế hoạt động:
 *   - Cắt bỏ chuỗi truy vấn sau dấu `?` và áp dụng chuỗi biểu thức chính quy thay thế lần lượt UUID -> `:id`, token thủy vân -> `:token`, vé tải -> `:ticket`, phân đoạn số -> `/:id` và chuỗi hex >= 16 ký tự -> `/:hash`.
 *
 * Algorithm: High-Cardinality Route Path Sanitization.
 * Strips query parameters and normalizes UUIDs, forensic watermark/download tokens,
 * numeric path segments, and long hex hashes into bounded route placeholders.
 */
export function sanitizeMetricRoute(path: string): string {
  if (!path) return 'unknown';
  const cleanPath = path.split('?')[0] || '/';

  return cleanPath
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, ':id')
    .replace(/WM-[0-9a-fA-F]+/g, ':token')
    .replace(/DT-[0-9a-fA-F]+/g, ':ticket')
    .replace(/\/\d+(?=\/|$)/g, '/:id')
    .replace(/\/[0-9a-f]{16,}(?=\/|$)/gi, '/:hash');
}

/**
 * Thuật toán: Tuần tự hóa tập nhãn chuẩn hóa có lọc danh sách cấm (Canonical Low-Cardinality Label Serialization)
 * Mục đích: Đảm bảo cùng một tập nhãn luôn sinh ra duy nhất một khóa chuỗi bất kể thứ tự truyền thuộc tính, đồng thời chặn rò rỉ PII lên hệ thống giám sát.
 * Cơ chế hoạt động:
 *   - Loại bỏ mọi khóa nằm trong `DISALLOWED_LABEL_KEYS`, cắt giá trị tối đa 64 ký tự, thoát ký tự đặc biệt (`\`, `"`, `\n`), sắp xếp từ điển `sort()` và nối bằng dấu phẩy.
 *
 * Algorithm: Canonical Low-Cardinality Label Serialization.
 * Drops deny-listed PII/high-cardinality keys, escapes quotes/slashes/newlines,
 * truncates values to 64 chars, and sorts `key="val"` pairs lexicographically.
 */
export function serializeMetricLabels(labels: MetricLabels = {}): string {
  return Object.entries(labels)
    .filter(([k]) => !DISALLOWED_LABEL_KEYS.has(k.toLowerCase()))
    .map(([k, v]) => {
      const valStr = String(v)
        .slice(0, 64)
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/\n/g, '');
      return `${k}="${valStr}"`;
    })
    .sort()
    .join(',');
}

/**
 * Thuật toán: Kết xuất văn bản Prometheus Exposition Format v0.0.4 kèm cộng dồn nhóm Histogram (`le` + `+Inf`)
 * Mục đích: Biến đổi trạng thái bộ nhớ của Counters, Gauges và Histograms sang định dạng chuẩn để máy chủ Prometheus thu thập.
 * Cơ chế hoạt động:
 *   - Phát dòng siêu dữ liệu `# HELP` và `# TYPE` cho từng chỉ số.
 *   - Với mỗi chuỗi nhãn của Histogram, tính tổng tích lũy `cumulative += bucketCounts[i]` qua các ngưỡng `le`, bổ sung nhóm bắt buộc `le="+Inf"` bằng tổng số mẫu `count`, tiếp theo là hai dòng `_sum` và `_count`.
 *
 * Algorithm: Prometheus Exposition v0.0.4 Text Serializer.
 * Emits HELP/TYPE headers and formats counter, gauge, and cumulative histogram bucket series
 * (`_bucket{le="..."}`, `_bucket{le="+Inf"}`, `_sum`, `_count`).
 */
export function serializePrometheusText(
  counters: ReadonlyMap<string, Map<string, number>>,
  gauges: ReadonlyMap<string, Map<string, number>>,
  histograms: ReadonlyMap<string, HistogramData>,
): string {
  const lines: string[] = [];

  for (const [name, labelMap] of counters.entries()) {
    lines.push(`# HELP ${name} Total count of ${name}`);
    lines.push(`# TYPE ${name} counter`);
    for (const [labels, val] of labelMap.entries()) {
      const labelPart = labels.length > 0 ? `{${labels}}` : '';
      lines.push(`${name}${labelPart} ${val}`);
    }
  }

  for (const [name, labelMap] of gauges.entries()) {
    lines.push(`# HELP ${name} Current value of ${name}`);
    lines.push(`# TYPE ${name} gauge`);
    for (const [labels, val] of labelMap.entries()) {
      const labelPart = labels.length > 0 ? `{${labels}}` : '';
      lines.push(`${name}${labelPart} ${val}`);
    }
  }

  for (const [name, histo] of histograms.entries()) {
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

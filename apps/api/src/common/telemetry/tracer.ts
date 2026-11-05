/**
 * Module: Bộ Truy vết Phân tán Tương thích OpenTelemetry (W3C TraceContext Distributed Tracer)
 * Thuật toán: Phân tích/lan truyền tiêu đề chuẩn W3C TraceContext (`00-traceId-spanId-flags`),
 *   lọc thuộc tính nhạy cảm trên Span và lưu trữ giới hạn theo cơ chế hàng đợi trượt FIFO.
 */
import crypto from 'node:crypto';

export interface TraceContext {
  traceId: string;
  spanId: string;
  parentSpanId?: string | undefined;
  correlationId: string;
  sampled: boolean;
}

export interface Span {
  traceId: string;
  spanId: string;
  parentSpanId?: string | undefined;
  name: string;
  startTime: number;
  endTime?: number | undefined;
  durationMs?: number | undefined;
  attributes: Record<string, string | number | boolean>;
  status: 'OK' | 'ERROR';
  errorMessage?: string | undefined;
  end: (status?: 'OK' | 'ERROR', errorMessage?: string) => void;
}

// Strict list of disallowed attribute keys to prevent sensitive data leakage
const FORBIDDEN_ATTRIBUTE_KEYS = new Set([
  'password',
  'token',
  'secret',
  'key',
  'authorization',
  'email',
  'user_email',
  'document_title',
  'title',
  'jwt',
  'session_id',
  'credential',
]);

/**
 * Lightweight, high-performance OpenTelemetry-compatible Tracer.
 * Adheres to W3C TraceContext specifications and strict data privacy.
 */
export class OpenTelemetryTracer {
  private static instance: OpenTelemetryTracer;
  // shortcut: 1,000 recent spans (~1 MB) ring buffer for diagnostics, export via OTLP/gRPC to Tempo or Jaeger above 500 req/s
  private readonly recentSpans: Span[] = [];
  private readonly maxRecentSpans = 1000;

  static getInstance(): OpenTelemetryTracer {
    if (!this.instance) {
      this.instance = new OpenTelemetryTracer();
    }
    return this.instance;
  }

  /**
   * Generates a random 32-hex character Trace ID (16 bytes).
   *
   * Thuật toán: Sinh định danh vết CSPRNG 128-bit theo chuẩn W3C TraceContext
   * Mục đích: Tạo mã `traceId` duy nhất toàn cục gồm 32 ký tự thập lục phân chữ thường.
   * Cơ chế hoạt động:
   *   - Lấy 16 byte ngẫu nhiên an toàn mật mã từ `crypto.randomBytes(16)` và mã hóa sang chuỗi hex.
   */
  generateTraceId(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Generates a random 16-hex character Span ID (8 bytes).
   *
   * Thuật toán: Sinh định danh phân đoạn CSPRNG 64-bit theo chuẩn W3C TraceContext
   * Mục đích: Tạo mã `spanId` duy nhất cho từng thao tác con gồm 16 ký tự thập lục phân.
   * Cơ chế hoạt động:
   *   - Lấy 8 byte ngẫu nhiên an toàn mật mã từ `crypto.randomBytes(8)` và mã hóa sang chuỗi hex.
   */
  generateSpanId(): string {
    return crypto.randomBytes(8).toString('hex');
  }

  /**
   * Extracts W3C traceparent (format: 00-{traceId}-{spanId}-{flags}) and correlation headers.
   *
   * Thuật toán: Giải mã & Khôi phục Ngữ cảnh Truy vết W3C TraceContext (Traceparent Context Extraction)
   * Mục đích: Liên kết yêu cầu hiện tại vào chuỗi vết phân tán từ hệ thống gọi đến hoặc khởi tạo
   *   chuỗi vết gốc mới một cách an toàn.
   * Cơ chế hoạt động:
   *   - Đọc và kiểm tra tính hợp lệ của `x-correlation-id` / `x-request-id` bằng biểu thức chính quy
   *     whitelist độ dài 1..128 ký tự để ngăn chặn tiêm ký tự điều khiển.
   *   - Đối sánh `traceparent` với biểu thức chính quy chuẩn W3C phiên bản `00`, dùng negative lookahead
   *     loại trừ `traceId` toàn số 0 (`0{32}`) và `spanId` toàn số 0 (`0{16}`), giải mã bit thấp nhất
   *     `flags & 0x01` để xác định cờ lấy mẫu `sampled`, và sinh `spanId` con mới kế thừa `parentSpanId`.
   *   - Nếu header vắng mặt hoặc sai định dạng, tự động sinh `traceId` và `spanId` gốc mới với `sampled = true`.
   */
  extractContext(headers: Record<string, string | string[] | undefined>): TraceContext {
    const rawTraceparent = headers['traceparent'];
    const traceparent = typeof rawTraceparent === 'string' ? rawTraceparent.trim() : undefined;

    const rawCorrId = headers['x-correlation-id'] ?? headers['x-request-id'];
    const trimmedCorrId = typeof rawCorrId === 'string' ? rawCorrId.trim() : undefined;
    const headerCorrId =
      trimmedCorrId && /^[a-zA-Z0-9._:-]{1,128}$/.test(trimmedCorrId) ? trimmedCorrId : undefined;

    if (traceparent) {
      const match = /^00-(?!0{32})([0-9a-f]{32})-(?!0{16})([0-9a-f]{16})-([0-9a-f]{2})$/.exec(
        traceparent,
      );
      if (match && match[1] && match[2] && match[3]) {
        const traceId = match[1];
        const parentSpanId = match[2];
        const sampled = (Number.parseInt(match[3], 16) & 0x01) === 0x01;
        return {
          traceId,
          spanId: this.generateSpanId(),
          parentSpanId,
          correlationId: headerCorrId || traceId,
          sampled,
        };
      }
    }

    const traceId = this.generateTraceId();
    return {
      traceId,
      spanId: this.generateSpanId(),
      correlationId: headerCorrId || traceId,
      sampled: true,
    };
  }

  /**
   * Injects W3C traceparent and correlation ID into outbound carrier headers.
   *
   * Thuật toán: Tiêm Ngữ cảnh Truy vết Đầu ra (W3C TraceContext Carrier Injection)
   * Mục đích: Lan truyền định danh vết và mã tương quan sang các lời gọi dịch vụ hạ nguồn.
   * Cơ chế hoạt động:
   *   - Định dạng cờ lấy mẫu thành byte hex (`01` hoặc `00`), ghép chuỗi `traceparent` chuẩn phiên bản `00`
   *     và đính kèm đồng thời `x-correlation-id` cùng `x-request-id`.
   */
  injectContext(context: TraceContext, headers: Record<string, string>): void {
    const flags = context.sampled ? '01' : '00';
    headers['traceparent'] = `00-${context.traceId}-${context.spanId}-${flags}`;
    headers['x-correlation-id'] = context.correlationId;
    headers['x-request-id'] = context.correlationId;
  }

  /**
   * Starts a new span. Attributes are sanitized to prevent sensitive data leaks.
   *
   * Thuật toán: Khởi tạo Phân đoạn Truy vết kèm Lọc Thuộc tính An toàn (Privacy-Preserving Span Lifecycle)
   * Mục đích: Đo lường thời gian thực thi của một tác vụ con mà không thu thập PII hay dữ liệu mật.
   * Cơ chế hoạt động:
   *   - Kế thừa `traceId` và gán `parentSpanId` từ ngữ cảnh cha (nếu có), bấm giờ bằng `performance.now()`.
   *   - Lọc bỏ mọi khóa thuộc `FORBIDDEN_ATTRIBUTE_KEYS` hoặc chứa từ khóa nhạy cảm, đồng thời cắt ngắn
   *     giá trị chuỗi tối đa 100 ký tự để giới hạn bộ nhớ tiêu thụ trên mỗi span.
   *   - Đóng gói closure `end()` để tính thời lượng chính xác đến 0.01ms và đẩy span hoàn tất vào bộ đệm.
   */
  startSpan(
    name: string,
    attributes: Record<string, string | number | boolean> = {},
    parentContext?: TraceContext,
  ): Span {
    const traceId = parentContext?.traceId ?? this.generateTraceId();
    const spanId = this.generateSpanId();
    const parentSpanId = parentContext?.spanId;
    const startTime = performance.now();

    // Sanitize attributes: strictly remove sensitive keys
    const sanitizedAttributes: Record<string, string | number | boolean> = {};
    for (const [key, value] of Object.entries(attributes)) {
      const lower = key.toLowerCase();
      if (
        !FORBIDDEN_ATTRIBUTE_KEYS.has(lower) &&
        !lower.includes('secret') &&
        !lower.includes('password')
      ) {
        sanitizedAttributes[key] = typeof value === 'string' ? value.slice(0, 100) : value;
      }
    }

    const span: Span = {
      traceId,
      spanId,
      parentSpanId,
      name,
      startTime,
      attributes: sanitizedAttributes,
      status: 'OK',
      end: (status: 'OK' | 'ERROR' = 'OK', errorMessage?: string) => {
        span.endTime = performance.now();
        span.durationMs = Math.round((span.endTime - span.startTime) * 100) / 100;
        span.status = status;
        if (errorMessage) {
          span.errorMessage = errorMessage.slice(0, 200);
        }
        this.recordSpan(span);
      },
    };

    return span;
  }

  /**
   * Wraps an async operation within an OpenTelemetry span.
   *
   * Thuật toán: Bao đóng Thực thi Bất đồng bộ có Truy vết Tự động (Automatic Async Span Instrumentation)
   * Mục đích: Đảm bảo mọi nhánh hoàn tất thành công hay ném ngoại lệ đều đóng Span đúng trạng thái.
   * Cơ chế hoạt động:
   *   - Mở Span trước khi gọi hàm bất đồng bộ `fn`, đánh dấu `OK` khi hoàn tất; nếu phát sinh lỗi thì
   *     thu nhận thông điệp lỗi, đóng Span với trạng thái `ERROR` rồi ném trả lại ngoại lệ gốc.
   */
  async withSpan<T>(
    name: string,
    attributes: Record<string, string | number | boolean>,
    fn: (span: Span) => Promise<T>,
    parentContext?: TraceContext,
  ): Promise<T> {
    const span = this.startSpan(name, attributes, parentContext);
    try {
      const result = await fn(span);
      span.end('OK');
      return result;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      span.end('ERROR', message);
      throw err;
    }
  }

  /**
   * Thuật toán: Bộ đệm Trượt Giới hạn Dung lượng theo Thứ tự FIFO (Bounded FIFO Span Eviction)
   * Mục đích: Lưu giữ các Span gần nhất phục vụ chẩn đoán nội bộ mà không gây rò rỉ bộ nhớ dài hạn.
   * Cơ chế hoạt động:
   *   - Khi mảng `recentSpans` đạt ngưỡng `maxRecentSpans` (1000 phần tử), loại bỏ phần tử cũ nhất
   *     ở đầu hàng đợi (`shift()`) trước khi chèn Span mới vào cuối (`push()`).
   */
  private recordSpan(span: Span): void {
    if (this.recentSpans.length >= this.maxRecentSpans) {
      this.recentSpans.shift();
    }
    this.recentSpans.push(span);
  }

  getRecentSpans(): readonly Span[] {
    return this.recentSpans;
  }
}

export const tracer = OpenTelemetryTracer.getInstance();

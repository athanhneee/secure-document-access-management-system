/**
 * Module: Đường ống Fastify Lifecycle Hooks (Truy vết phân tán, Gia cố HTTP Headers & Đo lường)
 * Thuật toán: Lọc tham số URL nhạy cảm, lan truyền ngữ cảnh W3C TraceContext, gắn tiêu đề bảo mật
 *   phòng thủ chiều sâu (Defense-in-Depth Security Headers) và ghi nhận độ trễ chuẩn hóa Cardinality thấp.
 */
import type { FastifyInstance } from 'fastify';
import { redactSensitiveData } from '../logger/redaction.js';
import { tracer, type TraceContext } from '../telemetry/tracer.js';
import { MetricsService } from '../../modules/system-health/metrics.service.js';

declare module 'fastify' {
  interface FastifyRequest {
    correlationId?: string;
    traceContext?: TraceContext;
    startTime?: number;
  }
}

const SENSITIVE_QUERY_KEYS = new Set([
  'token',
  'ticket',
  'sessionid',
  'session_id',
  'code',
  'secret',
  'password',
  'key',
  'access_token',
  'refresh_token',
]);

/**
 * Thuật toán: Phân tách và Làm sạch URL Nhật ký (URL Token & Query Parameter Sanitization)
 * Mục đích: Loại bỏ mã vé truyền tải tài liệu, mã thủy vân trên đường dẫn và các tham số truy vấn
 *   nhạy cảm trước khi ghi vào nhật ký HTTP nhằm ngăn rò rỉ thông tin xác thực qua log.
 * Cơ chế hoạt động:
 *   - Tách chuỗi URL thô tại dấu `?` đầu tiên thành hai phần độc lập: `rawPath` và `rawQuery`.
 *   - Quét biểu thức chính quy trên `rawPath` để thay thế các mã định danh động dạng hex
 *     (`DT-...` và `WM-...`) bằng nhãn che dấu cố định.
 *   - Phân tích `rawQuery` bằng `URLSearchParams`, duyệt toàn bộ khóa (không phân biệt hoa thường)
 *     đối chiếu tập `SENSITIVE_QUERY_KEYS` O(1) để ghi đè giá trị nhạy cảm thành `[REDACTED]`,
 *     sau đó tái tạo lại chuỗi URL an toàn.
 */
export function sanitizeLoggedUrl(rawUrl: string): string {
  const [rawPath = '/', rawQuery] = rawUrl.split('?', 2);
  const sanitizedPath = rawPath
    .replace(/DT-[0-9a-fA-F]+/g, 'DT-[REDACTED]')
    .replace(/WM-[0-9a-fA-F]+/g, 'WM-[REDACTED]');
  if (!rawQuery) {
    return sanitizedPath;
  }
  const params = new URLSearchParams(rawQuery);
  for (const key of Array.from(params.keys())) {
    if (SENSITIVE_QUERY_KEYS.has(key.toLowerCase())) {
      params.set(key, '[REDACTED]');
    }
  }
  const serialized = params.toString();
  return serialized ? `${sanitizedPath}?${serialized}` : sanitizedPath;
}

/**
 * Thuật toán: Đường ống Sự kiện Vòng đời Yêu cầu HTTP (HTTP Request Lifecycle Hook Pipeline)
 * Mục đích: Đảm bảo mọi yêu cầu đi qua máy chủ đều được gắn mã tương quan truy vết, áp đặt
 *   tiêu đề bảo mật trình duyệt nghiêm ngặt, đo thời gian xử lý chính xác và xuất nhật ký JSON an toàn.
 * Cơ chế hoạt động:
 *   - Pha `onRequest`: Ghi mốc thời gian đơn điệu độ phân giải cao (`performance.now()`), trích xuất
 *     hoặc sinh mới ngữ cảnh W3C `traceparent` & `correlationId`, đồng thời phản hồi lại trên header.
 *   - Pha `onSend`: Đính kèm bộ tiêu đề bảo mật chuẩn OWASP (CSP khóa chặt nguồn, HSTS, X-Frame-Options DENY,
 *     nosniff, COOP/CORP same-origin, Permissions-Policy rỗng) trên mọi phản hồi.
 *   - Pha `onResponse`: Tính độ trễ thực thi, chuẩn hóa nhãn tuyến đường (`routeOptions.url` hoặc `/unmatched`
 *     cho lỗi 404 để chống bùng nổ số lượng chuỗi thời gian Prometheus), cập nhật metrics và xuất NDJSON log
 *     đã che dấu URL/headers (bỏ qua các probe kiểm tra sức khỏe tần suất cao).
 */
export function registerFastifyHooks(fastify: FastifyInstance): void {
  // Thuật toán: Khởi tạo đồng hồ đo đơn điệu và trích xuất/chuẩn hóa ngữ cảnh truy vết W3C TraceContext
  fastify.addHook('onRequest', async (request, reply) => {
    request.startTime = performance.now();
    const context = tracer.extractContext(request.headers);

    request.correlationId = context.correlationId;
    request.traceContext = context;

    reply.header('x-correlation-id', context.correlationId);
    reply.header('x-request-id', context.correlationId);
    reply.header(
      'traceparent',
      `00-${context.traceId}-${context.spanId}-${context.sampled ? '01' : '00'}`,
    );
  });

  // Thuật toán: Gia cố tiêu đề bảo mật phản hồi HTTP (OWASP Defense-in-Depth Security Headers)
  fastify.addHook('onSend', async (_request, reply, payload) => {
    reply.header('x-content-type-options', 'nosniff');
    reply.header('x-frame-options', 'DENY');
    reply.header('referrer-policy', 'strict-origin-when-cross-origin');
    reply.header('permissions-policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    reply.header('content-security-policy', "default-src 'none'; frame-ancestors 'none'; sandbox");
    reply.header('cross-origin-opener-policy', 'same-origin');
    reply.header('cross-origin-resource-policy', 'same-origin');
    reply.header('strict-transport-security', 'max-age=31536000; includeSubDomains; preload');
    return payload;
  });

  // Thuật toán: Đo độ trễ yêu cầu, chuẩn hóa nhãn Prometheus và xuất nhật ký cấu trúc đã che dấu
  fastify.addHook('onResponse', async (request, reply) => {
    const rawUrl = request.url;
    const [rawPath = '/'] = rawUrl.split('?', 1);
    const safeUrl = sanitizeLoggedUrl(rawUrl);
    // CONFLICT-RESOLVED: Chuẩn hóa mọi tuyến đường không khớp về '/unmatched' trên mọi mã trạng thái để chống bùng nổ nhãn Prometheus (HIGH-04).
    const metricRoute = request.routeOptions?.url || '/unmatched';
    const durationMs = request.startTime ? performance.now() - request.startTime : 0;
    const durationSeconds = durationMs / 1000;

    // Record low-cardinality Prometheus metrics
    MetricsService.getInstance().recordHttpRequest(
      request.method,
      metricRoute,
      reply.statusCode,
      durationSeconds,
    );

    // CONFLICT-RESOLVED: Tách bỏ query string và chỉ miễn ghi log cho GET probe chuẩn xác để chặn kỹ thuật tắt nhật ký qua '?_=/health/live' (HIGH-04).
    const isSilentCheck =
      request.method === 'GET' &&
      (rawPath === '/health/live' ||
        rawPath === '/api/v1/health/live' ||
        rawPath === '/health/metrics' ||
        rawPath === '/api/v1/health/metrics');
    if (!isSilentCheck) {
      const logData = {
        level: 'info',
        time: new Date().toISOString(),
        msg: `HTTP ${request.method} ${safeUrl} ${reply.statusCode}`,
        method: request.method,
        url: safeUrl,
        statusCode: reply.statusCode,
        durationMs: Math.round(durationMs * 100) / 100,
        correlationId: request.correlationId ?? 'unknown',
        traceId: request.traceContext?.traceId ?? 'unknown',
        spanId: request.traceContext?.spanId ?? 'unknown',
        ip: request.ip,
        headers: redactSensitiveData(request.headers),
      };
      process.stdout.write(`${JSON.stringify(logData)}\n`);
    }
  });
}

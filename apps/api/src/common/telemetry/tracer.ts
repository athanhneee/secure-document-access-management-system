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
   */
  generateTraceId(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Generates a random 16-hex character Span ID (8 bytes).
   */
  generateSpanId(): string {
    return crypto.randomBytes(8).toString('hex');
  }

  /**
   * Extracts W3C traceparent (format: 00-{traceId}-{spanId}-{flags}) and correlation headers.
   */
  extractContext(headers: Record<string, string | string[] | undefined>): TraceContext {
    const rawTraceparent = headers['traceparent'];
    const traceparent = typeof rawTraceparent === 'string' ? rawTraceparent.trim() : undefined;

    const rawCorrId = headers['x-correlation-id'] ?? headers['x-request-id'];
    const headerCorrId = typeof rawCorrId === 'string' ? rawCorrId.trim() : undefined;

    if (traceparent) {
      const parts = traceparent.split('-');
      if (
        parts.length === 4 &&
        parts[0] === '00' &&
        parts[1]?.length === 32 &&
        parts[2]?.length === 16
      ) {
        const traceId = parts[1];
        const parentSpanId = parts[2];
        const sampled = parts[3] === '01';
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
   */
  injectContext(context: TraceContext, headers: Record<string, string>): void {
    const flags = context.sampled ? '01' : '00';
    headers['traceparent'] = `00-${context.traceId}-${context.spanId}-${flags}`;
    headers['x-correlation-id'] = context.correlationId;
    headers['x-request-id'] = context.correlationId;
  }

  /**
   * Starts a new span. Attributes are sanitized to prevent sensitive data leaks.
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

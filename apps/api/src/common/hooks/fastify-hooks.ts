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

export function registerFastifyHooks(fastify: FastifyInstance): void {
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

  fastify.addHook('onResponse', async (request, reply) => {
    const url = request.url;
    const durationMs = request.startTime ? performance.now() - request.startTime : 0;
    const durationSeconds = durationMs / 1000;

    // Record low-cardinality Prometheus metrics
    MetricsService.getInstance().recordHttpRequest(
      request.method,
      url,
      reply.statusCode,
      durationSeconds,
    );

    const isSilentCheck = url.endsWith('/health/live') || url.endsWith('/health/metrics');
    if (!isSilentCheck) {
      const logData = {
        level: 'info',
        time: new Date().toISOString(),
        msg: `HTTP ${request.method} ${url} ${reply.statusCode}`,
        method: request.method,
        url,
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

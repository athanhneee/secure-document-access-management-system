import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { redactSensitiveData } from '../logger/redaction.js';

declare module 'fastify' {
  interface FastifyRequest {
    correlationId?: string;
  }
}

export function registerFastifyHooks(fastify: FastifyInstance): void {
  fastify.addHook('onRequest', async (request, reply) => {
    const headerValue = request.headers['x-correlation-id'] ?? request.headers['x-request-id'];

    const correlationId =
      typeof headerValue === 'string' && headerValue.trim().length > 0
        ? headerValue.trim()
        : randomUUID();

    request.correlationId = correlationId;
    reply.header('x-correlation-id', correlationId);
    reply.header('x-request-id', correlationId);
  });

  fastify.addHook('onResponse', async (request, reply) => {
    const url = request.url;
    const isLiveCheck = url.endsWith('/health/live');
    if (!isLiveCheck) {
      const logData = {
        level: 'info',
        time: new Date().toISOString(),
        msg: `HTTP ${request.method} ${url} ${reply.statusCode}`,
        method: request.method,
        url,
        statusCode: reply.statusCode,
        correlationId: request.correlationId ?? 'unknown',
        ip: request.ip,
        headers: redactSensitiveData(request.headers),
      };
      process.stdout.write(`${JSON.stringify(logData)}\n`);
    }
  });
}

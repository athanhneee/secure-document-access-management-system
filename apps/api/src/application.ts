import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, type NestFastifyApplication } from '@nestjs/platform-fastify';
import cookie from '@fastify/cookie';
import { AppModule } from './app.module.js';
import { AppConfigService } from './config/config.service.js';
import { registerFastifyHooks } from './common/hooks/fastify-hooks.js';
import { HttpExceptionFilter } from './common/filters/http-exception.filter.js';

export async function createApplication(): Promise<NestFastifyApplication> {
  const application = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({ logger: false, bodyLimit: 1_048_576, requestTimeout: 15_000 }),
    { logger: false, abortOnError: false },
  );
  const fastify = application.getHttpAdapter().getInstance();
  await fastify.register(cookie as unknown as Parameters<typeof fastify.register>[0]);
  const config = application.get(AppConfigService);
  application.enableCors({
    origin: config.corsOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['content-type', 'x-csrf-token', 'x-correlation-id'],
  });
  registerFastifyHooks(fastify as unknown as Parameters<typeof registerFastifyHooks>[0]);
  application.useGlobalFilters(new HttpExceptionFilter());
  application.setGlobalPrefix('api/v1');
  application.enableShutdownHooks();
  return application;
}

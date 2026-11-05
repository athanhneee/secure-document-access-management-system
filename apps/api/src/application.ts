/**
 * Module: Khởi tạo Ứng dụng HTTP Gia cố Bảo mật (Hardened NestJS-Fastify Bootstrap)
 * Thuật toán: Thiết lập đường ống giới hạn tài nguyên chống DoS/Slowloris, kiểm soát kích thước tệp tải lên,
 *   cấu hình CORS chặt chẽ và đăng ký tập trung các chốt chặn quan sát/xử lý lỗi.
 */
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, type NestFastifyApplication } from '@nestjs/platform-fastify';
import cookie from '@fastify/cookie';
import multipart from '@fastify/multipart';
import { AppModule } from './app.module.js';
import { AppConfigService } from './config/config.service.js';
import { resolveTrustProxyConfig, validateEnv } from './config/env.schema.js';
import { registerFastifyHooks } from './common/hooks/fastify-hooks.js';
import { HttpExceptionFilter } from './common/filters/http-exception.filter.js';

/**
 * Thuật toán: Khởi dựng Đường ống Máy chủ HTTP Phòng thủ Chiều sâu (Defense-in-Depth Server Bootstrap)
 * Mục đích: Khởi tạo thực thể `NestFastifyApplication` với đầy đủ cơ chế giới hạn băng thông,
 *   thời gian chờ kết nối, chính sách nguồn chéo (CORS) và bộ lọc ngoại lệ an toàn trước khi nhận lưu lượng.
 * Cơ chế hoạt động:
 *   - Khởi tạo `FastifyAdapter` với giới hạn kích thước JSON/body 1 MiB và các ngưỡng timeout nghiêm ngặt
 *     (`requestTimeout`, `connectionTimeout`, `keepAliveTimeout`) nhằm triệt tiêu tấn công Slowloris và cạn kiệt kết nối.
 *   - Đăng ký plugin `cookie` và `multipart` giới hạn tối đa 1 tệp mỗi yêu cầu theo dung lượng cấu hình `UPLOAD_MAX_FILE_SIZE_BYTES`.
 *   - Kích hoạt CORS chỉ cho phép danh sách nguồn hợp lệ kèm thông tin xác thực và danh sách header tường minh.
 *   - Gắn chuỗi lifecycle hooks truy vết/bảo mật, `HttpExceptionFilter` toàn cục, tiền tố `/api/v1` và cơ chế đóng ứng dụng an toàn.
 */
export async function createApplication(): Promise<NestFastifyApplication> {
  const bootstrapEnv = validateEnv(process.env);
  const application = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({
      logger: false,
      trustProxy: resolveTrustProxyConfig(bootstrapEnv.TRUST_PROXY),
      bodyLimit: 1_048_576, // 1MB payload limit
      requestTimeout: 15_000, // 15s request timeout
      connectionTimeout: 15_000, // Slowloris defense
      keepAliveTimeout: 10_000,
    }),
    { logger: false, abortOnError: false },
  );
  const fastify = application.getHttpAdapter().getInstance();
  await fastify.register(cookie as unknown as Parameters<typeof fastify.register>[0]);
  const config = application.get(AppConfigService);
  await fastify.register(multipart as unknown as Parameters<typeof fastify.register>[0], {
    limits: {
      fileSize: config.get('UPLOAD_MAX_FILE_SIZE_BYTES'),
      files: 1,
    },
  });
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

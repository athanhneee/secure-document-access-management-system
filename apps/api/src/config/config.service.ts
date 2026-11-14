/**
 * @module AppConfigService
 * Thuật toán: Dịch vụ cung cấp cấu hình môi trường bất biến đã qua thẩm định Zod Fail-Fast,
 * đối xử đồng nhất cả `production` và `staging` như môi trường bảo mật nghiêm ngặt (`isProduction`).
 */
import { Injectable, Optional } from '@nestjs/common';
import { validateEnv, type EnvConfig } from './env.schema.js';

@Injectable()
export class AppConfigService {
  private readonly config: EnvConfig;

  constructor(@Optional() rawEnv?: Record<string, unknown>) {
    this.config = validateEnv(rawEnv ?? process.env);
  }

  get<K extends keyof EnvConfig>(key: K): EnvConfig[K] {
    return this.config[key];
  }

  getAll(): Readonly<EnvConfig> {
    return this.config;
  }

  get isProduction(): boolean {
    return this.config.NODE_ENV === 'production' || this.config.NODE_ENV === 'staging';
  }

  get isTest(): boolean {
    return this.config.NODE_ENV === 'test';
  }

  /**
   * Thuật toán: Tách danh sách nguồn gốc CORS được phép (`CORS_ALLOWED_ORIGINS`) loại bỏ phần tử rỗng.
   */
  get corsOrigins(): string[] {
    return this.config.CORS_ALLOWED_ORIGINS.split(',')
      .map((origin) => origin.trim())
      .filter((origin) => origin.length > 0);
  }
}

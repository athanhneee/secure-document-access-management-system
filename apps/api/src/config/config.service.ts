import { Injectable } from '@nestjs/common';
import { validateEnv, type EnvConfig } from './env.schema.js';

@Injectable()
export class AppConfigService {
  private readonly config: EnvConfig;

  constructor(rawEnv: Record<string, unknown> = process.env) {
    this.config = validateEnv(rawEnv);
  }

  get<K extends keyof EnvConfig>(key: K): EnvConfig[K] {
    return this.config[key];
  }

  getAll(): Readonly<EnvConfig> {
    return this.config;
  }

  get isProduction(): boolean {
    return this.config.NODE_ENV === 'production';
  }

  get isTest(): boolean {
    return this.config.NODE_ENV === 'test';
  }

  get corsOrigins(): string[] {
    return this.config.CORS_ALLOWED_ORIGINS.split(',')
      .map((origin) => origin.trim())
      .filter((origin) => origin.length > 0);
  }
}

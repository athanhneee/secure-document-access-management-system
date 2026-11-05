import { Injectable, type OnModuleDestroy } from '@nestjs/common';
import { Redis } from 'ioredis';
import { AppConfigService } from '../../config/config.service.js';
import type { CompiledPolicy } from './abac.types.js';

/**
 * Thuật toán: Bộ nhớ đệm chính sách bất biến định danh theo phiên bản (Version-Addressed Fail-Open Redis Cache).
 * Cơ chế hoạt động: Lưu trữ AST chính sách đã biên dịch dưới khóa `sda:abac:compiled:<version>` kèm kiểm tra
 * đối xứng phiên bản khi đọc. Nếu Redis mất kết nối, tự động bỏ qua lỗi để tầng trên biên dịch trực tiếp từ PostgreSQL.
 */
@Injectable()
export class PolicyCache implements OnModuleDestroy {
  private readonly redis: Redis;

  constructor(config: AppConfigService) {
    this.redis = new Redis(config.get('REDIS_URL'), {
      lazyConnect: true,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
      connectTimeout: 1_000,
    });
    this.redis.on('error', () => undefined);
  }

  async get(version: string): Promise<CompiledPolicy | null> {
    try {
      const serialized = await this.redis.get(this.key(version));
      if (!serialized) return null;
      const parsed = JSON.parse(serialized) as CompiledPolicy;
      return parsed.version === version ? parsed : null;
    } catch {
      return null;
    }
  }

  async put(policy: CompiledPolicy): Promise<void> {
    try {
      await this.redis.set(this.key(policy.version), JSON.stringify(policy), 'EX', 3600);
    } catch {
      // Redis is never the policy source of truth. Evaluation can safely compile from PostgreSQL.
    }
  }

  async invalidate(version: string): Promise<void> {
    try {
      await this.redis.del(this.key(version));
    } catch {
      // Versioned keys prevent stale reuse even when Redis is temporarily unavailable.
    }
  }

  onModuleDestroy(): void {
    this.redis.disconnect();
  }

  private key(version: string): string {
    return `sda:abac:compiled:${version}`;
  }
}

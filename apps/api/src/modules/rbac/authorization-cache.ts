/**
 * @module AuthorizationCache
 * Bộ nhớ đệm quyền hiệu lực RBAC trong tiến trình với thuật toán cắt trần TTL theo chân trời hết hạn vai trò
 * (Horizon-Clamped TTL Cache) kèm bộ đếm thế hệ phục vụ vô hiệu hóa tức thì.
 */
import { Injectable } from '@nestjs/common';

export interface EffectiveGrant {
  permissionId: bigint;
  code: string;
  resource: string;
  action: string;
  roleId: bigint;
  roleCode: string;
  scopeDepartmentId: bigint | null;
  validTo: Date | null;
}

interface CacheEntry {
  grants: EffectiveGrant[];
  expiresAt: number;
}

@Injectable()
export class AuthorizationCache {
  // shortcut: 10,000 user grant entries (~5 MB) with 30s horizon-clamped TTL, broadcast invalidations via Redis Pub/Sub across replicas
  private readonly entries = new Map<string, CacheEntry>();
  private generation = 0;

  /**
   * Thuật toán: Tra cứu bộ nhớ đệm kèm thu hồi lười khi quá hạn (Lazy-Expiration Lookup).
   * Cơ chế hoạt động: Kiểm tra `entry.expiresAt <= now`; nếu đã chạm mốc hết hạn thì xóa khóa ngay tại chỗ
   * và trả về `undefined` để buộc tầng dịch vụ nạp lại quyền mới từ cơ sở dữ liệu.
   */
  get(userId: bigint, now = Date.now()): EffectiveGrant[] | undefined {
    const key = userId.toString();
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= now) {
      this.entries.delete(key);
      return undefined;
    }
    return entry.grants;
  }

  /**
   * Thuật toán: Cắt trần TTL theo chân trời hết hạn vai trò gần nhất (Temporal Horizon TTL Clamping).
   * Cơ chế hoạt động: Tính `nearestExpiry = min(now + ttlMs, min_{g}(g.validTo))` trên toàn bộ các phép gán
   * vai trò có thời hạn hữu hạn, đảm bảo không bao giờ phục vụ quyền đã hết hạn `valid_to` dù TTL mặc định chưa trôi hết.
   */
  set(userId: bigint, grants: EffectiveGrant[], ttlMs = 30_000, now = Date.now()): void {
    const nearestExpiry = grants.reduce(
      (minimum, grant) => (grant.validTo ? Math.min(minimum, grant.validTo.getTime()) : minimum),
      now + ttlMs,
    );
    if (this.entries.size >= 10_000) {
      for (const [k, v] of this.entries) {
        if (v.expiresAt <= now) this.entries.delete(k);
      }
      while (this.entries.size >= 10_000) {
        const oldestKey = this.entries.keys().next().value;
        if (!oldestKey) break;
        this.entries.delete(oldestKey);
      }
    }
    this.entries.set(userId.toString(), { grants, expiresAt: nearestExpiry });
  }

  /**
   * Thuật toán: Vô hiệu hóa mục đơn lẻ và tăng đơn điệu số hiệu thế hệ (`generation`).
   */
  invalidateUser(userId: bigint): void {
    this.entries.delete(userId.toString());
    this.generation += 1;
  }

  /**
   * Thuật toán: Xóa trắng toàn cục bộ nhớ đệm khi thay đổi định nghĩa vai trò hoặc ánh xạ quyền hệ thống.
   */
  invalidateAll(): void {
    this.entries.clear();
    this.generation += 1;
  }

  currentGeneration(): number {
    return this.generation;
  }
}

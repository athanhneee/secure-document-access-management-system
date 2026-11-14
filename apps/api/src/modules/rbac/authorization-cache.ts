/**
 * @module AuthorizationCache
 * Bộ nhớ đệm quyền hiệu lực RBAC phân tán qua `DistributedStateService` (Redis + dự phòng cục bộ có trần)
 * với thuật toán cắt trần TTL theo chân trời hết hạn vai trò (`Horizon-Clamped TTL`) kết hợp số hiệu thế hệ
 * toàn cục và theo từng người dùng (`rbac-global`, `rbac-user:<id>`) để vô hiệu hóa tức thì trên mọi bản sao.
 */
import { Injectable, Optional } from '@nestjs/common';
import { AppConfigService } from '../../config/config.service.js';
import { DistributedStateService } from '../concurrency/distributed-state.service.js';

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

interface SerializedEffectiveGrant {
  permissionId: string;
  code: string;
  resource: string;
  action: string;
  roleId: string;
  roleCode: string;
  scopeDepartmentId: string | null;
  validTo: string | null;
}

interface SerializedCacheEntry {
  grants: SerializedEffectiveGrant[];
  expiresAt: number;
}

@Injectable()
export class AuthorizationCache {
  private readonly stateStore: DistributedStateService;
  private generation = 0;

  constructor(
    @Optional() config?: AppConfigService,
    @Optional() stateStore?: DistributedStateService,
  ) {
    this.stateStore = stateStore ?? new DistributedStateService(config);
  }

  /**
   * Thuật toán: Tra cứu bộ nhớ đệm quyền phân tán gắn phiên bản Epoch kèm thu hồi lười khi quá hạn (`Epoch-Scoped Lazy-Expiration Lookup`).
   * Cơ chế hoạt động: Ghép khóa `${globalEpoch}:${userEpoch}:${userId}` từ `DistributedStateService`, kiểm tra `entry.expiresAt <= now`
   * để đảm bảo quyền có `valid_to` hữu hạn không bao giờ sống sót quá thời điểm hết hạn ngay cả khi TTL mặc định chưa trôi hết.
   */
  async get(userId: bigint, now = Date.now()): Promise<EffectiveGrant[] | undefined> {
    const scopedKey = await this.buildScopedKey(userId);
    const entry = await this.stateStore.getJson<SerializedCacheEntry>('rbac-grants', scopedKey);
    if (!entry) return undefined;
    if (entry.expiresAt <= now) {
      await this.stateStore.deleteKey('rbac-grants', scopedKey);
      return undefined;
    }
    return entry.grants.map((grant) => ({
      permissionId: BigInt(grant.permissionId),
      code: grant.code,
      resource: grant.resource,
      action: grant.action,
      roleId: BigInt(grant.roleId),
      roleCode: grant.roleCode,
      scopeDepartmentId: grant.scopeDepartmentId !== null ? BigInt(grant.scopeDepartmentId) : null,
      validTo: grant.validTo !== null ? new Date(grant.validTo) : null,
    }));
  }

  /**
   * Thuật toán: Cắt trần TTL theo chân trời hết hạn vai trò gần nhất (`Temporal Horizon TTL Clamping`).
   * Cơ chế hoạt động: Tính `nearestExpiry = min(now + ttlMs, min_{g}(g.validTo))` trên toàn bộ các phép gán
   * vai trò có thời hạn hữu hạn, sau đó lưu vào `DistributedStateService` với TTL đã kẹp chặt.
   */
  async set(
    userId: bigint,
    grants: EffectiveGrant[],
    ttlMs = 30_000,
    now = Date.now(),
  ): Promise<void> {
    const nearestExpiry = grants.reduce(
      (minimum, grant) => (grant.validTo ? Math.min(minimum, grant.validTo.getTime()) : minimum),
      now + ttlMs,
    );
    const scopedKey = await this.buildScopedKey(userId);
    if (nearestExpiry <= now) {
      await this.stateStore.deleteKey('rbac-grants', scopedKey);
      return;
    }
    const serialized: SerializedCacheEntry = {
      expiresAt: nearestExpiry,
      grants: grants.map((grant) => ({
        permissionId: grant.permissionId.toString(),
        code: grant.code,
        resource: grant.resource,
        action: grant.action,
        roleId: grant.roleId.toString(),
        roleCode: grant.roleCode,
        scopeDepartmentId: grant.scopeDepartmentId?.toString() ?? null,
        validTo: grant.validTo ? grant.validTo.toISOString() : null,
      })),
    };
    await this.stateStore.putEphemeral(
      'rbac-grants',
      scopedKey,
      serialized,
      Math.max(1_000, nearestExpiry - now),
    );
  }

  /**
   * Thuật toán: Vô hiệu hóa tức thì quyền RBAC và phiên xác thực của một người dùng trên toàn cụm bằng tăng Epoch `O(1)`.
   */
  async invalidateUser(userId: bigint): Promise<void> {
    const id = userId.toString();
    this.generation += 1;
    await Promise.all([
      this.stateStore.bumpNamespaceEpoch(`rbac-user:${id}`),
      this.stateStore.bumpNamespaceEpoch(`auth-user:${id}`),
    ]);
  }

  /**
   * Thuật toán: Xóa trắng toàn cục bộ nhớ đệm quyền và phiên xác thực trên mọi bản sao khi thay đổi định nghĩa vai trò/cây phòng ban.
   */
  async invalidateAll(): Promise<void> {
    this.generation += 1;
    await Promise.all([
      this.stateStore.bumpNamespaceEpoch('rbac-global'),
      this.stateStore.bumpNamespaceEpoch('auth-global'),
    ]);
  }

  currentGeneration(): number {
    return this.generation;
  }

  private async buildScopedKey(userId: bigint): Promise<string> {
    const id = userId.toString();
    const [globalEpoch, userEpoch] = await Promise.all([
      this.stateStore.getNamespaceEpoch('rbac-global'),
      this.stateStore.getNamespaceEpoch(`rbac-user:${id}`),
    ]);
    return `${globalEpoch}:${userEpoch}:${id}`;
  }
}

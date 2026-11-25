/**
 * @module AuthorizationCache
 * Thuật toán: Bộ nhớ đệm quyền RBAC hai tầng L1 In-Memory + L2 Redis `MGET` 1-RTT (TTL mặc định 60 giây),
 * kẹp trần TTL theo chân trời hết hạn vai trò (`Horizon-Clamped TTL`) và vô hiệu hóa tức thì xuyên bản sao
 * qua Redis Pub/Sub (`rbac-global`, `rbac-user:<id>`, `auth-global`, `auth-user:<id>`).
 */
import { Injectable, Optional, type OnModuleDestroy } from '@nestjs/common';
import { AppConfigService } from '../../config/config.service.js';
import {
  DistributedStateService,
  type CacheInvalidationEvent,
} from '../concurrency/distributed-state.service.js';

const DEFAULT_RBAC_CACHE_TTL_MS = 60_000;
const MAX_L1_USERS = 5_000;

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
  globalEpoch: number;
  userEpoch: number;
}

interface L1GrantEntry {
  grants: EffectiveGrant[];
  expiresAt: number;
}

@Injectable()
export class AuthorizationCache implements OnModuleDestroy {
  private readonly stateStore: DistributedStateService;
  private readonly l1Grants = new Map<string, L1GrantEntry>();
  private readonly unsubscribeInvalidation: (() => void) | null = null;
  private generation = 0;

  constructor(
    @Optional() config?: AppConfigService,
    @Optional() stateStore?: DistributedStateService,
  ) {
    this.stateStore = stateStore ?? new DistributedStateService(config);
    if (typeof this.stateStore.onInvalidate === 'function') {
      this.unsubscribeInvalidation = this.stateStore.onInvalidate((event) => {
        this.handleCacheInvalidation(event);
      });
    }
  }

  onModuleDestroy(): void {
    this.unsubscribeInvalidation?.();
    this.l1Grants.clear();
  }

  /**
   * Thuật toán: Tra cứu quyền hiệu lực 2 tầng L1 RAM (~0ms) -> L2 Redis `MGET` 1-RTT gắn xác thực Epoch & kẹp trần `valid_to`.
   */
  async get(userId: bigint, now = Date.now()): Promise<EffectiveGrant[] | undefined> {
    const id = userId.toString();
    const l1Hit = this.l1Grants.get(id);
    if (l1Hit) {
      if (l1Hit.expiresAt <= now) {
        this.l1Grants.delete(id);
        return undefined;
      }
      return l1Hit.grants;
    }

    let globalEpoch = 0;
    let userEpoch = 0;
    let entry: SerializedCacheEntry | null = null;

    if (typeof this.stateStore.mgetBatch === 'function') {
      const [rawGlobal, rawUser, rawGrants] = await this.stateStore.mgetBatch([
        { kind: 'epoch', namespace: 'rbac-global' },
        { kind: 'epoch', namespace: `rbac-user:${id}` },
        { kind: 'state', namespace: 'rbac-grants', id },
      ]);
      globalEpoch = rawGlobal ? Number(rawGlobal) || 0 : 0;
      userEpoch = rawUser ? Number(rawUser) || 0 : 0;
      if (rawGrants) {
        try {
          entry = JSON.parse(rawGrants) as SerializedCacheEntry;
        } catch {
          entry = null;
        }
      }
    } else {
      const [g, u, c] = await Promise.all([
        this.stateStore.getNamespaceEpoch('rbac-global'),
        this.stateStore.getNamespaceEpoch(`rbac-user:${id}`),
        this.stateStore.getJson<SerializedCacheEntry>('rbac-grants', id),
      ]);
      globalEpoch = g;
      userEpoch = u;
      entry = c;
    }

    if (!entry || entry.globalEpoch !== globalEpoch || entry.userEpoch !== userEpoch) {
      return undefined;
    }
    if (entry.expiresAt <= now) {
      await this.stateStore.deleteKey('rbac-grants', id);
      return undefined;
    }

    const hydrated: EffectiveGrant[] = entry.grants.map((grant) => ({
      permissionId: BigInt(grant.permissionId),
      code: grant.code,
      resource: grant.resource,
      action: grant.action,
      roleId: BigInt(grant.roleId),
      roleCode: grant.roleCode,
      scopeDepartmentId: grant.scopeDepartmentId !== null ? BigInt(grant.scopeDepartmentId) : null,
      validTo: grant.validTo !== null ? new Date(grant.validTo) : null,
    }));
    this.setL1Entry(id, hydrated, entry.expiresAt);
    return hydrated;
  }

  /**
   * Thuật toán: Cắt trần TTL theo chân trời hết hạn vai trò gần nhất (`Horizon-Clamped TTL`),
   * ghi đồng bộ vào L1 RAM và đẩy nền sang L2 Redis với 1 vòng `MGET` Epoch.
   */
  async set(
    userId: bigint,
    grants: EffectiveGrant[],
    ttlMs = DEFAULT_RBAC_CACHE_TTL_MS,
    now = Date.now(),
  ): Promise<void> {
    const id = userId.toString();
    const nearestExpiry = grants.reduce(
      (minimum, grant) => (grant.validTo ? Math.min(minimum, grant.validTo.getTime()) : minimum),
      now + ttlMs,
    );
    if (nearestExpiry <= now) {
      this.l1Grants.delete(id);
      await this.stateStore.deleteKey('rbac-grants', id);
      return;
    }

    this.setL1Entry(id, grants, nearestExpiry);

    const writeL2 = async (): Promise<void> => {
      let globalEpoch = 0;
      let userEpoch = 0;
      if (typeof this.stateStore.mgetBatch === 'function') {
        const [rawGlobal, rawUser] = await this.stateStore.mgetBatch([
          { kind: 'epoch', namespace: 'rbac-global' },
          { kind: 'epoch', namespace: `rbac-user:${id}` },
        ]);
        globalEpoch = rawGlobal ? Number(rawGlobal) || 0 : 0;
        userEpoch = rawUser ? Number(rawUser) || 0 : 0;
      } else {
        const [g, u] = await Promise.all([
          this.stateStore.getNamespaceEpoch('rbac-global'),
          this.stateStore.getNamespaceEpoch(`rbac-user:${id}`),
        ]);
        globalEpoch = g;
        userEpoch = u;
      }

      const serialized: SerializedCacheEntry = {
        expiresAt: nearestExpiry,
        globalEpoch,
        userEpoch,
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
        id,
        serialized,
        Math.max(1_000, nearestExpiry - now),
      );
    };

    const isRemote =
      typeof this.stateStore.hasRemoteRedis === 'function' && this.stateStore.hasRemoteRedis();
    if (isRemote) {
      void writeL2().catch(() => undefined);
    } else {
      await writeL2();
    }
  }

  /**
   * Thuật toán: Vô hiệu hóa tức thì đệm quyền L1/L2 và phiên xác thực của một người dùng trên toàn cụm bằng 1 RTT Lua + Pub/Sub.
   */
  async invalidateUser(userId: bigint): Promise<void> {
    const id = userId.toString();
    this.generation += 1;
    this.l1Grants.delete(id);
    await Promise.all([
      this.stateStore.bumpNamespaceEpoch(`rbac-user:${id}`),
      this.stateStore.bumpNamespaceEpoch(`auth-user:${id}`),
    ]);
  }

  /**
   * Thuật toán: Xóa trắng toàn cục bộ nhớ đệm L1/L2 quyền và phiên xác thực trên mọi bản sao khi thay đổi định nghĩa vai trò/cây phòng ban.
   */
  async invalidateAll(): Promise<void> {
    this.generation += 1;
    this.l1Grants.clear();
    await Promise.all([
      this.stateStore.bumpNamespaceEpoch('rbac-global'),
      this.stateStore.bumpNamespaceEpoch('auth-global'),
    ]);
  }

  currentGeneration(): number {
    return this.generation;
  }

  private handleCacheInvalidation(event: CacheInvalidationEvent): void {
    if (event.kind === 'key') {
      if (event.namespace === 'rbac-grants') {
        this.l1Grants.delete(event.id);
      }
      return;
    }
    if (event.namespace === 'rbac-global') {
      this.l1Grants.clear();
      return;
    }
    if (event.namespace.startsWith('rbac-user:')) {
      this.l1Grants.delete(event.namespace.slice('rbac-user:'.length));
    }
  }

  private setL1Entry(userId: string, grants: EffectiveGrant[], expiresAt: number): void {
    if (!this.l1Grants.has(userId) && this.l1Grants.size >= MAX_L1_USERS) {
      const now = Date.now();
      for (const [key, entry] of this.l1Grants) {
        if (entry.expiresAt <= now) this.l1Grants.delete(key);
      }
      if (this.l1Grants.size >= MAX_L1_USERS) {
        const oldest = this.l1Grants.keys().next().value;
        if (oldest !== undefined) this.l1Grants.delete(oldest);
      }
    }
    this.l1Grants.set(userId, { grants, expiresAt });
  }
}

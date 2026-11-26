/**
 * @module AuthorizationCache
 * Thuật toán: Bộ nhớ đệm quyền RBAC hai tầng L1 In-Memory + L2 Redis `MGET` 1-RTT (TTL mặc định 60 giây),
 * kẹp trần TTL theo chân trời hết hạn vai trò (`Horizon-Clamped TTL`), chụp tem thế hệ `(generation, globalEpoch, userEpoch)`
 * trước khi truy vấn CSDL kèm ghi CAS Lua chống đầu độc cache (`BUG-043`) và vô hiệu hóa tức thì xuyên bản sao qua Redis Pub/Sub.
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

export interface AuthorizationCacheStamp {
  generation: number;
  globalEpoch: number;
  userEpoch: number;
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
  private readonly pendingSelfEpochBumps = new Map<string, number>();
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
   * Thuật toán: Chụp tem thế hệ `(generation, globalEpoch, userEpoch)` trước khi truy vấn CSDL để ngăn request chậm ghi ngược quyền đã thu hồi (`BUG-043`).
   */
  async captureStamp(userId: bigint): Promise<AuthorizationCacheStamp> {
    const id = userId.toString();
    const generation = this.generation;
    const { globalEpoch, userEpoch } = await this.readEpochs(id);
    return { generation, globalEpoch, userEpoch };
  }

  /**
   * Thuật toán: Tra cứu quyền hiệu lực 2 tầng L1 RAM (~0ms) -> L2 Redis `MGET` 1-RTT đồng thời chụp sẵn tem `(generation, globalEpoch, userEpoch)` khi trượt cache (`BUG-043`).
   */
  async getOrCaptureStamp(
    userId: bigint,
    now = Date.now(),
  ): Promise<{ grants: EffectiveGrant[] | undefined; stamp: AuthorizationCacheStamp }> {
    const id = userId.toString();
    const l1Hit = this.l1Grants.get(id);
    if (l1Hit) {
      if (l1Hit.expiresAt > now) {
        return {
          grants: l1Hit.grants,
          stamp: { generation: this.generation, globalEpoch: 0, userEpoch: 0 },
        };
      }
      this.l1Grants.delete(id);
    }

    const generationBeforeLookup = this.generation;
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

    const stamp: AuthorizationCacheStamp = {
      generation: generationBeforeLookup,
      globalEpoch,
      userEpoch,
    };

    if (
      !entry ||
      entry.globalEpoch !== globalEpoch ||
      entry.userEpoch !== userEpoch ||
      this.generation !== generationBeforeLookup
    ) {
      return { grants: undefined, stamp };
    }
    if (entry.expiresAt <= now) {
      await this.stateStore.deleteKey('rbac-grants', id);
      stamp.generation = this.generation;
      return { grants: undefined, stamp };
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
    return { grants: hydrated, stamp };
  }

  /**
   * Thuật toán: Tra cứu quyền hiệu lực 2 tầng L1 RAM (~0ms) -> L2 Redis `MGET` 1-RTT gắn xác thực Epoch & kẹp trần `valid_to`.
   */
  async get(userId: bigint, now = Date.now()): Promise<EffectiveGrant[] | undefined> {
    const { grants } = await this.getOrCaptureStamp(userId, now);
    return grants;
  }

  /**
   * Thuật toán: Cắt trần TTL theo chân trời hết hạn vai trò gần nhất (`Horizon-Clamped TTL`), đối chiếu tem `generation`
   * và chỉ ghi L2 Redis qua Lua CAS khi `(globalEpoch, userEpoch)` hiện tại trên Redis vẫn bằng đúng tem đã chụp trước lúc đọc CSDL (`BUG-043`).
   */
  async set(
    userId: bigint,
    grants: EffectiveGrant[],
    ttlMs = DEFAULT_RBAC_CACHE_TTL_MS,
    now = Date.now(),
    expectedStamp?: AuthorizationCacheStamp,
  ): Promise<void> {
    const id = userId.toString();
    if (expectedStamp && expectedStamp.generation !== this.generation) {
      return;
    }

    const nearestExpiry = grants.reduce(
      (minimum, grant) => (grant.validTo ? Math.min(minimum, grant.validTo.getTime()) : minimum),
      now + ttlMs,
    );
    if (nearestExpiry <= now) {
      this.l1Grants.delete(id);
      await this.stateStore.deleteKey('rbac-grants', id);
      return;
    }

    const activeStamp = expectedStamp ?? (await this.captureStamp(userId));
    if (activeStamp.generation !== this.generation) {
      this.l1Grants.delete(id);
      return;
    }

    const serialized: SerializedCacheEntry = {
      expiresAt: nearestExpiry,
      globalEpoch: activeStamp.globalEpoch,
      userEpoch: activeStamp.userEpoch,
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

    const safeTtlMs = Math.max(1_000, nearestExpiry - now);
    let written = false;

    try {
      if (typeof this.stateStore.putEphemeralIfEpochsMatch === 'function') {
        written = await this.stateStore.putEphemeralIfEpochsMatch({
          namespace: 'rbac-grants',
          id,
          value: serialized,
          ttlMs: safeTtlMs,
          expectedEpochs: [
            { namespace: 'rbac-global', epoch: activeStamp.globalEpoch },
            { namespace: `rbac-user:${id}`, epoch: activeStamp.userEpoch },
          ],
        });
      } else {
        const currentEpochs = await this.readEpochs(id);
        if (
          currentEpochs.globalEpoch === activeStamp.globalEpoch &&
          currentEpochs.userEpoch === activeStamp.userEpoch &&
          activeStamp.generation === this.generation
        ) {
          await this.stateStore.putEphemeral('rbac-grants', id, serialized, safeTtlMs);
          written = true;
        }
      }
    } catch {
      written = false;
    }

    if (written && activeStamp.generation === this.generation) {
      this.setL1Entry(id, grants, nearestExpiry);
    } else {
      this.l1Grants.delete(id);
    }
  }

  /**
   * Thuật toán: Vô hiệu hóa tức thì đệm quyền L1/L2 và phiên xác thực của một người dùng trên toàn cụm bằng 1 RTT Lua + Pub/Sub.
   */
  async invalidateUser(userId: bigint): Promise<void> {
    const id = userId.toString();
    const rbacNs = `rbac-user:${id}`;
    this.generation += 1;
    this.l1Grants.delete(id);
    this.pendingSelfEpochBumps.set(rbacNs, (this.pendingSelfEpochBumps.get(rbacNs) ?? 0) + 1);
    await Promise.all([
      this.stateStore.bumpNamespaceEpoch(rbacNs),
      this.stateStore.bumpNamespaceEpoch(`auth-user:${id}`),
    ]);
  }

  /**
   * Thuật toán: Xóa trắng toàn cục bộ nhớ đệm L1/L2 quyền và phiên xác thực trên mọi bản sao khi thay đổi định nghĩa vai trò/cây phòng ban.
   */
  async invalidateAll(): Promise<void> {
    this.generation += 1;
    this.l1Grants.clear();
    this.pendingSelfEpochBumps.set(
      'rbac-global',
      (this.pendingSelfEpochBumps.get('rbac-global') ?? 0) + 1,
    );
    await Promise.all([
      this.stateStore.bumpNamespaceEpoch('rbac-global'),
      this.stateStore.bumpNamespaceEpoch('auth-global'),
    ]);
  }

  currentGeneration(): number {
    return this.generation;
  }

  private async readEpochs(userIdStr: string): Promise<{ globalEpoch: number; userEpoch: number }> {
    if (typeof this.stateStore.mgetBatch === 'function') {
      const [rawGlobal, rawUser] = await this.stateStore.mgetBatch([
        { kind: 'epoch', namespace: 'rbac-global' },
        { kind: 'epoch', namespace: `rbac-user:${userIdStr}` },
      ]);
      return {
        globalEpoch: rawGlobal ? Number(rawGlobal) || 0 : 0,
        userEpoch: rawUser ? Number(rawUser) || 0 : 0,
      };
    }
    const [globalEpoch, userEpoch] = await Promise.all([
      this.stateStore.getNamespaceEpoch('rbac-global'),
      this.stateStore.getNamespaceEpoch(`rbac-user:${userIdStr}`),
    ]);
    return { globalEpoch, userEpoch };
  }

  /**
   * Thuật toán: Tăng `generation` và xóa mục đệm L1 ngay khi nhận thông điệp vô hiệu hóa Pub/Sub từ bản sao khác (`BUG-043`).
   */
  private handleCacheInvalidation(event: CacheInvalidationEvent): void {
    if (event.kind === 'key') {
      if (event.namespace === 'rbac-grants') {
        this.l1Grants.delete(event.id);
      }
      return;
    }
    if (event.namespace === 'rbac-global') {
      const pending = this.pendingSelfEpochBumps.get('rbac-global') ?? 0;
      if (pending > 0) {
        if (pending === 1) this.pendingSelfEpochBumps.delete('rbac-global');
        else this.pendingSelfEpochBumps.set('rbac-global', pending - 1);
      } else {
        this.generation += 1;
      }
      this.l1Grants.clear();
      return;
    }
    if (event.namespace.startsWith('rbac-user:')) {
      const pending = this.pendingSelfEpochBumps.get(event.namespace) ?? 0;
      if (pending > 0) {
        if (pending === 1) this.pendingSelfEpochBumps.delete(event.namespace);
        else this.pendingSelfEpochBumps.set(event.namespace, pending - 1);
      } else {
        this.generation += 1;
      }
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

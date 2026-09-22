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
  private readonly entries = new Map<string, CacheEntry>();
  private generation = 0;

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

  set(userId: bigint, grants: EffectiveGrant[], ttlMs = 30_000, now = Date.now()): void {
    const nearestExpiry = grants.reduce(
      (minimum, grant) => (grant.validTo ? Math.min(minimum, grant.validTo.getTime()) : minimum),
      now + ttlMs,
    );
    this.entries.set(userId.toString(), { grants, expiresAt: nearestExpiry });
  }

  invalidateUser(userId: bigint): void {
    this.entries.delete(userId.toString());
    this.generation += 1;
  }

  invalidateAll(): void {
    this.entries.clear();
    this.generation += 1;
  }

  currentGeneration(): number {
    return this.generation;
  }
}

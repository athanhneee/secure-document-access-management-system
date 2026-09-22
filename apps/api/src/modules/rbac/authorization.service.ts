import { ForbiddenException, Injectable } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import type { AuthPrincipal } from '../auth/auth.types.js';
import { AuthorizationCache, type EffectiveGrant } from './authorization-cache.js';

@Injectable()
export class AuthorizationService {
  private readonly database = getDatabaseClient();

  constructor(private readonly cache: AuthorizationCache) {}

  async effectiveGrants(userId: bigint): Promise<EffectiveGrant[]> {
    const cached = this.cache.get(userId);
    if (cached) return cached;
    const now = new Date();
    const assignments = await this.database.userRole.findMany({
      where: {
        user_id: userId,
        valid_from: { lte: now },
        AND: [
          { OR: [{ valid_to: null }, { valid_to: { gt: now } }] },
          { OR: [{ scope_department_id: null }, { departments: { is: { is_active: true } } }] },
        ],
        roles: { is_active: true },
        users_user_roles_user_idTousers: { status: 'ACTIVE' },
      },
      include: {
        roles: {
          include: {
            role_permissions: { include: { permissions: true } },
          },
        },
      },
    });
    const grants = assignments.flatMap((assignment) =>
      assignment.roles.role_permissions.map((mapping) => ({
        permissionId: mapping.permissions.id,
        code: mapping.permissions.code,
        resource: mapping.permissions.resource_type,
        action: mapping.permissions.action,
        roleId: assignment.roles.id,
        roleCode: assignment.roles.code,
        scopeDepartmentId: assignment.scope_department_id,
        validTo: assignment.valid_to,
      })),
    );
    this.cache.set(userId, grants);
    return grants;
  }

  async hasPermission(
    principal: AuthPrincipal,
    resource: string,
    action: string,
    options: {
      targetDepartmentId?: bigint | null;
      requireGlobal?: boolean;
      anyScope?: boolean;
    } = {},
  ): Promise<boolean> {
    const matching = (await this.effectiveGrants(principal.userId)).filter(
      (grant) => grant.resource === resource && grant.action === action,
    );
    if (options.requireGlobal) return matching.some((grant) => grant.scopeDepartmentId === null);
    if (options.anyScope) return matching.length > 0;
    if (options.targetDepartmentId == null) {
      return matching.some((grant) => grant.scopeDepartmentId === null);
    }
    const ancestors = await this.departmentAncestors(options.targetDepartmentId);
    return matching.some(
      (grant) => grant.scopeDepartmentId === null || ancestors.has(grant.scopeDepartmentId),
    );
  }

  async assertPermission(
    principal: AuthPrincipal,
    resource: string,
    action: string,
    options: {
      targetDepartmentId?: bigint | null;
      requireGlobal?: boolean;
      anyScope?: boolean;
    } = {},
  ): Promise<void> {
    if (!(await this.hasPermission(principal, resource, action, options))) {
      throw new ForbiddenException('Permission is not granted for this resource scope.');
    }
  }

  async assertCanDelegate(
    principal: AuthPrincipal,
    permissionIds: bigint[],
    targetDepartmentId: bigint | null,
  ): Promise<void> {
    const grants = await this.effectiveGrants(principal.userId);
    const ancestors =
      targetDepartmentId === null
        ? new Set<bigint>()
        : await this.departmentAncestors(targetDepartmentId);
    const allowed = permissionIds.every((permissionId) =>
      grants.some(
        (grant) =>
          grant.permissionId === permissionId &&
          (targetDepartmentId === null
            ? grant.scopeDepartmentId === null
            : grant.scopeDepartmentId === null || ancestors.has(grant.scopeDepartmentId)),
      ),
    );
    if (!allowed) {
      throw new ForbiddenException('Cannot delegate permissions outside the administrator grant.');
    }
  }

  async visibleDepartmentIds(
    principal: AuthPrincipal,
    resource: string,
    action: string,
  ): Promise<bigint[] | null> {
    const matching = (await this.effectiveGrants(principal.userId)).filter(
      (grant) => grant.resource === resource && grant.action === action,
    );
    if (matching.some((grant) => grant.scopeDepartmentId === null)) return null;
    const roots = matching.flatMap((grant) =>
      grant.scopeDepartmentId === null ? [] : [grant.scopeDepartmentId],
    );
    if (roots.length === 0) return [];
    const departments = await this.database.department.findMany({
      select: { id: true, parent_id: true },
    });
    const visible = new Set(roots);
    let changed = true;
    while (changed) {
      changed = false;
      for (const department of departments) {
        if (
          department.parent_id !== null &&
          visible.has(department.parent_id) &&
          !visible.has(department.id)
        ) {
          visible.add(department.id);
          changed = true;
        }
      }
    }
    return [...visible];
  }

  invalidateUser(userId: bigint): void {
    this.cache.invalidateUser(userId);
  }

  invalidateAll(): void {
    this.cache.invalidateAll();
  }

  async departmentWithinScope(departmentId: bigint, scopeDepartmentId: bigint): Promise<boolean> {
    return (await this.departmentAncestors(departmentId)).has(scopeDepartmentId);
  }

  private async departmentAncestors(departmentId: bigint): Promise<Set<bigint>> {
    const ancestors = new Set<bigint>();
    let current: bigint | null = departmentId;
    while (current !== null && !ancestors.has(current)) {
      ancestors.add(current);
      const department: { parent_id: bigint | null } | null =
        await this.database.department.findUnique({
          where: { id: current },
          select: { parent_id: true },
        });
      current = department?.parent_id ?? null;
    }
    return ancestors;
  }
}

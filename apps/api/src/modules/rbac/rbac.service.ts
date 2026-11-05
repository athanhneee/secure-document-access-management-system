/**
 * Module: RBAC Role Administration & User-Role Assignment Service
 * Algorithm: Manages roles with `SERIALIZABLE` optimistic CAS, self-modification blocks, system-role
 *   ceiling matrices, and temporal Separation-of-Duties (SoD) role assignments.
 */
import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { getDatabaseClient, withSerializableTransaction } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { AuthorizationService } from './authorization.service.js';
import { isPrivilegedSeparationRoleOrCapability } from './permission-matrix.js';
import { RbacAuditService } from './rbac-audit.service.js';
import {
  actorHoldsActiveRole,
  executeAssignUserRole,
  executeRevokeUserRole,
} from './rbac-assignments.helper.js';
import {
  auditRoleSnapshot,
  executeDeleteRole,
  executeReplaceRolePermissions,
  executeUpdateRole,
  presentRoleDto,
} from './rbac-roles.helper.js';

@Injectable()
export class RbacService {
  private readonly database = getDatabaseClient();

  constructor(
    private readonly authorization: AuthorizationService,
    private readonly audit: RbacAuditService,
  ) {}

  async listRoles() {
    const roles = await this.database.role.findMany({
      orderBy: [{ is_system_role: 'desc' }, { code: 'asc' }],
      include: { role_permissions: { include: { permissions: true } } },
    });
    return { data: roles.map((role) => presentRoleDto(role)) };
  }

  async lookupRoles(principal?: AuthPrincipal) {
    const roles = await this.database.role.findMany({
      where: { is_active: true },
      orderBy: { code: 'asc' },
      take: 200,
      include: {
        role_permissions: {
          include: { permissions: { select: { code: true, resource_type: true, action: true } } },
        },
      },
    });
    const canViewPrivilegedRoles = principal
      ? (await this.authorization.hasPermission(principal, 'ROLE', 'MANAGE', {
          requireGlobal: true,
        })) ||
        (await this.authorization.hasPermission(principal, 'USER', 'MANAGE', { anyScope: true }))
      : false;
    const filtered = canViewPrivilegedRoles
      ? roles
      : roles.filter(
          (r) =>
            !isPrivilegedSeparationRoleOrCapability(
              r.code,
              r.role_permissions.map((rp) => rp.permissions),
            ),
        );
    return {
      data: filtered.map((r) => ({
        id: r.id.toString(),
        code: r.code,
        name: r.name,
        description: r.description,
      })),
    };
  }

  async getRole(id: bigint) {
    const role = await this.database.role.findUnique({
      where: { id },
      include: { role_permissions: { include: { permissions: true } } },
    });
    if (!role) throw new NotFoundException('Role not found.');
    return presentRoleDto(role);
  }

  async listPermissions() {
    const permissions = await this.database.permission.findMany({
      orderBy: [{ resource_type: 'asc' }, { action: 'asc' }],
    });
    return {
      data: permissions.map((permission) => ({
        id: permission.id.toString(),
        code: permission.code,
        name: permission.name,
        resource: permission.resource_type,
        action: permission.action,
        description: permission.description,
      })),
    };
  }

  async createRole(
    principal: AuthPrincipal,
    input: { code: string; name: string; description?: string | null | undefined },
    context: RequestContext,
  ) {
    const role = await withSerializableTransaction(async (transaction) => {
      const created = await transaction.role.create({
        data: {
          code: input.code,
          name: input.name,
          description: input.description ?? null,
          is_system_role: false,
          created_by: principal.userId,
        },
      });
      await this.audit.record(
        transaction,
        {
          action: 'ROLE_CREATED',
          objectType: 'ROLE',
          objectId: created.id.toString(),
          before: null,
          after: auditRoleSnapshot(created),
        },
        principal,
        context,
      );
      return created;
    });
    this.authorization.invalidateAll();
    return presentRoleDto({ ...role, role_permissions: [] });
  }

  async updateRole(
    principal: AuthPrincipal,
    id: bigint,
    input: {
      expectedVersion: number;
      code?: string | undefined;
      name?: string | undefined;
      description?: string | null | undefined;
    },
    context: RequestContext,
  ) {
    const roleId = await executeUpdateRole({
      database: this.database,
      authorization: this.authorization,
      audit: this.audit,
      principal,
      id,
      input,
      context,
    });
    return this.getRole(roleId);
  }

  /**
   * Algorithm: OCC CAS Role Deactivation (`version = expectedVersion -> version + 1`)
   */
  async disableRole(
    principal: AuthPrincipal,
    id: bigint,
    expectedVersion: number,
    context: RequestContext,
  ) {
    const role = await withSerializableTransaction(
      async (transaction) => {
        const before = await transaction.role.findUnique({ where: { id } });
        if (!before) throw new NotFoundException('Role not found.');
        if (before.is_system_role) throw new ForbiddenException('System roles cannot be disabled.');
        // CONFLICT-RESOLVED: Chạy `actorHoldsActiveRole` bên trong giao dịch `transaction` để giữ cô lập SERIALIZABLE chống tự nâng quyền/khóa vai trò (HIGH-02).
        if (await actorHoldsActiveRole(transaction, principal.userId, id)) {
          throw new ForbiddenException('Administrators cannot disable a role they hold.');
        }
        const changed = await transaction.role.updateMany({
          where: { id, version: expectedVersion },
          data: { is_active: false, updated_at: new Date(), version: { increment: 1 } },
        });
        if (changed.count !== 1)
          throw new ConflictException('Role was changed by another request.');
        const after = await transaction.role.findUniqueOrThrow({ where: { id } });
        await this.audit.record(
          transaction,
          {
            action: 'ROLE_DISABLED',
            objectType: 'ROLE',
            objectId: id.toString(),
            before: auditRoleSnapshot(before),
            after: auditRoleSnapshot(after),
          },
          principal,
          context,
        );
        return after;
      },
      { client: this.database },
    );
    this.authorization.invalidateAll();
    return this.getRole(role.id);
  }

  deleteRole(principal: AuthPrincipal, id: bigint, context: RequestContext): Promise<void> {
    return executeDeleteRole({
      authorization: this.authorization,
      audit: this.audit,
      principal,
      id,
      context,
    });
  }

  replacePermissions(
    principal: AuthPrincipal,
    roleId: bigint,
    permissionIds: bigint[],
    context: RequestContext,
  ) {
    return executeReplaceRolePermissions({
      database: this.database,
      authorization: this.authorization,
      audit: this.audit,
      principal,
      roleId,
      permissionIds,
      context,
    });
  }

  assignUserRole(
    principal: AuthPrincipal,
    userId: bigint,
    input: {
      roleId: bigint;
      scopeDepartmentId: bigint | null;
      validFrom: Date;
      validTo: Date | null;
    },
    context: RequestContext,
  ) {
    return executeAssignUserRole(this.authorization, this.audit, principal, userId, input, context);
  }

  revokeUserRole(
    principal: AuthPrincipal,
    userId: bigint,
    assignmentId: bigint,
    context: RequestContext,
  ) {
    return executeRevokeUserRole(
      this.authorization,
      this.audit,
      principal,
      userId,
      assignmentId,
      context,
    );
  }
}

import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { getDatabaseClient, withSerializableTransaction } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { AuthorizationService } from './authorization.service.js';
import { PRIVILEGED_SEPARATION_ROLES, systemRoleAllows } from './permission-matrix.js';
import { RbacAuditService } from './rbac-audit.service.js';

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
    return { data: roles.map((role) => this.presentRole(role)) };
  }

  async getRole(id: bigint) {
    const role = await this.database.role.findUnique({
      where: { id },
      include: { role_permissions: { include: { permissions: true } } },
    });
    if (!role) throw new NotFoundException('Role not found.');
    return this.presentRole(role);
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
          after: this.auditRole(created),
        },
        principal,
        context,
      );
      return created;
    });
    this.authorization.invalidateAll();
    return this.presentRole({ ...role, role_permissions: [] });
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
    const role = await withSerializableTransaction(async (transaction) => {
      const before = await transaction.role.findUnique({ where: { id } });
      if (!before) throw new NotFoundException('Role not found.');
      if (before.is_system_role && (input.code !== undefined || input.name !== undefined)) {
        throw new ForbiddenException('System role code and name are immutable.');
      }
      const changed = await transaction.role.updateMany({
        where: { id, version: input.expectedVersion },
        data: {
          ...(input.code !== undefined ? { code: input.code } : {}),
          ...(input.name !== undefined ? { name: input.name } : {}),
          ...(input.description !== undefined ? { description: input.description } : {}),
          updated_at: new Date(),
          version: { increment: 1 },
        },
      });
      if (changed.count !== 1) throw new ConflictException('Role was changed by another request.');
      const after = await transaction.role.findUniqueOrThrow({ where: { id } });
      await this.audit.record(
        transaction,
        {
          action: 'ROLE_UPDATED',
          objectType: 'ROLE',
          objectId: id.toString(),
          before: this.auditRole(before),
          after: this.auditRole(after),
        },
        principal,
        context,
      );
      return after;
    });
    this.authorization.invalidateAll();
    return this.getRole(role.id);
  }

  async disableRole(
    principal: AuthPrincipal,
    id: bigint,
    expectedVersion: number,
    context: RequestContext,
  ) {
    const role = await withSerializableTransaction(async (transaction) => {
      const before = await transaction.role.findUnique({ where: { id } });
      if (!before) throw new NotFoundException('Role not found.');
      if (before.is_system_role) throw new ForbiddenException('System roles cannot be disabled.');
      if (await this.actorHoldsRole(principal.userId, id))
        throw new ForbiddenException('Administrators cannot disable a role they hold.');
      const changed = await transaction.role.updateMany({
        where: { id, version: expectedVersion },
        data: { is_active: false, updated_at: new Date(), version: { increment: 1 } },
      });
      if (changed.count !== 1) throw new ConflictException('Role was changed by another request.');
      const after = await transaction.role.findUniqueOrThrow({ where: { id } });
      await this.audit.record(
        transaction,
        {
          action: 'ROLE_DISABLED',
          objectType: 'ROLE',
          objectId: id.toString(),
          before: this.auditRole(before),
          after: this.auditRole(after),
        },
        principal,
        context,
      );
      return after;
    });
    this.authorization.invalidateAll();
    return this.getRole(role.id);
  }

  async deleteRole(principal: AuthPrincipal, id: bigint, context: RequestContext): Promise<void> {
    await withSerializableTransaction(async (transaction) => {
      const before = await transaction.role.findUnique({ where: { id } });
      if (!before) throw new NotFoundException('Role not found.');
      if (before.is_system_role) throw new ForbiddenException('System roles cannot be deleted.');
      const assignmentCount = await transaction.userRole.count({ where: { role_id: id } });
      if (assignmentCount > 0)
        throw new ConflictException(
          'Role assignment history prevents deletion; disable the role instead.',
        );
      await transaction.role.delete({ where: { id } });
      await this.audit.record(
        transaction,
        {
          action: 'ROLE_DELETED',
          objectType: 'ROLE',
          objectId: id.toString(),
          before: this.auditRole(before),
          after: null,
        },
        principal,
        context,
      );
    });
    this.authorization.invalidateAll();
  }

  async replacePermissions(
    principal: AuthPrincipal,
    roleId: bigint,
    permissionIds: bigint[],
    context: RequestContext,
  ) {
    const result = await withSerializableTransaction(async (transaction) => {
      const role = await transaction.role.findUnique({
        where: { id: roleId },
        include: { role_permissions: { include: { permissions: true } } },
      });
      if (!role) throw new NotFoundException('Role not found.');
      if (await this.actorHoldsRole(principal.userId, roleId))
        throw new ForbiddenException('Administrators cannot change a role they hold.');
      const permissions = await transaction.permission.findMany({
        where: { id: { in: permissionIds } },
      });
      if (permissions.length !== new Set(permissionIds.map(String)).size)
        throw new NotFoundException('Permission not found.');
      await this.authorization.assertCanDelegate(principal, permissionIds, null);
      if (
        role.is_system_role &&
        !systemRoleAllows(
          role.code,
          permissions.map((permission) => permission.code),
        )
      ) {
        throw new ForbiddenException(
          'System role mapping is outside the approved permission matrix.',
        );
      }
      const before = role.role_permissions.map((mapping) => mapping.permissions.code).sort();
      await transaction.rolePermission.deleteMany({ where: { role_id: roleId } });
      if (permissionIds.length > 0) {
        await transaction.rolePermission.createMany({
          data: permissionIds.map((permissionId) => ({
            role_id: roleId,
            permission_id: permissionId,
            granted_by: principal.userId,
          })),
        });
      }
      const after = permissions.map((permission) => permission.code).sort();
      await this.audit.record(
        transaction,
        {
          action: 'ROLE_PERMISSIONS_REPLACED',
          objectType: 'ROLE_PERMISSION',
          objectId: roleId.toString(),
          before: { permissionCodes: before },
          after: { permissionCodes: after },
        },
        principal,
        context,
      );
      return after;
    });
    this.authorization.invalidateAll();
    return { permissionCodes: result };
  }

  async assignUserRole(
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
    if (principal.userId === userId)
      throw new ForbiddenException('Administrators cannot assign roles to themselves.');
    const id = await withSerializableTransaction(async (transaction) => {
      const [user, role] = await Promise.all([
        transaction.user.findUnique({ where: { id: userId } }),
        transaction.role.findFirst({
          where: { id: input.roleId, is_active: true },
          include: { role_permissions: true },
        }),
      ]);
      if (!user || user.status === 'DISABLED')
        throw new NotFoundException('Active user not found.');
      if (!role) throw new NotFoundException('Active role not found.');
      await this.authorization.assertPermission(principal, 'USER', 'MANAGE', {
        targetDepartmentId: user.department_id,
      });
      await this.authorization.assertPermission(principal, 'USER', 'MANAGE', {
        targetDepartmentId: input.scopeDepartmentId,
      });
      if (input.scopeDepartmentId !== null) {
        const scope = await transaction.department.findFirst({
          where: { id: input.scopeDepartmentId, is_active: true },
        });
        if (!scope) throw new NotFoundException('Active scope department not found.');
        if (
          user.department_id === null ||
          !(await this.authorization.departmentWithinScope(
            user.department_id,
            input.scopeDepartmentId,
          ))
        ) {
          throw new ForbiddenException('Role scope must contain the target user department.');
        }
      }
      await this.authorization.assertCanDelegate(
        principal,
        role.role_permissions.map((mapping) => mapping.permission_id),
        input.scopeDepartmentId,
      );
      if (PRIVILEGED_SEPARATION_ROLES.has(role.code)) {
        const incompatible = await transaction.userRole.findFirst({
          where: {
            user_id: userId,
            roles: {
              code: { in: [...PRIVILEGED_SEPARATION_ROLES].filter((code) => code !== role.code) },
            },
            valid_from: { lte: new Date() },
            OR: [{ valid_to: null }, { valid_to: { gt: new Date() } }],
          },
        });
        if (incompatible) throw new ConflictException('Privileged roles are mutually exclusive.');
      }
      const assignment = await transaction.userRole.create({
        data: {
          user_id: userId,
          role_id: input.roleId,
          scope_department_id: input.scopeDepartmentId,
          valid_from: input.validFrom,
          valid_to: input.validTo,
          assigned_by: principal.userId,
        },
      });
      await this.audit.record(
        transaction,
        {
          action: 'USER_ROLE_ASSIGNED',
          objectType: 'USER_ROLE',
          objectId: assignment.id.toString(),
          before: null,
          after: this.auditAssignment(assignment),
        },
        principal,
        context,
      );
      return assignment.id;
    });
    this.authorization.invalidateUser(userId);
    return { id: id.toString() };
  }

  async revokeUserRole(
    principal: AuthPrincipal,
    userId: bigint,
    assignmentId: bigint,
    context: RequestContext,
  ) {
    if (principal.userId === userId)
      throw new ForbiddenException('Administrators cannot revoke their own roles.');
    await withSerializableTransaction(async (transaction) => {
      const assignment = await transaction.userRole.findFirst({
        where: { id: assignmentId, user_id: userId },
      });
      if (!assignment) throw new NotFoundException('Role assignment not found.');
      const user = await transaction.user.findUniqueOrThrow({ where: { id: userId } });
      await this.authorization.assertPermission(principal, 'USER', 'MANAGE', {
        targetDepartmentId: user.department_id,
      });
      const now = new Date();
      if (assignment.valid_to !== null && assignment.valid_to <= now)
        throw new ConflictException('Role assignment is already inactive.');
      const after = await transaction.userRole.update({
        where: { id: assignmentId },
        data: { valid_to: now },
      });
      await this.audit.record(
        transaction,
        {
          action: 'USER_ROLE_REVOKED',
          objectType: 'USER_ROLE',
          objectId: assignmentId.toString(),
          before: this.auditAssignment(assignment),
          after: this.auditAssignment(after),
        },
        principal,
        context,
      );
    });
    this.authorization.invalidateUser(userId);
  }

  private async actorHoldsRole(userId: bigint, roleId: bigint): Promise<boolean> {
    const now = new Date();
    return (
      (await this.database.userRole.count({
        where: {
          user_id: userId,
          role_id: roleId,
          valid_from: { lte: now },
          OR: [{ valid_to: null }, { valid_to: { gt: now } }],
        },
      })) > 0
    );
  }

  private presentRole(role: {
    id: bigint;
    code: string;
    name: string;
    description: string | null;
    is_system_role: boolean;
    is_active: boolean;
    version: number;
    role_permissions: Array<{
      permissions: { id: bigint; code: string; resource_type: string; action: string };
    }>;
  }) {
    return {
      id: role.id.toString(),
      code: role.code,
      name: role.name,
      description: role.description,
      isSystemRole: role.is_system_role,
      isActive: role.is_active,
      version: role.version,
      permissions: role.role_permissions
        .map((mapping) => ({
          id: mapping.permissions.id.toString(),
          code: mapping.permissions.code,
          resource: mapping.permissions.resource_type,
          action: mapping.permissions.action,
        }))
        .sort((left, right) => left.code.localeCompare(right.code)),
    };
  }

  private auditRole(role: {
    id: bigint;
    code: string;
    name: string;
    description: string | null;
    is_system_role: boolean;
    is_active: boolean;
    version: number;
  }) {
    return {
      id: role.id.toString(),
      code: role.code,
      name: role.name,
      description: role.description,
      isSystemRole: role.is_system_role,
      isActive: role.is_active,
      version: role.version,
    };
  }

  private auditAssignment(assignment: {
    id: bigint;
    user_id: bigint;
    role_id: bigint;
    scope_department_id: bigint | null;
    valid_from: Date;
    valid_to: Date | null;
  }) {
    return {
      id: assignment.id.toString(),
      userId: assignment.user_id.toString(),
      roleId: assignment.role_id.toString(),
      scopeDepartmentId: assignment.scope_department_id?.toString() ?? null,
      validFrom: assignment.valid_from.toISOString(),
      validTo: assignment.valid_to?.toISOString() ?? null,
    };
  }
}

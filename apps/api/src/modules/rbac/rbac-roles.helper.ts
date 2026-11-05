/**
 * Module: RBAC Role DTO Projections & OCC CAS Role Mutation Helpers
 * Algorithm: Enforces self-modification guards (`actorHoldsActiveRole`), system-role immutability,
 *   optimistic Compare-And-Swap (`version`) updates, history-checked deletion, and delegation-ceiling permission replacement.
 */
import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { withSerializableTransaction, type getDatabaseClient } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from './authorization.service.js';
import {
  areOverlappingRolesSodCompatible,
  resolveCompatibleSodArchetypes,
  systemRoleAllows,
} from './permission-matrix.js';
import type { RbacAuditService } from './rbac-audit.service.js';
import { actorHoldsActiveRole } from './rbac-assignments.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm: Deterministic Lexicographical Role-Permission DTO Projection
 */
export function presentRoleDto(role: {
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

export function auditRoleSnapshot(role: {
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

/**
 * Algorithm: OCC CAS Role Update + Self-Modification Guard
 */
export async function executeUpdateRole(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  audit: RbacAuditService;
  principal: AuthPrincipal;
  id: bigint;
  input: {
    expectedVersion: number;
    code?: string | undefined;
    name?: string | undefined;
    description?: string | null | undefined;
  };
  context: RequestContext;
}): Promise<bigint> {
  const { database, authorization, audit, principal, id, input, context } = params;
  const role = await withSerializableTransaction(
    async (transaction) => {
      const before = await transaction.role.findUnique({ where: { id } });
      if (!before) throw new NotFoundException('Role not found.');
      // CONFLICT-RESOLVED: Chạy `actorHoldsActiveRole` bên trong giao dịch `transaction` thay vì `database` bên ngoài để giữ tính cô lập SERIALIZABLE (HIGH-02).
      if (await actorHoldsActiveRole(transaction, principal.userId, id)) {
        throw new ForbiddenException('Administrators cannot change a role they hold.');
      }
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
      await audit.record(
        transaction,
        {
          action: 'ROLE_UPDATED',
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
    { client: database },
  );
  authorization.invalidateAll();
  return role.id;
}

/**
 * Algorithm: History-Protected Custom Role Deletion
 * Blocks deletion of system roles or roles with historical user assignments under `SERIALIZABLE` isolation.
 */
export async function executeDeleteRole(params: {
  authorization: AuthorizationService;
  audit: RbacAuditService;
  principal: AuthPrincipal;
  id: bigint;
  context: RequestContext;
}): Promise<void> {
  const { authorization, audit, principal, id, context } = params;
  await withSerializableTransaction(async (transaction) => {
    const before = await transaction.role.findUnique({ where: { id } });
    if (!before) throw new NotFoundException('Role not found.');
    if (before.is_system_role) throw new ForbiddenException('System roles cannot be deleted.');
    const assignmentCount = await transaction.userRole.count({ where: { role_id: id } });
    if (assignmentCount > 0) {
      throw new ConflictException(
        'Role assignment history prevents deletion; disable the role instead.',
      );
    }
    await transaction.role.delete({ where: { id } });
    await audit.record(
      transaction,
      {
        action: 'ROLE_DELETED',
        objectType: 'ROLE',
        objectId: id.toString(),
        before: auditRoleSnapshot(before),
        after: null,
      },
      principal,
      context,
    );
  });
  authorization.invalidateAll();
}

/**
 * Algorithm: Atomic Permission-Set Replacement with System-Role Ceiling & Delegation Check
 */
export async function executeReplaceRolePermissions(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  audit: RbacAuditService;
  principal: AuthPrincipal;
  roleId: bigint;
  permissionIds: bigint[];
  context: RequestContext;
}) {
  const { database, authorization, audit, principal, roleId, permissionIds, context } = params;
  // CONFLICT-RESOLVED: Khử trùng lặp `permissionIds` đầu vào trước khi truy vấn và ghi bảng trung gian `role_permissions` để tránh lỗi khóa chính kép (HIGH-12)
  const uniquePermissionIds = [...new Map(permissionIds.map((id) => [id.toString(), id])).values()];
  const result = await withSerializableTransaction(
    async (transaction) => {
      const role = await transaction.role.findUnique({
        where: { id: roleId },
        include: { role_permissions: { include: { permissions: true } } },
      });
      if (!role) throw new NotFoundException('Role not found.');
      // CONFLICT-RESOLVED: Kiểm tra quyền sở hữu vai trò trong cùng giao dịch SERIALIZABLE và chặn trộn lẫn tập quyền trái Phân tách Nhiệm vụ trên Custom Role (HIGH-01, HIGH-02).
      if (await actorHoldsActiveRole(transaction, principal.userId, roleId)) {
        throw new ForbiddenException('Administrators cannot change a role they hold.');
      }
      const permissions = await transaction.permission.findMany({
        where: { id: { in: uniquePermissionIds } },
      });
      if (permissions.length !== uniquePermissionIds.length)
        throw new NotFoundException('Permission not found.');
      await authorization.assertCanDelegate(principal, uniquePermissionIds, null);
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
      if (resolveCompatibleSodArchetypes([{ code: role.code, permissions }]).size === 0) {
        throw new ForbiddenException(
          'Role permissions violate Separation of Duties across incompatible security domains.',
        );
      }
      const now = new Date();
      const activeHolders =
        typeof transaction.userRole?.findMany === 'function'
          ? await transaction.userRole.findMany({
              where: {
                role_id: roleId,
                OR: [{ valid_to: null }, { valid_to: { gt: now } }],
              },
              select: { user_id: true, valid_from: true, valid_to: true },
            })
          : [];
      if (activeHolders.length > 0) {
        const holderIds = [...new Set(activeHolders.map((h) => h.user_id))];
        const allHolderAssignments = await transaction.userRole.findMany({
          where: {
            user_id: { in: holderIds },
            roles: { is_active: true },
            OR: [{ valid_to: null }, { valid_to: { gt: now } }],
          },
          include: {
            roles: { include: { role_permissions: { include: { permissions: true } } } },
          },
        });
        for (const targetAssignment of activeHolders) {
          const overlappingForHolder = allHolderAssignments
            .filter(
              (other) =>
                other.user_id === targetAssignment.user_id &&
                (other.valid_to === null || other.valid_to > targetAssignment.valid_from) &&
                (targetAssignment.valid_to === null ||
                  other.valid_from < targetAssignment.valid_to),
            )
            .map((other) => ({
              code: other.roles.code,
              permissions:
                other.role_id === roleId
                  ? permissions
                  : (other.roles.role_permissions ?? [])
                      .map((m) => m.permissions)
                      .filter((p): p is NonNullable<typeof p> => Boolean(p)),
            }));
          if (!areOverlappingRolesSodCompatible(overlappingForHolder)) {
            throw new ConflictException(
              'Separation of duties violation: updating role permissions conflicts with another role held by an assigned user.',
            );
          }
        }
      }
      const before = role.role_permissions.map((mapping) => mapping.permissions.code).sort();
      await transaction.rolePermission.deleteMany({ where: { role_id: roleId } });
      if (uniquePermissionIds.length > 0) {
        await transaction.rolePermission.createMany({
          data: uniquePermissionIds.map((permissionId) => ({
            role_id: roleId,
            permission_id: permissionId,
            granted_by: principal.userId,
          })),
        });
      }
      const after = permissions.map((permission) => permission.code).sort();
      await audit.record(
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
    },
    { client: database },
  );
  authorization.invalidateAll();
  return { permissionCodes: result };
}

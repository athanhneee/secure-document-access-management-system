/**
 * @module RbacRolesHelper
 * Thuật toán: Chiếu DTO vai trò tất định theo thứ tự từ điển, cập nhật vai trò bằng kiểm soát đồng thời lạc quan
 * Compare-And-Swap (`version`) kèm chốt chặn tự sửa đổi (`actorHoldsActiveRole`) và xóa vai trò có bảo vệ lịch sử gán.
 */
import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { withSerializableTransaction, type getDatabaseClient } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from './authorization.service.js';
import type { RbacAuditService } from './rbac-audit.service.js';
import { actorHoldsActiveRole } from './rbac-assignments.helper.js';

export { executeReplaceRolePermissions } from './rbac-role-permissions.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Chiếu DTO vai trò và sắp xếp danh sách quyền tất định theo mã quyền (`code`).
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
    permissions: {
      id: bigint;
      code: string;
      name?: string | undefined;
      resource_type: string;
      action: string;
    };
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
        ...(mapping.permissions.name !== undefined ? { name: mapping.permissions.name } : {}),
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
 * Thuật toán: Cập nhật thông tin vai trò bằng Compare-And-Swap (`version`) kèm chốt chặn tự sửa đổi vai trò đang nắm giữ.
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
  await authorization.invalidateAll();
  return role.id;
}

/**
 * Thuật toán: Xóa vai trò tùy chỉnh có bảo vệ lịch sử gán dưới mức cô lập `SERIALIZABLE`.
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
  await authorization.invalidateAll();
}

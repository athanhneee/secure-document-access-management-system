/**
 * @module RbacRolesHelper
 * Thuật toán: Chiếu DTO vai trò tất định theo thứ tự từ điển, cập nhật vai trò bằng kiểm soát đồng thời lạc quan
 * Compare-And-Swap (`version`) kèm chốt chặn tự sửa đổi (`actorHoldsActiveRole`) và xóa vai trò có bảo vệ lịch sử gán.
 */
import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { withSerializableTransaction, type getDatabaseClient } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from './authorization.service.js';
import { resolveCompatibleSodArchetypes } from './permission-matrix.js';
import type { RbacAuditService } from './rbac-audit.service.js';
import { actorHoldsActiveRole, isGlobalSystemAdminRoleManager } from './rbac-assignments.helper.js';
import {
  assertRoleHoldersSodAndGrants,
  revokeUnverifiedMfaSessionsForUsers,
} from './rbac-role-permissions.helper.js';

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

/**
 * Thuật toán: Kích hoạt lại vai trò tùy chỉnh đang bị vô hiệu hóa bằng Compare-And-Swap (`version`) dưới mức cô lập `SERIALIZABLE`,
 * cưỡng chế đầy đủ trần ủy quyền (`assertCanDelegate`), Phân tách Nhiệm vụ (SoD) chồng lấp thời gian trên toàn bộ người giữ vai trò,
 * kiểm tra xung đột `AccessGrant` và thu hồi tức thì mọi phiên chưa xác thực MFA nếu vai trò mang đặc quyền.
 */
export async function executeEnableRole(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  audit: RbacAuditService;
  principal: AuthPrincipal;
  id: bigint;
  expectedVersion: number;
  context: RequestContext;
}): Promise<bigint> {
  const { database, authorization, audit, principal, id, expectedVersion, context } = params;
  const role = await withSerializableTransaction(
    async (transaction) => {
      const bypassDelegationSubset = await isGlobalSystemAdminRoleManager(
        authorization,
        principal,
        transaction,
      );
      const before = await transaction.role.findUnique({
        where: { id },
        include: { role_permissions: { include: { permissions: true } } },
      });
      if (!before) throw new NotFoundException('Role not found.');
      if (before.is_system_role) throw new ForbiddenException('System roles cannot be modified.');
      if (await actorHoldsActiveRole(transaction, principal.userId, id)) {
        throw new ForbiddenException('Administrators cannot change a role they hold.');
      }
      const rolePermissionMappings = before.role_permissions ?? [];
      const rolePermissionIds = rolePermissionMappings
        .map((mapping) => mapping.permission_id ?? mapping.permissions?.id)
        .filter((permissionId): permissionId is bigint => typeof permissionId === 'bigint');
      const rolePermissions = rolePermissionMappings
        .map((mapping) => mapping.permissions)
        .filter((permission): permission is NonNullable<typeof permission> => Boolean(permission));
      // BUG-005 & BUG-048: Chặn quản trị viên cấp thấp kích hoạt lại vai trò chứa quyền vượt quá trần ủy quyền của chính mình ngay trên kết nối `transaction`.
      if (!bypassDelegationSubset && rolePermissionIds.length > 0) {
        await authorization.assertCanDelegate(principal, rolePermissionIds, null, transaction);
      }
      if (before.is_active) throw new ConflictException('Role is already active.');
      if (
        resolveCompatibleSodArchetypes([{ code: before.code, permissions: rolePermissions }])
          .size === 0
      ) {
        throw new ForbiddenException(
          'Role permissions violate Separation of Duties across incompatible security domains.',
        );
      }
      const now = new Date();
      // BUG-005 & BUG-047: Kiểm tra lại SoD chồng lấp thời gian, chặn sở hữu tài liệu chưa bàn giao và thu hồi dây chuyền AccessGrant/AccessSession/AccessRequest trước khi bật lại vai trò đặc quyền.
      const { holderIds, isPrivileged } = await assertRoleHoldersSodAndGrants({
        transaction,
        roleId: id,
        roleCode: before.code,
        rolePermissions,
        actorUserId: principal.userId,
        cascadeReason: `Privileged custom role ${before.code} re-enabled`,
        now,
        conflictMessage:
          'Separation of duties violation: enabling this role conflicts with another active role held by an assigned user.',
      });
      const changed = await transaction.role.updateMany({
        where: { id, version: expectedVersion },
        data: { is_active: true, updated_at: now, version: { increment: 1 } },
      });
      if (changed.count !== 1) throw new ConflictException('Role was changed by another request.');
      // BUG-005: Thu hồi tức thì các phiên chưa xác thực MFA của toàn bộ người đang giữ vai trò đặc quyền vừa được bật lại.
      if (holderIds.length > 0 && isPrivileged) {
        await revokeUnverifiedMfaSessionsForUsers(transaction, holderIds, now);
      }
      const after = await transaction.role.findUniqueOrThrow({ where: { id } });
      await audit.record(
        transaction,
        {
          action: 'ROLE_ENABLED',
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

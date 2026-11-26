/**
 * @module RbacRolePermissionsHelper
 * Thuật toán: Thay thế nguyên tử tập quyền của vai trò (`executeReplaceRolePermissions`) dưới cô lập `SERIALIZABLE`,
 * kiểm chứng trần ma trận vai trò hệ thống, kiểm tra Phân tách Nhiệm vụ (SoD) cho toàn bộ người đang nắm vai trò
 * và thu hồi tức thì các phiên thiếu MFA nếu tập quyền mới biến vai trò thành vai trò đặc quyền.
 */
import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { withSerializableTransaction, type getDatabaseClient } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from './authorization.service.js';
import {
  areOverlappingRolesSodCompatible,
  isPrivilegedSeparationRoleOrCapability,
  resolveCompatibleSodArchetypes,
  systemRoleAllows,
} from './permission-matrix.js';
import type { RbacAuditService } from './rbac-audit.service.js';
import { actorHoldsActiveRole, isGlobalSystemAdminRoleManager } from './rbac-assignments.helper.js';
import {
  assertUsersOwnNoBusinessDocuments,
  cascadeCleanupOnPrivilegedRoleEscalation,
} from './rbac-grant-cascade.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;
type SerializableTransaction = Parameters<Parameters<typeof withSerializableTransaction>[0]>[0];

export const PRIVILEGED_ROLE_MFA_REVOKE_REASON = 'PRIVILEGED_ROLE_ASSIGNED_REQUIRES_MFA';

export interface RoleSodPermission {
  code: string;
  resource_type?: string | undefined;
  action?: string | undefined;
}

/**
 * Thuật toán: Kiểm chứng Phân tách Nhiệm vụ (SoD) chồng lấp thời gian trên toàn bộ người giữ vai trò
 * (luôn gộp cả vai trò mục tiêu dù đang `is_active: false`) và chặn xung đột `AccessGrant` (`ROLE` / `USER`).
 */
export async function assertRoleHoldersSodAndGrants(params: {
  transaction: SerializableTransaction;
  roleId: bigint;
  roleCode: string;
  rolePermissions: readonly RoleSodPermission[];
  actorUserId: bigint;
  cascadeReason: string;
  now: Date;
  conflictMessage: string;
}): Promise<{ holderIds: bigint[]; isPrivileged: boolean }> {
  const {
    transaction,
    roleId,
    roleCode,
    rolePermissions,
    actorUserId,
    cascadeReason,
    now,
    conflictMessage,
  } = params;
  const isPrivileged = isPrivilegedSeparationRoleOrCapability(roleCode, rolePermissions);

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
  const holderIds = [...new Set(activeHolders.map((h) => h.user_id))];

  const overlappingOtherRoleIds = new Set<bigint>();
  let anyHolderHasOverlappingPrivilegedRole = false;

  if (activeHolders.length > 0) {
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
    const targetDescriptor = { code: roleCode, permissions: rolePermissions };

    for (const targetAssignment of activeHolders) {
      const overlappingOtherAssignments = allHolderAssignments.filter(
        (other) =>
          other.user_id === targetAssignment.user_id &&
          other.role_id !== roleId &&
          (other.valid_to === null || other.valid_to > targetAssignment.valid_from) &&
          (targetAssignment.valid_to === null || other.valid_from < targetAssignment.valid_to),
      );
      const overlappingOtherDescriptors = overlappingOtherAssignments.map((other) => {
        if (typeof other.role_id === 'bigint') {
          overlappingOtherRoleIds.add(other.role_id);
        }
        const perms = (other.roles.role_permissions ?? [])
          .map((m) => m.permissions)
          .filter((p): p is NonNullable<typeof p> => Boolean(p));
        if (isPrivilegedSeparationRoleOrCapability(other.roles.code, perms)) {
          anyHolderHasOverlappingPrivilegedRole = true;
        }
        return { code: other.roles.code, permissions: perms };
      });
      // BUG-005: Luôn bao gồm vai trò mục tiêu (kể cả khi đang tắt `is_active: false`) khi kiểm tra SoD chồng lấp thời gian.
      if (!areOverlappingRolesSodCompatible([...overlappingOtherDescriptors, targetDescriptor])) {
        throw new ConflictException(conflictMessage);
      }
    }
  }

  // CONFLICT-RESOLVED: Hợp nhất BUG-005 và BUG-047 — khi nâng Custom Role thành vai trò đặc quyền (hoặc kích hoạt lại vai trò đặc quyền),
  // chặn 409 nếu người giữ đang sở hữu tài liệu chưa bàn giao (`owner_id`), đồng thời thu hồi dây chuyền mọi USER/ROLE AccessGrant ACTIVE,
  // đóng AccessSession ACTIVE và hủy AccessRequest PENDING của họ; giữ nguyên chặn 409 khi vai trò thường có ROLE grant kết hợp với người dùng đã mang vai trò đặc quyền.
  if (isPrivileged) {
    await assertUsersOwnNoBusinessDocuments(transaction, holderIds);
    await cascadeCleanupOnPrivilegedRoleEscalation({
      transaction,
      userIds: holderIds,
      roleIds: [roleId, ...overlappingOtherRoleIds],
      actorUserId,
      reason: cascadeReason,
      now,
    });
  } else if (
    anyHolderHasOverlappingPrivilegedRole &&
    typeof transaction.accessGrant?.count === 'function'
  ) {
    const activeRoleGrantsOnTarget = await transaction.accessGrant.count({
      where: {
        principal_type: 'ROLE',
        principal_role_id: roleId,
        status: 'ACTIVE',
        valid_until: { gt: now },
      },
    });
    if (activeRoleGrantsOnTarget > 0) {
      throw new ConflictException(
        'Separation of duties violation: a role with active document access grants cannot be combined with a privileged role.',
      );
    }
  }

  return { holderIds, isPrivileged };
}

/**
 * Thuật toán: Thu hồi nguyên tử mọi phiên đăng nhập chưa xác thực yếu tố thứ hai (`mfa_verified_at IS NULL`)
 * cùng thẻ làm mới (`refresh_tokens`) liên kết ngay khi người dùng được gán vai trò đặc quyền quản trị/SOC/kiểm toán.
 */
export async function revokeUnverifiedMfaSessionsForUsers(
  transaction: SerializableTransaction,
  userIds: bigint[],
  now: Date = new Date(),
): Promise<void> {
  if (userIds.length === 0) return;
  if (typeof transaction.refreshToken?.updateMany === 'function') {
    await transaction.refreshToken.updateMany({
      where: {
        revoked_at: null,
        auth_sessions: { user_id: { in: userIds }, status: 'ACTIVE', mfa_verified_at: null },
      },
      data: { revoked_at: now, revocation_reason: PRIVILEGED_ROLE_MFA_REVOKE_REASON },
    });
  }
  if (typeof transaction.authSession?.updateMany === 'function') {
    await transaction.authSession.updateMany({
      where: { user_id: { in: userIds }, status: 'ACTIVE', mfa_verified_at: null },
      data: {
        status: 'REVOKED',
        revoked_at: now,
        revocation_reason: PRIVILEGED_ROLE_MFA_REVOKE_REASON,
      },
    });
  }
}

/**
 * Thuật toán: Thay thế tập quyền nguyên tử kèm kiểm tra trần ủy quyền, SoD chéo người giữ vai trò và thu hồi phiên thiếu MFA.
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
  const uniquePermissionIds = [...new Set(permissionIds.map((id) => id.toString()))].map((id) =>
    BigInt(id),
  );
  const result = await withSerializableTransaction(
    async (transaction) => {
      const bypassDelegationSubset = await isGlobalSystemAdminRoleManager(
        authorization,
        principal,
        transaction,
      );
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
      if (permissions.length !== uniquePermissionIds.length) {
        throw new NotFoundException('Permission not found.');
      }
      // CONFLICT-RESOLVED: Cho phép SYSTEM_ADMIN toàn cục có ROLE_MANAGE toàn cục phân quyền cho vai trò hệ thống khác và Custom Role nghiệp vụ (do SoD đã tách quyền nghiệp vụ khỏi SYSTEM_ADMIN), đồng thời truyền `transaction` vào `assertCanDelegate` chống tự khóa chết pool CSDL (BUG-048).
      if (!bypassDelegationSubset) {
        await authorization.assertCanDelegate(principal, uniquePermissionIds, null, transaction);
      }
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
      const { holderIds, isPrivileged } = await assertRoleHoldersSodAndGrants({
        transaction,
        roleId,
        roleCode: role.code,
        rolePermissions: permissions,
        actorUserId: principal.userId,
        cascadeReason: `Role ${role.code} permissions updated to privileged capability`,
        now,
        conflictMessage:
          'Separation of duties violation: updating role permissions conflicts with another role held by an assigned user.',
      });
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
      if (holderIds.length > 0 && isPrivileged) {
        await revokeUnverifiedMfaSessionsForUsers(transaction, holderIds, now);
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
  await authorization.invalidateAll();
  return { permissionCodes: result };
}

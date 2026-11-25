/**
 * @module RbacAssignmentsHelper
 * Thuật toán: Cấp phát & thu hồi vai trò theo khoảng thời gian nửa mở `[valid_from, valid_to)` với kiểm chứng
 * bao đóng phòng ban, trần ủy quyền, Phân tách Nhiệm vụ (SoD) và thu hồi tức thì mọi phiên chưa xác thực MFA
 * khi gán vai trò đặc quyền (`PRIVILEGED_ROLE_ASSIGNED_REQUIRES_MFA`).
 */
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { withSerializableTransaction, type getDatabaseClient } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from './authorization.service.js';
import {
  areOverlappingRolesSodCompatible,
  isPrivilegedSeparationRoleOrCapability,
} from './permission-matrix.js';
import type { RbacAuditService } from './rbac-audit.service.js';
import {
  PRIVILEGED_ROLE_MFA_REVOKE_REASON,
  revokeUnverifiedMfaSessionsForUsers,
} from './rbac-role-permissions.helper.js';

export { PRIVILEGED_ROLE_MFA_REVOKE_REASON, revokeUnverifiedMfaSessionsForUsers };

type PrismaClient = ReturnType<typeof getDatabaseClient>;
type RoleLookupClient = Pick<PrismaClient, 'userRole'>;

/**
 * Thuật toán: Xác định quản trị viên hệ thống tối cao (`SYSTEM_ADMIN` toàn cục kèm quyền `ROLE_MANAGE` toàn cục).
 * Chỉ khi người thực hiện nắm giữ đồng thời vai trò `SYSTEM_ADMIN` đang hiệu lực và quyền `ROLE_MANAGE` ở phạm vi
 * `scopeDepartmentId === null`, hệ thống mới cho phép cấp phát/thu hồi vai trò nghiệp vụ hoặc đặc quyền cho nhân sự
 * khác mà không bị chặn bởi tập con `targetRolePermissions ⊆ actorPermissions` (do SoD đã gỡ `DOCUMENT_*` khỏi `SYSTEM_ADMIN`).
 */
export async function isGlobalSystemAdminRoleManager(
  authorization: AuthorizationService,
  principal: AuthPrincipal,
): Promise<boolean> {
  if (typeof authorization.effectiveGrants === 'function') {
    const grants = await authorization.effectiveGrants(principal.userId);
    const hasGlobalSystemAdminRole = grants.some(
      (grant) => grant.roleCode === 'SYSTEM_ADMIN' && grant.scopeDepartmentId === null,
    );
    const hasGlobalRoleManage = grants.some(
      (grant) =>
        grant.scopeDepartmentId === null &&
        (grant.code === 'ROLE_MANAGE' || (grant.resource === 'ROLE' && grant.action === 'MANAGE')),
    );
    return hasGlobalSystemAdminRole && hasGlobalRoleManage;
  }
  if (!principal.roles.includes('SYSTEM_ADMIN')) {
    return false;
  }
  if (typeof authorization.hasPermission === 'function') {
    return authorization.hasPermission(principal, 'ROLE', 'MANAGE', { requireGlobal: true });
  }
  if (typeof authorization.assertPermission === 'function') {
    try {
      await authorization.assertPermission(principal, 'ROLE', 'MANAGE', { requireGlobal: true });
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Thuật toán: Gán vai trò có kiểm tra Phân tách Nhiệm vụ (SoD), phạm vi phòng ban và cưỡng chế thu hồi phiên thiếu MFA.
 */
export async function executeAssignUserRole(
  authorization: AuthorizationService,
  audit: RbacAuditService,
  principal: AuthPrincipal,
  userId: bigint,
  input: {
    roleId: bigint;
    scopeDepartmentId: bigint | null;
    validFrom: Date;
    validTo: Date | null;
  },
  context: RequestContext,
  database?: PrismaClient,
): Promise<{ id: string }> {
  if (principal.userId === userId) {
    throw new ForbiddenException('Administrators cannot assign roles to themselves.');
  }
  const now = new Date();
  if (input.validTo !== null && input.validTo <= input.validFrom) {
    throw new BadRequestException('validTo must be later than validFrom.');
  }
  if (input.validTo !== null && input.validTo <= now) {
    throw new BadRequestException('validTo must be in the future.');
  }
  const bypassDelegationSubset = await isGlobalSystemAdminRoleManager(authorization, principal);
  const id = await withSerializableTransaction(
    async (transaction) => {
      const [user, role] = await Promise.all([
        transaction.user.findUnique({ where: { id: userId } }),
        transaction.role.findFirst({
          where: { id: input.roleId, is_active: true },
          include: { role_permissions: { include: { permissions: true } } },
        }),
      ]);
      if (!user || user.status === 'DISABLED')
        throw new NotFoundException('Active user not found.');
      if (!role) throw new NotFoundException('Active role not found.');
      await authorization.assertPermission(principal, 'USER', 'MANAGE', {
        targetDepartmentId: user.department_id,
      });
      await authorization.assertPermission(principal, 'USER', 'MANAGE', {
        targetDepartmentId: input.scopeDepartmentId,
      });
      if (input.scopeDepartmentId !== null) {
        const scope = await transaction.department.findFirst({
          where: { id: input.scopeDepartmentId, is_active: true },
        });
        if (!scope) throw new NotFoundException('Active scope department not found.');
        if (
          user.department_id === null ||
          !(await authorization.departmentWithinScope(user.department_id, input.scopeDepartmentId))
        ) {
          throw new ForbiddenException('Role scope must contain the target user department.');
        }
      }
      // CONFLICT-RESOLVED: Cho phép SYSTEM_ADMIN toàn cục có ROLE_MANAGE toàn cục cấp phát vai trò cho nhân sự khác (bởi SoD đã tách quyền nghiệp vụ khỏi SYSTEM_ADMIN), đồng thời giữ nguyên kiểm tra trần ủy quyền tập con cho mọi quản trị viên cấp thấp/custom role.
      if (!bypassDelegationSubset) {
        await authorization.assertCanDelegate(
          principal,
          role.role_permissions.map((mapping) => mapping.permission_id),
          input.scopeDepartmentId,
        );
      }
      // CONFLICT-RESOLVED: Kiểm tra xung đột Phân tách Nhiệm vụ (SoD) theo cả mã vai trò lẫn tập quyền thực tế trên khoảng thời gian chồng lấp (HIGH-01).
      const overlappingAssignments = await transaction.userRole.findMany({
        where: {
          user_id: userId,
          roles: { is_active: true },
          AND: [
            { OR: [{ valid_to: null }, { valid_to: { gt: input.validFrom } }] },
            ...(input.validTo !== null ? [{ valid_from: { lt: input.validTo } }] : []),
          ],
        },
        include: {
          roles: { include: { role_permissions: { include: { permissions: true } } } },
        },
      });
      const candidateDescriptor = {
        code: role.code,
        permissions: role.role_permissions
          .map((m) => m.permissions)
          .filter((p): p is NonNullable<typeof p> => Boolean(p)),
      };
      const overlappingDescriptors = overlappingAssignments.map((assignment) => ({
        code: assignment.roles.code,
        permissions: (assignment.roles.role_permissions ?? [])
          .map((m) => m.permissions)
          .filter((p): p is NonNullable<typeof p> => Boolean(p)),
      }));
      if (!areOverlappingRolesSodCompatible([...overlappingDescriptors, candidateDescriptor])) {
        throw new ConflictException(
          'Separation of duties violation: privileged roles and capabilities are mutually exclusive and cannot be combined with business roles.',
        );
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
      if (isPrivilegedSeparationRoleOrCapability(role.code, candidateDescriptor.permissions)) {
        await revokeUnverifiedMfaSessionsForUsers(transaction, [userId], new Date());
      }
      await audit.record(
        transaction,
        {
          action: 'USER_ROLE_ASSIGNED',
          objectType: 'USER_ROLE',
          objectId: assignment.id.toString(),
          before: null,
          after: auditAssignmentSnapshot(assignment),
        },
        principal,
        context,
      );
      return assignment.id;
    },
    database ? { client: database } : undefined,
  );
  await authorization.invalidateUser(userId);
  return { id: id.toString() };
}

/**
 * Thuật toán: Thu hồi phép gán vai trò trong giao dịch `SERIALIZABLE` có giới hạn trần ủy quyền.
 */
export async function executeRevokeUserRole(
  authorization: AuthorizationService,
  audit: RbacAuditService,
  principal: AuthPrincipal,
  userId: bigint,
  assignmentId: bigint,
  context: RequestContext,
  database?: PrismaClient,
): Promise<void> {
  if (principal.userId === userId) {
    throw new ForbiddenException('Administrators cannot revoke their own roles.');
  }
  const bypassDelegationSubset = await isGlobalSystemAdminRoleManager(authorization, principal);
  await withSerializableTransaction(
    async (transaction) => {
      const assignment = await transaction.userRole.findFirst({
        where: { id: assignmentId, user_id: userId },
        include: { roles: { include: { role_permissions: true } } },
      });
      if (!assignment) throw new NotFoundException('Role assignment not found.');
      const user = await transaction.user.findUniqueOrThrow({ where: { id: userId } });
      await authorization.assertPermission(principal, 'USER', 'MANAGE', {
        targetDepartmentId: user.department_id,
      });
      await authorization.assertPermission(principal, 'USER', 'MANAGE', {
        targetDepartmentId: assignment.scope_department_id,
      });
      if (!bypassDelegationSubset && assignment.roles?.role_permissions) {
        await authorization.assertCanDelegate(
          principal,
          assignment.roles.role_permissions.map((mapping) => mapping.permission_id),
          assignment.scope_department_id,
        );
      }
      const now = new Date();
      if (assignment.valid_to !== null && assignment.valid_to <= now) {
        throw new ConflictException('Role assignment is already inactive.');
      }
      // CONFLICT-RESOLVED: Xóa trực tiếp bản ghi gán vai trò chưa đến giờ hiệu lực (`valid_from >= now`) để không vi phạm ràng buộc SQL `CHECK (valid_to IS NULL OR valid_to > valid_from)` (HIGH-12)
      let afterSnapshot: ReturnType<typeof auditAssignmentSnapshot> | null = null;
      if (assignment.valid_from >= now) {
        await transaction.userRole.delete({ where: { id: assignmentId } });
      } else {
        const after = await transaction.userRole.update({
          where: { id: assignmentId },
          data: { valid_to: now },
        });
        afterSnapshot = auditAssignmentSnapshot(after);
      }
      await audit.record(
        transaction,
        {
          action: 'USER_ROLE_REVOKED',
          objectType: 'USER_ROLE',
          objectId: assignmentId.toString(),
          before: auditAssignmentSnapshot(assignment),
          after: afterSnapshot,
        },
        principal,
        context,
      );
    },
    database ? { client: database } : undefined,
  );
  await authorization.invalidateUser(userId);
}

/**
 * Thuật toán: Kiểm tra xem người thực thi có đang giữ hoặc được hẹn giờ giữ vai trò `roleId` hay không để chặn tự nâng quyền.
 */
export async function actorHoldsActiveRole(
  database: RoleLookupClient,
  userId: bigint,
  roleId: bigint,
): Promise<boolean> {
  const now = new Date();
  // CONFLICT-RESOLVED: Thực thi truy vấn trên client giao dịch SERIALIZABLE và bao gồm cả vai trò hẹn giờ tương lai (`valid_from > now`) chống tự nâng quyền (HIGH-02).
  return (
    (await database.userRole.count({
      where: {
        user_id: userId,
        role_id: roleId,
        OR: [{ valid_to: null }, { valid_to: { gt: now } }],
      },
    })) > 0
  );
}

export function auditAssignmentSnapshot(assignment: {
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

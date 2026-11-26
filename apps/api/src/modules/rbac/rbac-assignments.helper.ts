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
import { withSerializableTransaction, type getDatabaseClient, type Prisma } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from './authorization.service.js';
import {
  areOverlappingRolesSodCompatible,
  isPrivilegedSeparationRoleOrCapability,
} from './permission-matrix.js';
import type { RbacAuditService } from './rbac-audit.service.js';
import {
  assertUserClearanceMeetsActiveRoleGrants,
  assertUsersOwnNoBusinessDocuments,
  cascadeCleanupOnPrivilegedRoleEscalation,
  terminateUserSessionsOpenedViaRevokedRole,
} from './rbac-grant-cascade.helper.js';
import {
  PRIVILEGED_ROLE_MFA_REVOKE_REASON,
  revokeUnverifiedMfaSessionsForUsers,
} from './rbac-role-permissions.helper.js';
import {
  assertCanManageTargetUser,
  assertNotLastActiveGlobalSystemAdminForAssignment,
  resolveActorGovernanceContext,
} from './rbac-user-governance.helper.js';

export { PRIVILEGED_ROLE_MFA_REVOKE_REASON, revokeUnverifiedMfaSessionsForUsers };

type PrismaClient = ReturnType<typeof getDatabaseClient>;
type RoleLookupClient = Pick<PrismaClient, 'userRole'>;

/**
 * Thuật toán: Xác định quản trị viên hệ thống tối cao (`SYSTEM_ADMIN` toàn cục kèm quyền `ROLE_MANAGE` toàn cục),
 * hỗ trợ tái sử dụng kết nối `tx` của giao dịch `SERIALIZABLE` đang mở để chống tự khóa chết pool CSDL (`BUG-048`).
 */
export async function isGlobalSystemAdminRoleManager(
  authorization: AuthorizationService,
  principal: AuthPrincipal,
  tx?: Prisma.TransactionClient,
): Promise<boolean> {
  if (typeof authorization.effectiveGrants === 'function') {
    const grants = await authorization.effectiveGrants(principal.userId, tx);
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
    return authorization.hasPermission(principal, 'ROLE', 'MANAGE', { requireGlobal: true }, tx);
  }
  if (typeof authorization.assertPermission === 'function') {
    try {
      await authorization.assertPermission(
        principal,
        'ROLE',
        'MANAGE',
        { requireGlobal: true },
        tx,
      );
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
  const id = await withSerializableTransaction(
    async (transaction) => {
      const [bypassDelegationSubset, actorContext] = await Promise.all([
        isGlobalSystemAdminRoleManager(authorization, principal, transaction),
        resolveActorGovernanceContext(authorization, principal, transaction),
      ]);
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
      await authorization.assertPermission(
        principal,
        'USER',
        'MANAGE',
        { targetDepartmentId: user.department_id },
        transaction,
      );
      await authorization.assertPermission(
        principal,
        'USER',
        'MANAGE',
        { targetDepartmentId: input.scopeDepartmentId },
        transaction,
      );
      if (input.scopeDepartmentId !== null) {
        const scope = await transaction.department.findFirst({
          where: { id: input.scopeDepartmentId, is_active: true },
        });
        if (!scope) throw new NotFoundException('Active scope department not found.');
        if (
          user.department_id === null ||
          !(await authorization.departmentWithinScope(
            user.department_id,
            input.scopeDepartmentId,
            transaction,
          ))
        ) {
          throw new ForbiddenException('Role scope must contain the target user department.');
        }
      }
      // CONFLICT-RESOLVED: Cho phép SYSTEM_ADMIN toàn cục có ROLE_MANAGE toàn cục cấp phát vai trò cho nhân sự khác, đồng thời truyền `transaction` vào `assertCanDelegate` chống tự khóa chết kết nối CSDL (BUG-048).
      if (!bypassDelegationSubset) {
        await authorization.assertCanDelegate(
          principal,
          role.role_permissions.map((mapping) => mapping.permission_id),
          input.scopeDepartmentId,
          transaction,
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
          .map((p) => p.permissions)
          .filter((p): p is NonNullable<typeof p> => Boolean(p)),
      }));
      if (!areOverlappingRolesSodCompatible([...overlappingDescriptors, candidateDescriptor])) {
        throw new ConflictException(
          'Separation of duties violation: privileged roles and capabilities are mutually exclusive and cannot be combined with business roles.',
        );
      }
      // BUG-006: Chặn tài khoản không phải global SYSTEM_ADMIN gán vai trò lên tài khoản đang giữ vai trò đặc quyền cao hơn hoặc toàn cục.
      await assertCanManageTargetUser({
        transaction,
        actorContext,
        targetUserId: userId,
        now,
      });
      const candidateIsPrivileged = isPrivilegedSeparationRoleOrCapability(
        role.code,
        candidateDescriptor.permissions,
      );
      // CONFLICT-RESOLVED: Hợp nhất BUG-005 và BUG-047 —
      // 1) Khi gán vai trò đặc quyền: chặn 409 nếu người dùng đang sở hữu tài liệu chưa bàn giao (`owner_id`), đồng thời thu hồi dây chuyền mọi USER/ROLE AccessGrant ACTIVE, đóng AccessSession ACTIVE và hủy AccessRequest PENDING của họ.
      // 2) Khi gán vai trò thường đang nắm ROLE grant mức mật cao: chặn 409 nếu người dùng đang giữ vai trò đặc quyền hoặc có bậc thẩm tra thấp hơn bậc mật của ROLE grant (yêu cầu nâng clearance trước, bảo toàn quyền cho các thành viên khác của vai trò).
      if (candidateIsPrivileged) {
        await assertUsersOwnNoBusinessDocuments(transaction, [userId]);
        const overlappingRoleIds = [
          ...new Set([
            input.roleId,
            ...overlappingAssignments
              .map((assignment) => assignment.role_id)
              .filter((rid): rid is bigint => typeof rid === 'bigint'),
          ]),
        ];
        await cascadeCleanupOnPrivilegedRoleEscalation({
          transaction,
          userIds: [userId],
          roleIds: overlappingRoleIds,
          actorUserId: principal.userId,
          reason: `User assigned privileged role ${role.code}`,
          now,
        });
      } else {
        if (
          overlappingDescriptors.some((descriptor) =>
            isPrivilegedSeparationRoleOrCapability(descriptor.code, descriptor.permissions),
          ) &&
          typeof transaction.accessGrant?.count === 'function'
        ) {
          const activeCandidateRoleGrants = await transaction.accessGrant.count({
            where: {
              principal_type: 'ROLE',
              principal_role_id: input.roleId,
              status: 'ACTIVE',
              valid_until: { gt: now },
            },
          });
          if (activeCandidateRoleGrants > 0) {
            throw new ConflictException(
              'Separation of duties violation: cannot assign a role with active document access grants to a privileged user.',
            );
          }
        }
        await assertUserClearanceMeetsActiveRoleGrants({
          transaction,
          userId,
          roleId: input.roleId,
          roleCode: role.code,
          now,
        });
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
      if (candidateIsPrivileged) {
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
  await withSerializableTransaction(
    async (transaction) => {
      const [bypassDelegationSubset, actorContext] = await Promise.all([
        isGlobalSystemAdminRoleManager(authorization, principal, transaction),
        resolveActorGovernanceContext(authorization, principal, transaction),
      ]);
      const assignment = await transaction.userRole.findFirst({
        where: { id: assignmentId, user_id: userId },
        include: { roles: { include: { role_permissions: true } } },
      });
      if (!assignment) throw new NotFoundException('Role assignment not found.');
      const user = await transaction.user.findUniqueOrThrow({ where: { id: userId } });
      await authorization.assertPermission(
        principal,
        'USER',
        'MANAGE',
        { targetDepartmentId: user.department_id },
        transaction,
      );
      await authorization.assertPermission(
        principal,
        'USER',
        'MANAGE',
        { targetDepartmentId: assignment.scope_department_id },
        transaction,
      );
      const now = new Date();
      // BUG-006: Ngăn tài khoản không phải global SYSTEM_ADMIN thu hồi vai trò của tài khoản đặc quyền cao hơn hoặc toàn cục.
      await assertCanManageTargetUser({
        transaction,
        actorContext,
        targetUserId: userId,
        now,
      });
      if (!bypassDelegationSubset && assignment.roles?.role_permissions) {
        await authorization.assertCanDelegate(
          principal,
          assignment.roles.role_permissions.map((mapping) => mapping.permission_id),
          assignment.scope_department_id,
          transaction,
        );
      }
      if (assignment.valid_to !== null && assignment.valid_to <= now) {
        throw new ConflictException('Role assignment is already inactive.');
      }
      // BUG-006: Trong giao dịch SERIALIZABLE, bắt buộc duy trì ít nhất 1 global SYSTEM_ADMIN đang ACTIVE sau khi thu hồi.
      await assertNotLastActiveGlobalSystemAdminForAssignment({
        transaction,
        assignment,
        targetUserStatus: user.status,
        now,
      });
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
      // BUG-047: Đóng tức thì mọi AccessSession đang ACTIVE mà người dùng đã mở qua ROLE grant của vai trò vừa gỡ.
      await terminateUserSessionsOpenedViaRevokedRole({
        transaction,
        userId,
        roleId: assignment.role_id,
        roleCode: assignment.roles?.code,
        now,
      });
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

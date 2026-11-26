/**
 * @module RbacUserGovernanceHelper
 * Thuật toán:
 *   1. Phân tầng thẩm quyền quản lý tài khoản chống nghịch đảo đặc quyền (`assertCanManageTargetUser`):
 *      - Chỉ `SYSTEM_ADMIN` toàn cục mới được tác động lên tài khoản nắm vai trò đặc quyền hệ thống
 *        (`SYSTEM_ADMIN`, `SECURITY_OFFICER`, `AUDITOR`) hoặc vai trò phạm vi toàn cục (`scope_department_id === null`).
 *      - Với tài khoản giữ vai trò tùy chỉnh có năng lực đặc quyền theo phòng ban, người thực thi không phải
 *        `SYSTEM_ADMIN` toàn cục bắt buộc phải thống trị toàn bộ tập quyền ở phạm vi tổ tiên rộng hơn hẳn.
 *   2. Bất biến duy trì ít nhất 1 `SYSTEM_ADMIN` toàn cục đang `ACTIVE` (`assertNotLastActiveGlobalSystemAdmin*`):
 *      - Kiểm chứng ngay trong giao dịch `SERIALIZABLE` trước khi khóa/vô hiệu hóa tài khoản hoặc thu hồi
 *        phép gán `SYSTEM_ADMIN` toàn cục (chống cả khóa chết đơn luồng lẫn thu hồi chéo đồng thời).
 */
import { ConflictException, ForbiddenException } from '@nestjs/common';
import type { Prisma, withSerializableTransaction } from '@sda/database';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { EffectiveGrant } from './authorization-cache.js';
import type { AuthorizationService } from './authorization.service.js';
import {
  isPrivilegedSeparationRoleOrCapability,
  PRIVILEGED_SEPARATION_ROLES,
} from './permission-matrix.js';

type SerializableTransaction = Parameters<Parameters<typeof withSerializableTransaction>[0]>[0];

export interface ActorGovernanceContext {
  isGlobalSystemAdmin: boolean;
  grants: EffectiveGrant[] | null;
}

/**
 * Thuật toán: Nạp tập quyền hiệu lực và cờ `isGlobalSystemAdmin` ngay trên kết nối `tx` của giao dịch `SERIALIZABLE` đang mở
 * (tốn 0 kết nối phụ chống Self-Deadlock `BUG-048` đồng thời bảo toàn cô lập chống TOCTOU).
 */
export async function resolveActorGovernanceContext(
  authorization: AuthorizationService,
  principal: AuthPrincipal,
  tx?: Prisma.TransactionClient,
): Promise<ActorGovernanceContext> {
  if (typeof authorization.effectiveGrants === 'function') {
    const grants = await authorization.effectiveGrants(principal.userId, tx);
    const hasGlobalSystemAdminRole = grants.some(
      (grant) => grant.roleCode === 'SYSTEM_ADMIN' && grant.scopeDepartmentId === null,
    );
    const hasGlobalManagePerm = grants.some(
      (grant) =>
        grant.scopeDepartmentId === null &&
        ((grant.resource === 'USER' && grant.action === 'MANAGE') ||
          (grant.resource === 'ROLE' && grant.action === 'MANAGE')),
    );
    return {
      isGlobalSystemAdmin: hasGlobalSystemAdminRole && hasGlobalManagePerm,
      grants,
    };
  }
  return {
    isGlobalSystemAdmin: false,
    grants: null,
  };
}

/**
 * Thuật toán: Duyệt ngược tập tổ tiên thực sự (không gồm chính `departmentId`) có chốt chặn chu trình `visited`
 * ngay trên giao dịch `SERIALIZABLE` để kiểm chứng quan hệ thống trị phạm vi nghiêm ngặt.
 */
async function strictDepartmentAncestors(
  transaction: SerializableTransaction,
  departmentId: bigint,
): Promise<Set<bigint>> {
  const ancestors = new Set<bigint>();
  if (typeof transaction.department?.findUnique !== 'function') {
    return ancestors;
  }
  const visited = new Set<bigint>([departmentId]);
  const selfNode: { parent_id: bigint | null } | null = await transaction.department.findUnique({
    where: { id: departmentId },
    select: { parent_id: true },
  });
  let current: bigint | null = selfNode?.parent_id ?? null;
  while (current !== null && !visited.has(current)) {
    visited.add(current);
    ancestors.add(current);
    const parentNode: { parent_id: bigint | null } | null = await transaction.department.findUnique(
      {
        where: { id: current },
        select: { parent_id: true },
      },
    );
    current = parentNode?.parent_id ?? null;
  }
  return ancestors;
}

/**
 * Thuật toán: Cưỡng chế phân tầng quyền quản lý người dùng chống nghịch đảo đặc quyền (Anti-Privilege-Inversion).
 * Ngăn quản lý cấp phòng ban hoặc quản trị viên cấp thấp tác động lên tài khoản nắm vai trò `SYSTEM_ADMIN`,
 * `SECURITY_OFFICER`, `AUDITOR`, vai trò toàn cục (`scope_department_id === null`), hoặc quản trị viên ngang/cao cấp hơn.
 */
export async function assertCanManageTargetUser(params: {
  transaction: SerializableTransaction;
  actorContext: ActorGovernanceContext;
  targetUserId: bigint;
  now: Date;
}): Promise<void> {
  const { transaction, actorContext, targetUserId, now } = params;
  if (actorContext.isGlobalSystemAdmin) {
    return;
  }
  if (typeof transaction.userRole?.findMany !== 'function') {
    return;
  }
  const targetAssignments = await transaction.userRole.findMany({
    where: {
      user_id: targetUserId,
      roles: { is_active: true },
      OR: [{ valid_to: null }, { valid_to: { gt: now } }],
    },
    include: {
      roles: { include: { role_permissions: { include: { permissions: true } } } },
    },
  });

  const ancestorCache = new Map<string, Set<bigint>>();

  for (const assignment of targetAssignments) {
    const roleCode = assignment.roles?.code;
    const roleMappings = assignment.roles?.role_permissions ?? [];
    const rolePerms = roleMappings
      .map((mapping) => mapping.permissions)
      .filter((permission): permission is NonNullable<typeof permission> => Boolean(permission));
    const rolePermIds = roleMappings
      .map((mapping) => mapping.permission_id ?? mapping.permissions?.id)
      .filter((permissionId): permissionId is bigint => typeof permissionId === 'bigint');

    if (roleCode !== undefined && PRIVILEGED_SEPARATION_ROLES.has(roleCode)) {
      throw new ForbiddenException(
        'Only a global SYSTEM_ADMIN can manage accounts holding system privileged roles.',
      );
    }
    if (assignment.scope_department_id === null) {
      throw new ForbiddenException(
        'Only a global SYSTEM_ADMIN can manage accounts holding global-scoped roles.',
      );
    }
    if (isPrivilegedSeparationRoleOrCapability(roleCode, rolePerms)) {
      if (!actorContext.grants || rolePermIds.length === 0) {
        throw new ForbiddenException(
          'Insufficient authority to manage an account holding privileged roles.',
        );
      }
      const targetScopeId = assignment.scope_department_id;
      const scopeKey = targetScopeId.toString();
      let strictAncestors = ancestorCache.get(scopeKey);
      if (!strictAncestors) {
        strictAncestors = await strictDepartmentAncestors(transaction, targetScopeId);
        ancestorCache.set(scopeKey, strictAncestors);
      }
      const strictlyDominates = rolePermIds.every((permissionId) =>
        actorContext.grants!.some(
          (grant) =>
            grant.permissionId === permissionId &&
            (grant.scopeDepartmentId === null ||
              (grant.scopeDepartmentId !== targetScopeId &&
                strictAncestors.has(grant.scopeDepartmentId))),
        ),
      );
      if (!strictlyDominates) {
        throw new ForbiddenException(
          'Cannot manage an account holding equal or higher privileged capabilities.',
        );
      }
    }
  }
}

/**
 * Thuật toán: Chốt chặn bất biến "Còn ít nhất 1 `SYSTEM_ADMIN` toàn cục đang `ACTIVE`" trước khi khóa/vô hiệu hóa tài khoản.
 * Thực thi bên trong giao dịch `SERIALIZABLE` để chống cả thao tác đơn luồng lẫn khóa/vô hiệu hóa chéo đồng thời.
 */
export async function assertNotLastActiveGlobalSystemAdminForUser(params: {
  transaction: SerializableTransaction;
  targetUserId: bigint;
  now: Date;
}): Promise<void> {
  const { transaction, targetUserId, now } = params;
  if (typeof transaction.userRole?.count !== 'function') {
    return;
  }
  const targetHoldsActiveGlobalSysAdmin =
    (await transaction.userRole.count({
      where: {
        user_id: targetUserId,
        scope_department_id: null,
        valid_from: { lte: now },
        OR: [{ valid_to: null }, { valid_to: { gt: now } }],
        roles: { code: 'SYSTEM_ADMIN', is_active: true },
      },
    })) > 0;
  if (!targetHoldsActiveGlobalSysAdmin) {
    return;
  }
  const otherActiveGlobalSysAdmins = await transaction.userRole.count({
    where: {
      user_id: { not: targetUserId },
      scope_department_id: null,
      valid_from: { lte: now },
      OR: [{ valid_to: null }, { valid_to: { gt: now } }],
      roles: { code: 'SYSTEM_ADMIN', is_active: true },
      users_user_roles_user_idTousers: { status: 'ACTIVE' },
    },
  });
  if (otherActiveGlobalSysAdmins < 1) {
    throw new ConflictException(
      'Cannot lock or disable the last active global SYSTEM_ADMIN account.',
    );
  }
}

/**
 * Thuật toán: Chốt chặn bất biến "Còn ít nhất 1 `SYSTEM_ADMIN` toàn cục đang `ACTIVE`" trước khi thu hồi phép gán vai trò.
 */
export async function assertNotLastActiveGlobalSystemAdminForAssignment(params: {
  transaction: SerializableTransaction;
  assignment: {
    id: bigint;
    scope_department_id: bigint | null;
    valid_from: Date;
    valid_to: Date | null;
    roles?: { code?: string; is_active?: boolean } | null;
  };
  targetUserStatus: string;
  now: Date;
}): Promise<void> {
  const { transaction, assignment, targetUserStatus, now } = params;
  if (typeof transaction.userRole?.count !== 'function') {
    return;
  }
  const isActiveGlobalSysAdminAssignment =
    targetUserStatus === 'ACTIVE' &&
    assignment.roles?.code === 'SYSTEM_ADMIN' &&
    assignment.roles?.is_active !== false &&
    assignment.scope_department_id === null &&
    assignment.valid_from <= now &&
    (assignment.valid_to === null || assignment.valid_to > now);
  if (!isActiveGlobalSysAdminAssignment) {
    return;
  }
  const remainingGlobalSysAdmins = await transaction.userRole.count({
    where: {
      id: { not: assignment.id },
      scope_department_id: null,
      valid_from: { lte: now },
      OR: [{ valid_to: null }, { valid_to: { gt: now } }],
      roles: { code: 'SYSTEM_ADMIN', is_active: true },
      users_user_roles_user_idTousers: { status: 'ACTIVE' },
    },
  });
  if (remainingGlobalSysAdmins < 1) {
    throw new ConflictException(
      'Cannot revoke the last active global SYSTEM_ADMIN role assignment.',
    );
  }
}

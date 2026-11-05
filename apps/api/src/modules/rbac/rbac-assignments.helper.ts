/**
 * Module: RBAC Temporal SoD User-Role Assignment & Revocation Helper
 * Algorithm: Enforces department subtree containment, delegation ceilings, and half-open temporal
 *   interval overlap checks (`[valid_from, valid_to)`) over `PRIVILEGED_SEPARATION_ROLES`.
 */
import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { withSerializableTransaction, type getDatabaseClient } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from './authorization.service.js';
import { PRIVILEGED_SEPARATION_ROLES } from './permission-matrix.js';
import type { RbacAuditService } from './rbac-audit.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm: Temporal Separation-of-Duties (SoD) & Department-Subtree User Role Assignment
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
): Promise<{ id: string }> {
  if (principal.userId === userId) {
    throw new ForbiddenException('Administrators cannot assign roles to themselves.');
  }
  const id = await withSerializableTransaction(async (transaction) => {
    const [user, role] = await Promise.all([
      transaction.user.findUnique({ where: { id: userId } }),
      transaction.role.findFirst({
        where: { id: input.roleId, is_active: true },
        include: { role_permissions: true },
      }),
    ]);
    if (!user || user.status === 'DISABLED') throw new NotFoundException('Active user not found.');
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
    await authorization.assertCanDelegate(
      principal,
      role.role_permissions.map((mapping) => mapping.permission_id),
      input.scopeDepartmentId,
    );
    // CONFLICT-RESOLVED: Enforce bidirectional Temporal SoD so PRIVILEGED_SEPARATION_ROLES
    // (SYSTEM_ADMIN, SECURITY_OFFICER, AUDITOR) cannot stack with one another OR with any business/custom role.
    const incompatibleRoleFilter = PRIVILEGED_SEPARATION_ROLES.has(role.code)
      ? { is_active: true, code: { not: role.code } }
      : { is_active: true, code: { in: [...PRIVILEGED_SEPARATION_ROLES] } };
    const incompatible = await transaction.userRole.findFirst({
      where: {
        user_id: userId,
        roles: incompatibleRoleFilter,
        AND: [
          { OR: [{ valid_to: null }, { valid_to: { gt: input.validFrom } }] },
          ...(input.validTo !== null ? [{ valid_from: { lt: input.validTo } }] : []),
        ],
      },
    });
    if (incompatible) {
      throw new ConflictException(
        'Separation of duties violation: privileged roles are mutually exclusive and cannot be combined with business roles.',
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
  });
  authorization.invalidateUser(userId);
  return { id: id.toString() };
}

/**
 * Algorithm: Delegation-Bounded Serializable User Role Revocation
 */
export async function executeRevokeUserRole(
  authorization: AuthorizationService,
  audit: RbacAuditService,
  principal: AuthPrincipal,
  userId: bigint,
  assignmentId: bigint,
  context: RequestContext,
): Promise<void> {
  if (principal.userId === userId) {
    throw new ForbiddenException('Administrators cannot revoke their own roles.');
  }
  await withSerializableTransaction(async (transaction) => {
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
    if (assignment.roles?.role_permissions) {
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
    const after = await transaction.userRole.update({
      where: { id: assignmentId },
      data: { valid_to: now },
    });
    await audit.record(
      transaction,
      {
        action: 'USER_ROLE_REVOKED',
        objectType: 'USER_ROLE',
        objectId: assignmentId.toString(),
        before: auditAssignmentSnapshot(assignment),
        after: auditAssignmentSnapshot(after),
      },
      principal,
      context,
    );
  });
  authorization.invalidateUser(userId);
}

/**
 * Algorithm: Temporal Half-Open Active Role Membership Predicate
 */
export async function actorHoldsActiveRole(
  database: PrismaClient,
  userId: bigint,
  roleId: bigint,
): Promise<boolean> {
  const now = new Date();
  return (
    (await database.userRole.count({
      where: {
        user_id: userId,
        role_id: roleId,
        valid_from: { lte: now },
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

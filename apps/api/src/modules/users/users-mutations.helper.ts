/**
 * Module: Serializable User Lifecycle Mutations Helper
 * Algorithm: Executes `SERIALIZABLE` user provisioning, optimistic Compare-And-Swap (`version`) profile updates
 *   with automatic old-department role expiration, and status changes with cascading session revocation.
 */
import { ConflictException, NotFoundException } from '@nestjs/common';
import { withSerializableTransaction, type getDatabaseClient } from '@sda/database';

type PrismaClient = ReturnType<typeof getDatabaseClient>;
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { PasswordService } from '../auth/password.service.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { RbacAuditService } from '../rbac/rbac-audit.service.js';
import {
  auditUserSnapshot,
  expirePreviousDepartmentRoles,
  presentUserRecord,
  revokeUserActiveSessions,
  type CreateUserInput,
  type UpdateUserInput,
} from './users-clearance.helper.js';

/**
 * Algorithm: Anti-Enumeration Department Visibility Check
 */
export async function assertUserDepartmentVisible(
  authorization: AuthorizationService,
  principal: AuthPrincipal,
  departmentId: bigint | null,
): Promise<void> {
  if (
    !(await authorization.hasPermission(principal, 'USER', 'MANAGE', {
      targetDepartmentId: departmentId,
    }))
  ) {
    throw new NotFoundException('User not found.');
  }
}

/**
 * Algorithm: Serializable User Provisioning with Argon2id Pre-Hashing
 */
export async function executeCreateUser(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  passwords: PasswordService;
  audit: RbacAuditService;
  principal: AuthPrincipal;
  input: CreateUserInput;
  context: RequestContext;
}): Promise<{ id: string }> {
  const { database, authorization, passwords, audit, principal, input, context } = params;
  await authorization.assertPermission(principal, 'USER', 'MANAGE', {
    targetDepartmentId: input.departmentId ?? null,
  });
  passwords.validate(input.password, [input.username, input.email]);
  const passwordHash = await passwords.hash(input.password);

  const id = await withSerializableTransaction(
    async (transaction) => {
      if (input.departmentId !== null && input.departmentId !== undefined) {
        const department = await transaction.department.findFirst({
          where: { id: input.departmentId, is_active: true },
          select: { id: true },
        });
        if (!department) throw new NotFoundException('Active department not found.');
      }
      const user = await transaction.user.create({
        data: {
          username: input.username,
          email: input.email,
          full_name: input.fullName,
          employee_code: input.employeeCode ?? null,
          department_id: input.departmentId ?? null,
          password_hash: passwordHash,
          status: 'ACTIVE',
          created_by: principal.userId,
        },
      });
      await audit.record(
        transaction,
        {
          action: 'USER_CREATED',
          objectType: 'USER',
          objectId: user.id.toString(),
          before: null,
          after: auditUserSnapshot(user),
        },
        principal,
        context,
      );
      return user.id;
    },
    { client: database },
  );

  authorization.invalidateUser(id);
  return { id: id.toString() };
}

/**
 * Algorithm: Optimistic CAS User Update with Department-Transfer Role Expiration
 */
export async function executeUpdateUser(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  audit: RbacAuditService;
  principal: AuthPrincipal;
  id: bigint;
  input: UpdateUserInput;
  context: RequestContext;
}) {
  const { database, authorization, audit, principal, id, input, context } = params;
  const result = await withSerializableTransaction(
    async (transaction) => {
      const before = await transaction.user.findUnique({ where: { id } });
      if (!before) throw new NotFoundException('User not found.');
      await assertUserDepartmentVisible(authorization, principal, before.department_id);
      const targetDepartment =
        input.departmentId === undefined ? before.department_id : input.departmentId;
      await authorization.assertPermission(principal, 'USER', 'MANAGE', {
        targetDepartmentId: targetDepartment,
      });
      if (targetDepartment !== null && targetDepartment !== before.department_id) {
        const department = await transaction.department.findFirst({
          where: { id: targetDepartment, is_active: true },
          select: { id: true },
        });
        if (!department) throw new NotFoundException('Active department not found.');
      }
      const changed = await transaction.user.updateMany({
        where: { id, version: input.expectedVersion },
        data: {
          ...(input.email !== undefined ? { email: input.email } : {}),
          ...(input.fullName !== undefined ? { full_name: input.fullName } : {}),
          ...(input.employeeCode !== undefined ? { employee_code: input.employeeCode } : {}),
          ...(input.departmentId !== undefined ? { department_id: input.departmentId } : {}),
          updated_at: new Date(),
          version: { increment: 1 },
        },
      });
      if (changed.count !== 1) throw new ConflictException('User was changed by another request.');
      if (
        input.departmentId !== undefined &&
        before.department_id !== input.departmentId &&
        before.department_id !== null
      ) {
        await expirePreviousDepartmentRoles(transaction, id, before.department_id);
      }
      const after = await transaction.user.findUniqueOrThrow({ where: { id } });
      await audit.record(
        transaction,
        {
          action: 'USER_UPDATED',
          objectType: 'USER',
          objectId: id.toString(),
          before: auditUserSnapshot(before),
          after: auditUserSnapshot(after),
        },
        principal,
        context,
      );
      return after;
    },
    { client: database },
  );

  authorization.invalidateUser(id);
  return presentUserRecord(result);
}

/**
 * Algorithm: CAS Account Status Transition with Cascading Session Revocation
 */
export async function executeChangeUserStatus(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  audit: RbacAuditService;
  principal: AuthPrincipal;
  id: bigint;
  expectedVersion: number;
  status: 'ACTIVE' | 'LOCKED' | 'DISABLED';
  action: string;
  context: RequestContext;
}) {
  const {
    database,
    authorization,
    audit,
    principal,
    id,
    expectedVersion,
    status,
    action,
    context,
  } = params;
  const result = await withSerializableTransaction(
    async (transaction) => {
      const before = await transaction.user.findUnique({ where: { id } });
      if (!before) throw new NotFoundException('User not found.');
      await assertUserDepartmentVisible(authorization, principal, before.department_id);
      const now = new Date();
      const changed = await transaction.user.updateMany({
        where: { id, version: expectedVersion },
        data: {
          status,
          disabled_at: status === 'DISABLED' ? now : null,
          locked_until: null,
          ...(status === 'ACTIVE' ? { failed_login_count: 0 } : {}),
          updated_at: now,
          version: { increment: 1 },
        },
      });
      if (changed.count !== 1) throw new ConflictException('User was changed by another request.');
      if (status !== 'ACTIVE') {
        await revokeUserActiveSessions(transaction, id, status, action, now);
      }
      const after = await transaction.user.findUniqueOrThrow({ where: { id } });
      await audit.record(
        transaction,
        {
          action,
          objectType: 'USER',
          objectId: id.toString(),
          before: auditUserSnapshot(before),
          after: auditUserSnapshot(after),
        },
        principal,
        context,
      );
      return after;
    },
    { client: database },
  );

  authorization.invalidateUser(id);
  return presentUserRecord(result);
}

/**
 * Module: Serializable User Lifecycle Mutations Helper
 * Algorithm: Executes `SERIALIZABLE` user provisioning, optimistic Compare-And-Swap (`version`) profile updates
 *   with automatic old-department role expiration, and status changes with cascading session revocation.
 */
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { withSerializableTransaction, type getDatabaseClient, type Prisma } from '@sda/database';

type PrismaClient = ReturnType<typeof getDatabaseClient>;
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { PasswordService } from '../auth/password.service.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { RbacAuditService } from '../rbac/rbac-audit.service.js';
import {
  assertCanManageTargetUser,
  assertNotLastActiveGlobalSystemAdminForUser,
  resolveActorGovernanceContext,
} from '../rbac/rbac-user-governance.helper.js';
import {
  auditUserSnapshot,
  EMPTY_CLEARANCE_SUMMARY,
  expirePreviousDepartmentRoles,
  presentUserRecord,
  revokeUserActiveSessions,
  type ClearanceSummary,
  type CreateUserInput,
  type UpdateUserClearanceInput,
  type UpdateUserInput,
} from './users-clearance.helper.js';
import {
  fetchActiveUserClearance,
  syncUserClearanceAssignment,
} from './users-clearance-assignment.helper.js';

/**
 * Algorithm: Anti-Enumeration Department Visibility Check (reuses open `tx` inside `SERIALIZABLE` transactions, `BUG-048`).
 */
export async function assertUserDepartmentVisible(
  authorization: AuthorizationService,
  principal: AuthPrincipal,
  departmentId: bigint | null,
  tx?: Prisma.TransactionClient,
): Promise<void> {
  if (
    !(await authorization.hasPermission(
      principal,
      'USER',
      'MANAGE',
      { targetDepartmentId: departmentId },
      tx,
    ))
  ) {
    throw new NotFoundException('User not found.');
  }
}

/**
 * Algorithm: Serializable User Provisioning with Argon2id Pre-Hashing & In-Transaction Scope Re-Assertion (`BUG-048`)
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
  if (input.departmentId === null || input.departmentId === undefined) {
    throw new BadRequestException(
      'Active departmentId is required because SUBJECT_DEPARTMENT is mandatory under ABAC policy.',
    );
  }
  const targetDepartmentId = input.departmentId;
  await authorization.assertPermission(principal, 'USER', 'MANAGE', {
    targetDepartmentId,
  });
  passwords.validate(input.password, [input.username, input.email]);
  const passwordHash = await passwords.hash(input.password);

  const id = await withSerializableTransaction(
    async (transaction) => {
      await authorization.assertPermission(
        principal,
        'USER',
        'MANAGE',
        { targetDepartmentId },
        transaction,
      );
      if (input.departmentId !== null && input.departmentId !== undefined) {
        const department = await transaction.department.findFirst({
          where: { id: input.departmentId, is_active: true },
          select: { id: true },
        });
        if (!department) throw new NotFoundException('Active department not found.');
      }
      const now = new Date();
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
      let initialClearance: ClearanceSummary = { ...EMPTY_CLEARANCE_SUMMARY };
      if (input.clearanceOptionId !== undefined && input.clearanceOptionId !== null) {
        const synced = await syncUserClearanceAssignment({
          transaction,
          userId: user.id,
          clearanceOptionId: input.clearanceOptionId,
          actorUserId: principal.userId,
          now,
        });
        initialClearance = synced.after;
      }
      await audit.record(
        transaction,
        {
          action: 'USER_CREATED',
          objectType: 'USER',
          objectId: user.id.toString(),
          before: null,
          after: {
            ...auditUserSnapshot(user),
            ...initialClearance,
          },
        },
        principal,
        context,
      );
      return user.id;
    },
    { client: database },
  );

  await authorization.invalidateUser(id);
  return { id: id.toString() };
}

/**
 * Algorithm: Optimistic CAS User Update with Department-Transfer Role Expiration & Optional Clearance Sync
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
  // BUG-007: Chặn tự nâng hoặc tự thay đổi bậc thẩm tra an ninh của chính mình (Self-Clearance Escalation).
  if (principal.userId === id && input.clearanceOptionId !== undefined) {
    throw new ForbiddenException('Administrators cannot modify their own security clearance.');
  }
  const result = await withSerializableTransaction(
    async (transaction) => {
      const actorContext = await resolveActorGovernanceContext(
        authorization,
        principal,
        transaction,
      );
      const before = await transaction.user.findUnique({ where: { id } });
      if (!before) throw new NotFoundException('User not found.');
      await assertUserDepartmentVisible(
        authorization,
        principal,
        before.department_id,
        transaction,
      );
      const now = new Date();
      // BUG-006: Ngăn quản lý cấp phòng ban hoặc cấp thấp hơn chỉnh sửa thông tin/email/phòng ban của tài khoản đặc quyền hoặc toàn cục.
      await assertCanManageTargetUser({
        transaction,
        actorContext,
        targetUserId: id,
        now,
      });
      if (input.departmentId === null) {
        throw new BadRequestException(
          'Department cannot be cleared because SUBJECT_DEPARTMENT is mandatory under ABAC policy.',
        );
      }
      const targetDepartment =
        input.departmentId === undefined ? before.department_id : input.departmentId;
      await authorization.assertPermission(
        principal,
        'USER',
        'MANAGE',
        { targetDepartmentId: targetDepartment },
        transaction,
      );
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
          updated_at: now,
          version: { increment: 1 },
        },
      });
      if (changed.count !== 1) throw new ConflictException('User was changed by another request.');
      if (
        input.departmentId !== undefined &&
        before.department_id !== input.departmentId &&
        before.department_id !== null
      ) {
        await expirePreviousDepartmentRoles(
          transaction,
          id,
          before.department_id,
          now,
          input.departmentId ?? null,
        );
      }

      let beforeClearance: ClearanceSummary | undefined;
      let afterClearance: ClearanceSummary;
      let clearanceCascadeDetails: Record<string, number> = {};
      if (input.clearanceOptionId !== undefined) {
        const synced = await syncUserClearanceAssignment({
          transaction,
          userId: id,
          clearanceOptionId: input.clearanceOptionId,
          actorUserId: principal.userId,
          now,
        });
        beforeClearance = synced.before;
        afterClearance = synced.after;
        if (synced.changed) {
          clearanceCascadeDetails = {
            revokedGrantsCount: synced.revokedGrantsCount,
            terminatedSessionsCount: synced.terminatedSessionsCount,
          };
        }
      } else {
        afterClearance = await fetchActiveUserClearance(transaction, id, now);
      }

      const after = await transaction.user.findUniqueOrThrow({ where: { id } });
      await audit.record(
        transaction,
        {
          action: 'USER_UPDATED',
          objectType: 'USER',
          objectId: id.toString(),
          before: {
            ...auditUserSnapshot(before),
            ...(beforeClearance ?? {}),
          },
          after: {
            ...auditUserSnapshot(after),
            ...(beforeClearance ? afterClearance : {}),
            ...clearanceCascadeDetails,
          },
        },
        principal,
        context,
      );
      return { after, clearance: afterClearance };
    },
    { client: database },
  );

  await authorization.invalidateUser(id);
  return {
    ...presentUserRecord(result.after),
    ...result.clearance,
  };
}

/**
 * Algorithm: Optimistic CAS Bell-LaPadula Clearance Assignment with Cascading Downgrade Revocation
 */
export async function executeUpdateUserClearance(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  audit: RbacAuditService;
  principal: AuthPrincipal;
  id: bigint;
  input: UpdateUserClearanceInput;
  context: RequestContext;
}) {
  const { database, authorization, audit, principal, id, input, context } = params;
  // BUG-007: Chặn tự nâng hoặc tự thay đổi bậc thẩm tra an ninh của chính mình (Self-Clearance Escalation).
  if (principal.userId === id && input.clearanceOptionId !== undefined) {
    throw new ForbiddenException('Administrators cannot modify their own security clearance.');
  }
  const result = await withSerializableTransaction(
    async (transaction) => {
      const actorContext = await resolveActorGovernanceContext(
        authorization,
        principal,
        transaction,
      );
      const before = await transaction.user.findUnique({ where: { id } });
      if (!before) throw new NotFoundException('User not found.');
      await assertUserDepartmentVisible(
        authorization,
        principal,
        before.department_id,
        transaction,
      );
      const now = new Date();
      // BUG-006: Chặn quản lý cấp phòng ban thay đổi độ mật của tài khoản nắm vai trò đặc quyền hoặc toàn cục.
      await assertCanManageTargetUser({
        transaction,
        actorContext,
        targetUserId: id,
        now,
      });
      const changed = await transaction.user.updateMany({
        where: { id, version: input.expectedVersion },
        data: {
          updated_at: now,
          version: { increment: 1 },
        },
      });
      if (changed.count !== 1) throw new ConflictException('User was changed by another request.');

      const synced = await syncUserClearanceAssignment({
        transaction,
        userId: id,
        clearanceOptionId: input.clearanceOptionId,
        actorUserId: principal.userId,
        now,
      });

      const after = await transaction.user.findUniqueOrThrow({ where: { id } });
      await audit.record(
        transaction,
        {
          action: 'USER_CLEARANCE_UPDATED',
          objectType: 'USER',
          objectId: id.toString(),
          before: {
            ...auditUserSnapshot(before),
            ...synced.before,
          },
          after: {
            ...auditUserSnapshot(after),
            ...synced.after,
            revokedGrantsCount: synced.revokedGrantsCount,
            terminatedSessionsCount: synced.terminatedSessionsCount,
          },
        },
        principal,
        context,
      );
      return {
        after,
        clearance: synced.after,
        revokedGrantsCount: synced.revokedGrantsCount,
        terminatedSessionsCount: synced.terminatedSessionsCount,
      };
    },
    { client: database },
  );

  await authorization.invalidateUser(id);
  return {
    ...presentUserRecord(result.after),
    ...result.clearance,
    revokedGrantsCount: result.revokedGrantsCount,
    terminatedSessionsCount: result.terminatedSessionsCount,
  };
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
  allowDisabledReactivation?: boolean;
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
    allowDisabledReactivation = false,
  } = params;
  const result = await withSerializableTransaction(
    async (transaction) => {
      const actorContext = await resolveActorGovernanceContext(
        authorization,
        principal,
        transaction,
      );
      const before = await transaction.user.findUnique({ where: { id } });
      if (!before) throw new NotFoundException('User not found.');
      await assertUserDepartmentVisible(
        authorization,
        principal,
        before.department_id,
        transaction,
      );
      const now = new Date();
      // BUG-006: Ngăn tài khoản không phải global SYSTEM_ADMIN khóa/mở khóa/vô hiệu hóa/kích hoạt lại tài khoản đặc quyền hoặc toàn cục.
      await assertCanManageTargetUser({
        transaction,
        actorContext,
        targetUserId: id,
        now,
      });
      // Thuật toán: Máy trạng thái hữu hạn chuyển đổi trạng thái tài khoản tường minh (Explicit User Status State Machine, BUG-105):
      // - LOCKED: chỉ cho phép từ ACTIVE (chặn lách DISABLED -> LOCKED -> ACTIVE xóa mất disabled_at và chặn khóa PENDING).
      // - USER_UNLOCKED: chỉ cho phép từ LOCKED (chặn mở khóa PENDING hoặc DISABLED).
      // - USER_REACTIVATED: chỉ cho phép từ DISABLED hoặc PENDING (xóa sạch disabled_at, locked_until, failed_login_count).
      // - DISABLED: từ chối lặp vô hiệu hóa tài khoản đã DISABLED bằng 409 ConflictException.
      if (status === 'LOCKED' && before.status !== 'ACTIVE') {
        throw new ConflictException(
          `Cannot lock account in ${before.status} status; only ACTIVE accounts can be locked.`,
        );
      }
      if (status === 'ACTIVE' && !allowDisabledReactivation && before.status !== 'LOCKED') {
        throw new ConflictException(
          `Cannot unlock account in ${before.status} status; only LOCKED accounts can be unlocked.`,
        );
      }
      if (
        status === 'ACTIVE' &&
        allowDisabledReactivation &&
        before.status !== 'DISABLED' &&
        before.status !== 'PENDING'
      ) {
        throw new ConflictException(
          `Cannot reactivate account in ${before.status} status; only DISABLED or PENDING accounts can be reactivated.`,
        );
      }
      if (status === 'DISABLED' && before.status === 'DISABLED') {
        throw new ConflictException('Account is already disabled.');
      }
      // BUG-006: Trong giao dịch SERIALIZABLE, bắt buộc duy trì ít nhất 1 global SYSTEM_ADMIN đang ACTIVE sau khi khóa/vô hiệu hóa.
      if (status !== 'ACTIVE' && before.status === 'ACTIVE') {
        await assertNotLastActiveGlobalSystemAdminForUser({
          transaction,
          targetUserId: id,
          now,
        });
      }
      const changed = await transaction.user.updateMany({
        where: { id, version: expectedVersion, status: before.status },
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

  await authorization.invalidateUser(id);
  return presentUserRecord(result);
}

import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { getDatabaseClient, withSerializableTransaction } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { PasswordService } from '../auth/password.service.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { RbacAuditService } from '../rbac/rbac-audit.service.js';

interface CreateUserInput {
  username: string;
  email: string;
  fullName: string;
  employeeCode?: string | null | undefined;
  departmentId?: bigint | null | undefined;
  password: string;
}

interface UpdateUserInput {
  expectedVersion: number;
  email?: string | undefined;
  fullName?: string | undefined;
  employeeCode?: string | null | undefined;
  departmentId?: bigint | null | undefined;
}

@Injectable()
export class UsersService {
  private readonly database = getDatabaseClient();

  constructor(
    private readonly authorization: AuthorizationService,
    private readonly passwords: PasswordService,
    private readonly audit: RbacAuditService,
  ) {}

  async currentUser(principal: AuthPrincipal) {
    const user = await this.database.user.findUnique({
      where: { id: principal.userId },
      select: {
        id: true,
        username: true,
        email: true,
        full_name: true,
        department_id: true,
        status: true,
        version: true,
      },
    });
    if (!user) throw new NotFoundException('User not found.');
    const grants = await this.authorization.effectiveGrants(principal.userId);
    return {
      ...this.present(user),
      roles: [...new Set(grants.map((grant) => grant.roleCode))].sort(),
      permissions: [...new Set(grants.map((grant) => `${grant.resource}:${grant.action}`))].sort(),
    };
  }

  async list(principal: AuthPrincipal) {
    const visible = await this.authorization.visibleDepartmentIds(principal, 'USER', 'MANAGE');
    const users = await this.database.user.findMany({
      where: visible === null ? {} : { department_id: { in: visible } },
      orderBy: [{ full_name: 'asc' }, { id: 'asc' }],
      select: {
        id: true,
        username: true,
        email: true,
        full_name: true,
        employee_code: true,
        department_id: true,
        status: true,
        locked_until: true,
        version: true,
      },
    });
    return { data: users.map((user) => this.present(user)) };
  }

  async get(principal: AuthPrincipal, id: bigint) {
    const user = await this.database.user.findUnique({
      where: { id },
      select: {
        id: true,
        username: true,
        email: true,
        full_name: true,
        employee_code: true,
        department_id: true,
        status: true,
        locked_until: true,
        disabled_at: true,
        version: true,
        user_roles_user_roles_user_idTousers: {
          include: { roles: true },
          orderBy: { valid_from: 'desc' },
        },
      },
    });
    if (!user) throw new NotFoundException('User not found.');
    await this.assertTargetVisible(principal, user.department_id);
    return {
      ...this.present(user),
      roleAssignments: user.user_roles_user_roles_user_idTousers.map((assignment) => ({
        id: assignment.id.toString(),
        roleId: assignment.role_id.toString(),
        roleCode: assignment.roles.code,
        scopeDepartmentId: assignment.scope_department_id?.toString() ?? null,
        validFrom: assignment.valid_from.toISOString(),
        validTo: assignment.valid_to?.toISOString() ?? null,
      })),
    };
  }

  async create(
    principal: AuthPrincipal,
    input: CreateUserInput,
    context: RequestContext,
  ): Promise<{ id: string }> {
    await this.authorization.assertPermission(principal, 'USER', 'MANAGE', {
      targetDepartmentId: input.departmentId ?? null,
    });
    this.passwords.validate(input.password, [input.username, input.email]);
    const passwordHash = await this.passwords.hash(input.password);
    const id = await withSerializableTransaction(async (transaction) => {
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
      await this.audit.record(
        transaction,
        {
          action: 'USER_CREATED',
          objectType: 'USER',
          objectId: user.id.toString(),
          before: null,
          after: this.auditUser(user),
        },
        principal,
        context,
      );
      return user.id;
    });
    this.authorization.invalidateUser(id);
    return { id: id.toString() };
  }

  async update(
    principal: AuthPrincipal,
    id: bigint,
    input: UpdateUserInput,
    context: RequestContext,
  ) {
    const result = await withSerializableTransaction(async (transaction) => {
      const before = await transaction.user.findUnique({ where: { id } });
      if (!before) throw new NotFoundException('User not found.');
      await this.assertTargetVisible(principal, before.department_id);
      const targetDepartment =
        input.departmentId === undefined ? before.department_id : input.departmentId;
      await this.authorization.assertPermission(principal, 'USER', 'MANAGE', {
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
        const changedAt = new Date();
        await transaction.userRole.updateMany({
          where: {
            user_id: id,
            scope_department_id: before.department_id,
            valid_from: { lt: changedAt },
            OR: [{ valid_to: null }, { valid_to: { gt: changedAt } }],
          },
          data: { valid_to: changedAt },
        });
      }
      const after = await transaction.user.findUniqueOrThrow({ where: { id } });
      await this.audit.record(
        transaction,
        {
          action: 'USER_UPDATED',
          objectType: 'USER',
          objectId: id.toString(),
          before: this.auditUser(before),
          after: this.auditUser(after),
        },
        principal,
        context,
      );
      return after;
    });
    this.authorization.invalidateUser(id);
    return this.present(result);
  }

  lock(principal: AuthPrincipal, id: bigint, expectedVersion: number, context: RequestContext) {
    return this.changeStatus(principal, id, expectedVersion, 'LOCKED', 'USER_LOCKED', context);
  }

  unlock(principal: AuthPrincipal, id: bigint, expectedVersion: number, context: RequestContext) {
    return this.changeStatus(principal, id, expectedVersion, 'ACTIVE', 'USER_UNLOCKED', context);
  }

  disable(principal: AuthPrincipal, id: bigint, expectedVersion: number, context: RequestContext) {
    if (principal.userId === id)
      throw new ForbiddenException('Administrators cannot disable themselves.');
    return this.changeStatus(principal, id, expectedVersion, 'DISABLED', 'USER_DISABLED', context);
  }

  private async changeStatus(
    principal: AuthPrincipal,
    id: bigint,
    expectedVersion: number,
    status: 'ACTIVE' | 'LOCKED' | 'DISABLED',
    action: string,
    context: RequestContext,
  ) {
    const result = await withSerializableTransaction(async (transaction) => {
      const before = await transaction.user.findUnique({ where: { id } });
      if (!before) throw new NotFoundException('User not found.');
      await this.assertTargetVisible(principal, before.department_id);
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
        await transaction.refreshToken.updateMany({
          where: { auth_sessions: { user_id: id }, revoked_at: null },
          data: { revoked_at: now, revocation_reason: action },
        });
        await transaction.authSession.updateMany({
          where: { user_id: id, status: 'ACTIVE' },
          data: { status: 'REVOKED', revoked_at: now, revocation_reason: action },
        });
        await transaction.accessSession.updateMany({
          where: { user_id: id, status: 'ACTIVE' },
          data: {
            status: 'TERMINATED',
            ended_at: now,
            terminated_reason: `User ${status.toLowerCase()}: ${action}`,
          },
        });
      }
      const after = await transaction.user.findUniqueOrThrow({ where: { id } });
      await this.audit.record(
        transaction,
        {
          action,
          objectType: 'USER',
          objectId: id.toString(),
          before: this.auditUser(before),
          after: this.auditUser(after),
        },
        principal,
        context,
      );
      return after;
    });
    this.authorization.invalidateUser(id);
    return this.present(result);
  }

  private async assertTargetVisible(
    principal: AuthPrincipal,
    departmentId: bigint | null,
  ): Promise<void> {
    if (
      !(await this.authorization.hasPermission(principal, 'USER', 'MANAGE', {
        targetDepartmentId: departmentId,
      }))
    ) {
      throw new NotFoundException('User not found.');
    }
  }

  private present(user: Record<string, unknown> & { id: bigint }) {
    return Object.fromEntries(
      Object.entries(user)
        .filter(([key]) => !['password_hash', 'created_by'].includes(key))
        .map(([key, value]) => [
          key.replace(/_([a-z])/gu, (_, letter: string) => letter.toUpperCase()),
          typeof value === 'bigint'
            ? value.toString()
            : value instanceof Date
              ? value.toISOString()
              : value,
        ]),
    );
  }

  private auditUser(user: {
    id: bigint;
    username: string;
    full_name: string;
    department_id: bigint | null;
    status: string;
    version: number;
  }): Record<string, string | number | null> {
    return {
      id: user.id.toString(),
      username: user.username,
      fullName: user.full_name,
      departmentId: user.department_id?.toString() ?? null,
      status: user.status,
      version: user.version,
    };
  }
}

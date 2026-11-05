/**
 * Module: Users Lifecycle & Scoped Identity Service
 * Algorithm: Enforces department-subtree RBAC visibility, anti-enumeration 404 masking, `SERIALIZABLE`
 *   optimistic CAS mutations, and cascading session revocation on account lock/disable.
 */
import { ForbiddenException, Injectable, NotFoundException, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { PasswordService } from '../auth/password.service.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { RbacAuditService } from '../rbac/rbac-audit.service.js';
import {
  lookupUsersWithClearance,
  presentUserRecord,
  type CreateUserInput,
  type UpdateUserInput,
} from './users-clearance.helper.js';
import {
  assertUserDepartmentVisible,
  executeChangeUserStatus,
  executeCreateUser,
  executeUpdateUser,
} from './users-mutations.helper.js';

export type { CreateUserInput, UpdateUserInput };

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class UsersService {
  private readonly database: PrismaClient;

  constructor(
    private readonly authorization: AuthorizationService,
    private readonly passwords: PasswordService,
    private readonly audit: RbacAuditService,
    @Optional() databaseClient?: PrismaClient,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Algorithm: Effective Principal Profile & Deduplicated Grant Projection
   */
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
        departments: { select: { id: true, name: true } },
      },
    });
    if (!user) throw new NotFoundException('User not found.');
    const grants = await this.authorization.effectiveGrants(principal.userId);
    const { departments, ...userFields } = user;
    return {
      ...presentUserRecord(userFields),
      departmentName: departments?.name ?? null,
      roles: [...new Set(grants.map((grant) => grant.roleCode))].sort(),
      permissions: [...new Set(grants.map((grant) => `${grant.resource}:${grant.action}`))].sort(),
    };
  }

  async lookup(principal?: AuthPrincipal) {
    return lookupUsersWithClearance(this.database, this.authorization, principal);
  }

  /**
   * Algorithm: Department-Subtree Scoped User Listing
   */
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
    return { data: users.map((user) => presentUserRecord(user)) };
  }

  /**
   * Algorithm: Anti-Enumeration Scoped User Detail Projection
   */
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
    await assertUserDepartmentVisible(this.authorization, principal, user.department_id);
    return {
      ...presentUserRecord(user),
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

  create(principal: AuthPrincipal, input: CreateUserInput, context: RequestContext) {
    return executeCreateUser({
      database: this.database,
      authorization: this.authorization,
      passwords: this.passwords,
      audit: this.audit,
      principal,
      input,
      context,
    });
  }

  update(principal: AuthPrincipal, id: bigint, input: UpdateUserInput, context: RequestContext) {
    return executeUpdateUser({
      database: this.database,
      authorization: this.authorization,
      audit: this.audit,
      principal,
      id,
      input,
      context,
    });
  }

  lock(principal: AuthPrincipal, id: bigint, expectedVersion: number, context: RequestContext) {
    return executeChangeUserStatus({
      database: this.database,
      authorization: this.authorization,
      audit: this.audit,
      principal,
      id,
      expectedVersion,
      status: 'LOCKED',
      action: 'USER_LOCKED',
      context,
    });
  }

  unlock(principal: AuthPrincipal, id: bigint, expectedVersion: number, context: RequestContext) {
    return executeChangeUserStatus({
      database: this.database,
      authorization: this.authorization,
      audit: this.audit,
      principal,
      id,
      expectedVersion,
      status: 'ACTIVE',
      action: 'USER_UNLOCKED',
      context,
    });
  }

  disable(principal: AuthPrincipal, id: bigint, expectedVersion: number, context: RequestContext) {
    if (principal.userId === id) {
      throw new ForbiddenException('Administrators cannot disable themselves.');
    }
    return executeChangeUserStatus({
      database: this.database,
      authorization: this.authorization,
      audit: this.audit,
      principal,
      id,
      expectedVersion,
      status: 'DISABLED',
      action: 'USER_DISABLED',
      context,
    });
  }
}

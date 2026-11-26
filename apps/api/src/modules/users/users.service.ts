/**
 * Module: Users Lifecycle & Scoped Identity Service
 * Algorithm: Enforces department-subtree RBAC visibility, anti-enumeration 404 masking, `SERIALIZABLE`
 *   optimistic CAS mutations, and cascading session revocation on account lock/disable.
 */
import { ForbiddenException, Injectable, NotFoundException, Optional } from '@nestjs/common';
import { getDatabaseClient, type Prisma } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { PasswordService } from '../auth/password.service.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { RbacAuditService } from '../rbac/rbac-audit.service.js';
import { RealtimeEventsService } from '../realtime/realtime-events.service.js';
import {
  EMPTY_CLEARANCE_SUMMARY,
  lookupUsersWithClearance,
  presentUserRecord,
  type CreateUserInput,
  type UpdateUserClearanceInput,
  type UpdateUserInput,
} from './users-clearance.helper.js';
import {
  fetchActiveClearancesByUserIds,
  fetchActiveUserClearance,
  listClearanceOptions,
} from './users-clearance-assignment.helper.js';
import {
  assertUserDepartmentVisible,
  executeChangeUserStatus,
  executeCreateUser,
  executeUpdateUser,
  executeUpdateUserClearance,
} from './users-mutations.helper.js';

export type { CreateUserInput, UpdateUserClearanceInput, UpdateUserInput };

export interface ListUsersQueryInput {
  page?: number | undefined;
  pageSize?: number | undefined;
  search?: string | undefined;
  status?: 'ACTIVE' | 'LOCKED' | 'DISABLED' | 'PENDING' | undefined;
  departmentId?: bigint | 'UNASSIGNED' | undefined;
}

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class UsersService {
  private readonly database: PrismaClient;

  constructor(
    private readonly authorization: AuthorizationService,
    private readonly passwords: PasswordService,
    private readonly audit: RbacAuditService,
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly realtime?: RealtimeEventsService,
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
    const [grants, clearance, activeMfaCount] = await Promise.all([
      this.authorization.effectiveGrants(principal.userId),
      fetchActiveUserClearance(this.database, principal.userId),
      typeof this.database.mfaMethod?.count === 'function'
        ? this.database.mfaMethod
            .count({
              where: {
                user_id: principal.userId,
                enabled_at: { not: null },
                disabled_at: null,
              },
            })
            .catch(() => 0)
        : Promise.resolve(0),
    ]);
    const { departments, ...userFields } = user;
    const userManageGrants = grants.filter(
      (grant) => grant.resource === 'USER' && grant.action === 'MANAGE',
    );
    const hasGlobalUserManage = userManageGrants.some(
      (grant) => (grant.scopeDepartmentId ?? null) === null,
    );
    const userManageDepartmentIds = [
      ...new Set(
        userManageGrants
          .map((grant) => grant.scopeDepartmentId)
          .filter((id): id is bigint => id !== null && id !== undefined)
          .map((id) => id.toString()),
      ),
    ].sort();
    const docUploadGrants = grants.filter(
      (grant) =>
        grant.resource === 'DOCUMENT' &&
        (grant.action === 'UPLOAD' || grant.action === 'CLASSIFY' || grant.action === 'MANAGE'),
    );
    const hasGlobalDocumentUpload = docUploadGrants.some(
      (grant) => (grant.scopeDepartmentId ?? null) === null,
    );
    const documentUploadDepartmentIds = [
      ...new Set(
        docUploadGrants
          .map((grant) => grant.scopeDepartmentId)
          .filter((id): id is bigint => id !== null && id !== undefined)
          .map((id) => id.toString()),
      ),
    ].sort();
    const globalPermissions = [
      ...new Set(
        grants
          .filter((grant) => (grant.scopeDepartmentId ?? null) === null)
          .map((grant) => `${grant.resource}:${grant.action}`),
      ),
    ].sort();
    return {
      ...presentUserRecord(userFields),
      departmentName: departments?.name ?? null,
      mfaEnabled: activeMfaCount > 0,
      mfaVerified: Boolean(principal.mfa),
      ...clearance,
      roles: [...new Set(grants.map((grant) => grant.roleCode))].sort(),
      permissions: [...new Set(grants.map((grant) => `${grant.resource}:${grant.action}`))].sort(),
      globalPermissions,
      hasGlobalUserManage,
      userManageDepartmentIds,
      hasGlobalDocumentUpload,
      documentUploadDepartmentIds,
    };
  }

  async lookup(principal?: AuthPrincipal) {
    return lookupUsersWithClearance(this.database, this.authorization, principal);
  }

  async clearanceOptions() {
    return listClearanceOptions(this.database);
  }

  /**
   * Thuật toán: Liệt kê người dùng phân trang & lọc máy chủ theo bao đóng cây con phòng ban (`take: pageSize`, mặc định `200`),
   * giữ nguyên mảng `data` cấp 1 kèm siêu dữ liệu `{ total, page, pageSize, totalPages, truncated }` tương thích ngược 100%.
   */
  async list(principal: AuthPrincipal, query?: ListUsersQueryInput) {
    const page = query?.page ?? 1;
    const pageSize = query?.pageSize ?? 200;
    const skip = (page - 1) * pageSize;
    const visible = await this.authorization.visibleDepartmentIds(principal, 'USER', 'MANAGE');

    if (query?.departmentId === 'UNASSIGNED' && visible !== null) {
      return { data: [], total: 0, page, pageSize, totalPages: 1, truncated: false };
    }
    if (
      typeof query?.departmentId === 'bigint' &&
      visible !== null &&
      !visible.includes(query.departmentId)
    ) {
      return { data: [], total: 0, page, pageSize, totalPages: 1, truncated: false };
    }

    const where: Prisma.UserWhereInput = {};
    if (query?.departmentId === 'UNASSIGNED') {
      where.department_id = null;
    } else if (typeof query?.departmentId === 'bigint') {
      where.department_id = query.departmentId;
    } else if (visible !== null) {
      where.department_id = { in: visible };
    }

    if (query?.status) {
      where.status = query.status;
    }

    const trimmedSearch = query?.search?.trim();
    if (trimmedSearch && trimmedSearch.length > 0) {
      where.OR = [
        { full_name: { contains: trimmedSearch, mode: 'insensitive' } },
        { username: { contains: trimmedSearch, mode: 'insensitive' } },
        { email: { contains: trimmedSearch, mode: 'insensitive' } },
        { employee_code: { contains: trimmedSearch, mode: 'insensitive' } },
      ];
    }

    const hasCount = typeof this.database.user.count === 'function';
    const [users, countedTotal] = await Promise.all([
      this.database.user.findMany({
        where,
        orderBy: [{ full_name: 'asc' }, { id: 'asc' }],
        ...(skip > 0 ? { skip } : {}),
        take: pageSize,
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
      }),
      hasCount ? this.database.user.count({ where }) : Promise.resolve<number | null>(null),
    ]);

    const clearancesByUser = await fetchActiveClearancesByUserIds(
      this.database,
      users.map((user) => user.id),
    );
    const data = users.map((user) => ({
      ...presentUserRecord(user),
      ...(clearancesByUser.get(user.id.toString()) ?? EMPTY_CLEARANCE_SUMMARY),
    }));
    const total = countedTotal ?? skip + data.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const truncated = total > data.length;

    return {
      data,
      total,
      page,
      pageSize,
      totalPages,
      truncated,
    };
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
    const clearance = await fetchActiveUserClearance(this.database, id);
    return {
      ...presentUserRecord(user),
      ...clearance,
      roleAssignments: user.user_roles_user_roles_user_idTousers.map((assignment) => ({
        id: assignment.id.toString(),
        roleId: assignment.role_id.toString(),
        roleCode: assignment.roles.code,
        roleName: assignment.roles.name,
        roleIsActive: assignment.roles.is_active,
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

  updateClearance(
    principal: AuthPrincipal,
    id: bigint,
    input: UpdateUserClearanceInput,
    context: RequestContext,
  ) {
    return executeUpdateUserClearance({
      database: this.database,
      authorization: this.authorization,
      audit: this.audit,
      principal,
      id,
      input,
      context,
    });
  }

  /**
   * Thuật toán: Khóa tài khoản, thu hồi toàn bộ phiên DB và đẩy sự kiện SSE `USER_SESSION_REVOKED` để đăng xuất trình duyệt tức thì.
   */
  async lock(
    principal: AuthPrincipal,
    id: bigint,
    expectedVersion: number,
    context: RequestContext,
  ) {
    // CONFLICT-RESOLVED: Ngăn quản trị viên tự khóa tài khoản của chính mình gây mất quyền điều hành (MED-07)
    if (principal.userId === id) {
      throw new ForbiddenException('Administrators cannot lock themselves.');
    }
    const updated = await executeChangeUserStatus({
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
    this.realtime?.publish({
      type: 'USER_SESSION_REVOKED',
      targetUserIds: [id.toString()],
      payload: { userId: id.toString(), status: 'LOCKED', reason: 'USER_LOCKED' },
    });
    return updated;
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

  /**
   * Thuật toán: Kích hoạt lại tài khoản đang ở trạng thái `DISABLED` qua luồng riêng biệt có kiểm toán `USER_REACTIVATED`.
   */
  reactivate(
    principal: AuthPrincipal,
    id: bigint,
    expectedVersion: number,
    context: RequestContext,
  ) {
    return executeChangeUserStatus({
      database: this.database,
      authorization: this.authorization,
      audit: this.audit,
      principal,
      id,
      expectedVersion,
      status: 'ACTIVE',
      action: 'USER_REACTIVATED',
      context,
      allowDisabledReactivation: true,
    });
  }

  /**
   * Thuật toán: Vô hiệu hóa tài khoản, thu hồi toàn bộ phiên DB và phát sự kiện SSE `USER_SESSION_REVOKED` để cưỡng chế đăng xuất tức thì.
   */
  async disable(
    principal: AuthPrincipal,
    id: bigint,
    expectedVersion: number,
    context: RequestContext,
  ) {
    if (principal.userId === id) {
      throw new ForbiddenException('Administrators cannot disable themselves.');
    }
    const updated = await executeChangeUserStatus({
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
    this.realtime?.publish({
      type: 'USER_SESSION_REVOKED',
      targetUserIds: [id.toString()],
      payload: { userId: id.toString(), status: 'DISABLED', reason: 'USER_DISABLED' },
    });
    return updated;
  }
}

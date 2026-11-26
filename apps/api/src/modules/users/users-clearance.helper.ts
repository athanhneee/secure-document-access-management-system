/**
 * Module: UsersClearanceHelper — Tra cứu danh bạ nhân sự có che dấu độ mật theo thẩm quyền, thu hồi dây chuyền phiên hoạt động khi khóa tài khoản và cắt hiệu lực vai trò phòng ban cũ.
 */
import type { getDatabaseClient, withSerializableTransaction } from '@sda/database';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import { isPrivilegedSeparationRoleOrCapability } from '../rbac/permission-matrix.js';
import { terminateUserSessionsOpenedViaRevokedRole } from '../rbac/rbac-grant-cascade.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;
type SerializableTransaction = Parameters<Parameters<typeof withSerializableTransaction>[0]>[0];

export interface ClearanceSummary {
  clearanceOptionId: string | null;
  clearanceCode: string | null;
  clearanceName: string | null;
  clearanceRank: number;
}

export interface ClearanceOptionItem {
  id: string;
  code: string;
  name: string;
  rank: number;
}

export interface CreateUserInput {
  username: string;
  email: string;
  fullName: string;
  employeeCode?: string | null | undefined;
  departmentId?: bigint | null | undefined;
  clearanceOptionId?: bigint | null | undefined;
  password: string;
}

export interface UpdateUserInput {
  expectedVersion: number;
  email?: string | undefined;
  fullName?: string | undefined;
  employeeCode?: string | null | undefined;
  departmentId?: bigint | null | undefined;
  clearanceOptionId?: bigint | null | undefined;
}

export interface UpdateUserClearanceInput {
  expectedVersion: number;
  clearanceOptionId: bigint | null;
}

export const EMPTY_CLEARANCE_SUMMARY: ClearanceSummary = {
  clearanceOptionId: null,
  clearanceCode: null,
  clearanceName: null,
  clearanceRank: 0,
};

/**
 * Thuật toán: Phân giải tập phòng ban được phép nhìn thấy cấp độ thẩm tra an ninh (`CLEARANCE_LEVEL`) theo hợp bao đóng `ACCESS_GRANT:CREATE` và `USER:MANAGE` (HIGH-13).
 */
async function resolveClearanceVisibilityScope(
  authorization: AuthorizationService | undefined,
  principal: AuthPrincipal | undefined,
): Promise<{ global: boolean; departmentIds: Set<string> }> {
  // CONFLICT-RESOLVED: Đóng an toàn (fail-closed) khi thiếu `principal` và giới hạn hiển thị `CLEARANCE_LEVEL` theo bao đóng phòng ban được cấp quyền (HIGH-13)
  if (!authorization || !principal) {
    return { global: false, departmentIds: new Set<string>() };
  }
  if (typeof authorization.visibleDepartmentIds === 'function') {
    const [grantScope, userManageScope] = await Promise.all([
      authorization.visibleDepartmentIds(principal, 'ACCESS_GRANT', 'CREATE'),
      authorization.visibleDepartmentIds(principal, 'USER', 'MANAGE'),
    ]);
    if (grantScope === null || userManageScope === null) {
      return { global: true, departmentIds: new Set<string>() };
    }
    return {
      global: false,
      departmentIds: new Set([...grantScope, ...userManageScope].map((id) => id.toString())),
    };
  }
  const hasGlobal =
    (await authorization.hasPermission(principal, 'ACCESS_GRANT', 'CREATE', {
      requireGlobal: true,
    })) ||
    (await authorization.hasPermission(principal, 'USER', 'MANAGE', {
      requireGlobal: true,
    }));
  return { global: hasGlobal, departmentIds: new Set<string>() };
}

/**
 * Thuật toán: Tra cứu danh bạ người dùng hoạt động có lọc Phân tách Nhiệm vụ (SoD), loại trừ tự cấp quyền
 * và che dấu độ mật theo phạm vi phòng ban (Department-Scoped SoD-Filtered Clearance-Redacted Lookup).
 * Mục đích:
 *   - Cho phép chủ sở hữu tìm người nhận quyền hợp lệ (`ACCESS_GRANT:CREATE`) mà không hiển thị chính bản thân mình
 *     hay các tài khoản đặc quyền (`SYSTEM_ADMIN`, `SECURITY_OFFICER`, `AUDITOR`, Custom Role đặc quyền).
 *   - Chỉ hiển thị `CLEARANCE_LEVEL` cho nhân sự thuộc phòng ban mà người gọi nắm quyền `ACCESS_GRANT:CREATE` hoặc `USER:MANAGE`.
 */
export async function lookupUsersWithClearance(
  database: PrismaClient,
  authorization: AuthorizationService,
  principal?: AuthPrincipal,
) {
  const now = new Date();
  const visibility = await resolveClearanceVisibilityScope(authorization, principal);
  const canManageUsers = principal
    ? await authorization.hasPermission(principal, 'USER', 'MANAGE', { anyScope: true })
    : false;

  const users = await database.user.findMany({
    where: { status: 'ACTIVE' },
    orderBy: { username: 'asc' },
    take: 500,
    select: {
      id: true,
      username: true,
      full_name: true,
      department_id: true,
      departments: { select: { id: true, name: true } },
      user_roles_user_roles_user_idTousers: {
        where: {
          OR: [{ valid_to: null }, { valid_to: { gt: now } }],
          roles: { is_active: true },
        },
        select: {
          roles: {
            select: {
              code: true,
              role_permissions: {
                select: {
                  permissions: { select: { code: true, resource_type: true, action: true } },
                },
              },
            },
          },
        },
      },
      user_attribute_assignments_user_attribute_assignments_user_idTousers: {
        where: {
          attribute_definitions: { code: 'CLEARANCE_LEVEL', is_active: true },
          attribute_options: { is_active: true },
          valid_from: { lte: now },
          OR: [{ valid_to: null }, { valid_to: { gt: now } }],
        },
        include: { attribute_options: true },
        orderBy: { attribute_options: { numeric_rank: 'desc' } },
        take: 1,
      },
    },
  });

  const eligibleUsers =
    !canManageUsers && principal
      ? users.filter((u) => {
          if (u.id === principal.userId) return false;
          const activeRoleLinks =
            (
              u as {
                user_roles_user_roles_user_idTousers?: Array<{
                  roles?: {
                    code?: string;
                    role_permissions?: Array<{
                      permissions?: { code: string; resource_type?: string; action?: string };
                    }>;
                  };
                }>;
              }
            ).user_roles_user_roles_user_idTousers ?? [];
          const holdsPrivilegedCapability = activeRoleLinks.some((link) => {
            const roleObj = link.roles;
            if (!roleObj) return false;
            const perms = (roleObj.role_permissions ?? [])
              .map((rp) => rp.permissions)
              .filter((p): p is NonNullable<typeof p> => Boolean(p));
            return isPrivilegedSeparationRoleOrCapability(roleObj.code, perms);
          });
          return !holdsPrivilegedCapability;
        })
      : users;

  return {
    data: eligibleUsers.map((u) => {
      const canViewClearance =
        visibility.global ||
        (u.department_id !== null && visibility.departmentIds.has(u.department_id.toString()));
      const rawClearanceAttr =
        u.user_attribute_assignments_user_attribute_assignments_user_idTousers[0];
      const clearanceAttr =
        rawClearanceAttr?.attribute_options?.is_active === false ? undefined : rawClearanceAttr;
      return {
        id: u.id.toString(),
        username: u.username,
        fullName: u.full_name,
        departmentId: u.department_id?.toString() ?? null,
        departmentName: u.departments?.name ?? null,
        clearanceRank: canViewClearance ? (clearanceAttr?.attribute_options?.numeric_rank ?? 0) : 0,
        clearanceCode: canViewClearance
          ? (clearanceAttr?.attribute_options?.value_code ?? 'UNCLASSIFIED')
          : 'REDACTED',
        clearanceName: canViewClearance
          ? (clearanceAttr?.attribute_options?.display_name ?? 'Chưa phân loại')
          : 'Ẩn',
      };
    }),
  };
}

/**
 * Thuật toán: Thu hồi dây chuyền đa tầng phiên xác thực & phiên tài liệu (Cascading Multi-Layer Session Revocation)
 * Mục đích: Chấm dứt tức thời mọi kênh truy cập của tài khoản ngay trong cùng giao dịch `SERIALIZABLE` khi bị khóa hoặc vô hiệu hóa.
 * Cơ chế hoạt động:
 *   - Hủy đồng bộ 3 lớp trạng thái: (1) thu hồi toàn bộ thẻ làm mới chưa hủy (`refreshToken`), (2) chuyển các phiên đăng nhập `authSession` sang `REVOKED`, và (3) đóng mọi phiên xem tài liệu `accessSession` sang `TERMINATED`.
 *
 * Algorithm: Cascading Session & Token Revocation on Account Lock/Disable.
 * Atomically revokes refresh tokens, auth sessions, and active document access sessions inside
 * the caller's `SERIALIZABLE` transaction when a user transitions away from `ACTIVE`.
 */
export async function revokeUserActiveSessions(
  transaction: SerializableTransaction,
  userId: bigint,
  status: 'LOCKED' | 'DISABLED',
  action: string,
  now: Date,
): Promise<void> {
  if (typeof transaction.passwordResetToken?.updateMany === 'function') {
    await transaction.passwordResetToken.updateMany({
      where: { user_id: userId, used_at: null },
      data: { used_at: now },
    });
  }
  await transaction.refreshToken.updateMany({
    where: { auth_sessions: { user_id: userId }, revoked_at: null },
    data: { revoked_at: now, revocation_reason: action },
  });
  await transaction.authSession.updateMany({
    where: { user_id: userId, status: 'ACTIVE' },
    data: { status: 'REVOKED', revoked_at: now, revocation_reason: action },
  });
  await transaction.accessSession.updateMany({
    where: { user_id: userId, status: 'ACTIVE' },
    data: {
      status: 'TERMINATED',
      ended_at: now,
      terminated_reason: `User ${status.toLowerCase()}: ${action}`,
    },
  });
}

/**
 * Thuật toán: Cắt hiệu lực mọi vai trò gắn phạm vi phòng ban không khớp `newDepartmentId` khi điều chuyển công tác (`HIGH-04` + `BUG-106`)
 * và đóng tức thì các `AccessSession` đang `ACTIVE` mở qua `ROLE` grant của các vai trò vừa hết hạn.
 * Mục đích: Ngăn chặn tuyệt đối tích lũy đặc quyền xuyên phòng ban (bao gồm cả khi điều chuyển từ phòng ban cha xuống phòng ban con hoặc sang phòng ban ngang cấp)
 * mà không vi phạm ràng buộc `CHECK (valid_to IS NULL OR valid_to > valid_from)`.
 * Cơ chế hoạt động:
 *   1. Thu thập toàn bộ `user_roles` có `scope_department_id IS NOT NULL` và `scope_department_id !== newDepartmentId` (luôn bao gồm `previousDepartmentId` nếu khác `newDepartmentId`).
 *   2. Với bản ghi đặt lịch tương lai (`valid_from >= changedAt`): xóa hẳn bằng `deleteMany` để tránh lỗi PostgreSQL `23514`.
 *   3. Với bản ghi đã có hiệu lực (`valid_from < changedAt`): đặt `valid_to = changedAt` bằng `updateMany`.
 *   4. Đóng mọi `AccessSession` đang `ACTIVE` mở thông qua `ROLE` grant của các vai trò vừa bị cắt hiệu lực.
 */
export async function expirePreviousDepartmentRoles(
  transaction: SerializableTransaction,
  userId: bigint,
  previousDepartmentId: bigint,
  changedAt: Date = new Date(),
  newDepartmentId: bigint | null = null,
): Promise<void> {
  let targetScopeIds: bigint[] =
    newDepartmentId !== previousDepartmentId ? [previousDepartmentId] : [];
  const expiredRoleIds = new Set<bigint>();

  if (typeof transaction.userRole?.findMany === 'function') {
    const scopedAssignments = await transaction.userRole.findMany({
      where: {
        user_id: userId,
        scope_department_id: { not: null },
        OR: [{ valid_to: null }, { valid_to: { gt: changedAt } }],
      },
      select: { role_id: true, scope_department_id: true },
    });
    const outOfScopeIds = new Set<bigint>();
    for (const row of scopedAssignments) {
      if (row.scope_department_id !== null && row.scope_department_id !== newDepartmentId) {
        outOfScopeIds.add(row.scope_department_id);
        expiredRoleIds.add(row.role_id);
      }
    }
    if (previousDepartmentId !== newDepartmentId) {
      outOfScopeIds.add(previousDepartmentId);
    }
    targetScopeIds = [...outOfScopeIds];
  }

  if (targetScopeIds.length === 0) {
    return;
  }

  const scopeFilter = targetScopeIds.length === 1 ? targetScopeIds[0]! : { in: targetScopeIds };

  if (typeof transaction.userRole.deleteMany === 'function') {
    await transaction.userRole.deleteMany({
      where: {
        user_id: userId,
        scope_department_id: scopeFilter,
        valid_from: { gte: changedAt },
        OR: [{ valid_to: null }, { valid_to: { gt: changedAt } }],
      },
    });
  }
  await transaction.userRole.updateMany({
    where: {
      user_id: userId,
      scope_department_id: scopeFilter,
      valid_from: { lt: changedAt },
      OR: [{ valid_to: null }, { valid_to: { gt: changedAt } }],
    },
    data: { valid_to: changedAt },
  });

  for (const roleId of expiredRoleIds) {
    await terminateUserSessionsOpenedViaRevokedRole({
      transaction,
      userId,
      roleId,
      now: changedAt,
    });
  }
}

const SAFE_USER_RECORD_KEYS = new Set([
  'id',
  'username',
  'email',
  'full_name',
  'employee_code',
  'department_id',
  'status',
  'locked_until',
  'last_login_at',
  'failed_login_count',
  'version',
  'created_at',
  'updated_at',
]);

/**
 * Algorithm / Thuật toán: Chiếu danh sách trắng DTO người dùng an toàn (`SAFE_USER_RECORD_KEYS`) và chuẩn hóa `BigInt`/`Date`.
 * Loại bỏ tuyệt đối mọi trường bí mật (`password_hash`, `mfa_methods`, `refresh_tokens`, `password_reset_tokens`, `created_by`).
 */
export function presentUserRecord(user: Record<string, unknown> & { id: bigint }) {
  return Object.fromEntries(
    Object.entries(user)
      .filter(([key]) => SAFE_USER_RECORD_KEYS.has(key))
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

export function auditUserSnapshot(user: {
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

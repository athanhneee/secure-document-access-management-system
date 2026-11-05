/**
 * Module: UsersClearanceHelper — Tra cứu danh bạ nhân sự có che dấu độ mật theo thẩm quyền, thu hồi dây chuyền phiên hoạt động khi khóa tài khoản và cắt hiệu lực vai trò phòng ban cũ.
 */
import type { getDatabaseClient, withSerializableTransaction } from '@sda/database';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;
type SerializableTransaction = Parameters<Parameters<typeof withSerializableTransaction>[0]>[0];

export interface CreateUserInput {
  username: string;
  email: string;
  fullName: string;
  employeeCode?: string | null | undefined;
  departmentId?: bigint | null | undefined;
  password: string;
}

export interface UpdateUserInput {
  expectedVersion: number;
  email?: string | undefined;
  fullName?: string | undefined;
  employeeCode?: string | null | undefined;
  departmentId?: bigint | null | undefined;
}

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
 * Thuật toán: Tra cứu danh bạ người dùng hoạt động kèm che dấu độ mật theo phạm vi phòng ban (Department-Scoped Clearance-Redacted Lookup)
 * Mục đích: Cho phép tìm kiếm người dùng để cấp quyền, nhưng chỉ hiển thị `CLEARANCE_LEVEL` cho các nhân sự thuộc phòng ban mà người gọi nắm quyền `ACCESS_GRANT:CREATE` hoặc `USER:MANAGE`.
 *
 * Algorithm: Department-Scoped Clearance-Redacted Active User Directory Lookup.
 */
export async function lookupUsersWithClearance(
  database: PrismaClient,
  authorization: AuthorizationService,
  principal?: AuthPrincipal,
) {
  const now = new Date();
  const visibility = await resolveClearanceVisibilityScope(authorization, principal);

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

  return {
    data: users.map((u) => {
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
 * Thuật toán: Cắt hiệu lực vai trò gắn phạm vi phòng ban cũ khi điều chuyển công tác (Department-Scoped Role Expiration)
 * Mục đích: Ngăn chặn tích lũy đặc quyền xuyên phòng ban sau khi nhân sự chuyển sang đơn vị mới.
 * Cơ chế hoạt động:
 *   - Cập nhật `valid_to = changedAt` cho mọi bản ghi `user_roles` đang hiệu lực (`valid_from < changedAt` và `valid_to IS NULL OR valid_to > changedAt`) có `scope_department_id === previousDepartmentId`.
 *
 * Algorithm: Department-Transfer Scoped Role Expiration.
 * Terminates active role assignments bound to the user's previous department upon department transfer.
 */
export async function expirePreviousDepartmentRoles(
  transaction: SerializableTransaction,
  userId: bigint,
  previousDepartmentId: bigint,
  changedAt: Date = new Date(),
): Promise<void> {
  await transaction.userRole.updateMany({
    where: {
      user_id: userId,
      scope_department_id: previousDepartmentId,
      valid_from: { lt: changedAt },
      OR: [{ valid_to: null }, { valid_to: { gt: changedAt } }],
    },
    data: { valid_to: changedAt },
  });
}

/**
 * Algorithm: Snake-to-Camel Safe User DTO Projection.
 * Strips sensitive fields (`password_hash`, `created_by`) and normalizes BigInt/Date values.
 */
export function presentUserRecord(user: Record<string, unknown> & { id: bigint }) {
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

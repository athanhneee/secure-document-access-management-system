/**
 * @module AuthUserRepository
 * Algorithm: Active User Role/MFA Projection & Single-Use Atomic CAS Password Reset Persistence.
 */
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient, Prisma } from '@sda/database';
import { isPrivilegedSeparationRoleOrCapability } from '../rbac/permission-matrix.js';
import { revokeTokenFamily } from './auth-session.repository.js';
import type { AuthUser } from './auth.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm / Thuật toán: Xây dựng điều kiện `include` chuẩn hóa cho vai trò còn hiệu lực, quyền SoD,
 * phòng ban, cấp độ thẩm tra `CLEARANCE_LEVEL` và nhân tố MFA đang bật trong 1 lần truy vấn duy nhất
 * để phản hồi `POST /auth/login` và `POST /auth/mfa/verify` trả luôn hồ sơ người dùng không cần gọi lại `/users/me`.
 */
export function buildActiveUserInclude(now: Date) {
  // CONFLICT-RESOLVED: Unified duplicate active user role + MFA Prisma include block across findUserByIdentifier and findUserById
  return {
    departments: { select: { id: true, name: true } },
    user_attribute_assignments_user_attribute_assignments_user_idTousers: {
      where: {
        attribute_definitions: { code: 'CLEARANCE_LEVEL', is_active: true },
        attribute_options: { is_active: true },
        valid_from: { lte: now },
        OR: [{ valid_to: null }, { valid_to: { gt: now } }],
      },
      include: {
        attribute_options: {
          select: {
            id: true,
            value_code: true,
            display_name: true,
            numeric_rank: true,
            is_active: true,
          },
        },
      },
      orderBy: [{ attribute_options: { numeric_rank: 'desc' } }, { id: 'desc' }],
      take: 1,
    },
    user_roles_user_roles_user_idTousers: {
      where: {
        valid_from: { lte: now },
        AND: [
          { OR: [{ valid_to: null }, { valid_to: { gt: now } }] },
          { OR: [{ scope_department_id: null }, { departments: { is: { is_active: true } } }] },
        ],
        roles: { is_active: true },
      },
      include: {
        roles: {
          include: {
            role_permissions: {
              include: {
                permissions: { select: { code: true, resource_type: true, action: true } },
              },
            },
          },
        },
      },
    },
    mfa_methods: {
      where: { enabled_at: { not: null }, disabled_at: null },
      take: 1,
    },
  } satisfies Prisma.UserInclude;
}

/**
 * Algorithm / Thuật toán: Ánh xạ bản ghi ORM người dùng kèm quan hệ vai trò, quyền hiệu lực, phòng ban, cấp thẩm tra và MFA sang thực thể miền `AuthUser`.
 */
export function mapRecordToAuthUser(user: {
  id: bigint;
  username: string;
  email: string;
  password_hash: string;
  full_name: string;
  department_id?: bigint | null;
  version?: number;
  status: 'PENDING' | 'ACTIVE' | 'LOCKED' | 'DISABLED';
  locked_until: Date | null;
  failed_login_count: number;
  departments?: { id?: bigint; name: string } | null;
  user_attribute_assignments_user_attribute_assignments_user_idTousers?: Array<{
    attribute_options?: {
      id: bigint;
      value_code: string;
      display_name: string;
      numeric_rank: number | null;
      is_active?: boolean;
    } | null;
  }>;
  user_roles_user_roles_user_idTousers: Array<{
    roles: {
      code: string;
      role_permissions?: Array<{
        permissions?: { code: string; resource_type?: string; action?: string } | null;
      }>;
    };
  }>;
  mfa_methods: Array<{ id: string; secret_encrypted: string; recovery_code_hashes: unknown }>;
}): AuthUser {
  const method = user.mfa_methods[0];
  const recoveryHashes = Array.isArray(method?.recovery_code_hashes)
    ? method.recovery_code_hashes.filter((value): value is string => typeof value === 'string')
    : [];
  const requiresMfa =
    Boolean(method) ||
    user.user_roles_user_roles_user_idTousers.some((assignment) =>
      isPrivilegedSeparationRoleOrCapability(
        assignment.roles.code,
        (assignment.roles.role_permissions ?? [])
          .map((rp) => rp.permissions ?? undefined)
          .filter((perm): perm is NonNullable<typeof perm> => perm !== undefined),
      ),
    );
  const roleCodes = [
    ...new Set(user.user_roles_user_roles_user_idTousers.map((a) => a.roles.code)),
  ];
  const permissionCodes = [
    ...new Set(
      user.user_roles_user_roles_user_idTousers.flatMap((assignment) =>
        (assignment.roles.role_permissions ?? [])
          .map((rp) => rp.permissions)
          .filter((p): p is { code: string; resource_type: string; action: string } =>
            Boolean(p?.resource_type && p?.action),
          )
          .map((p) => `${p.resource_type}:${p.action}`),
      ),
    ),
  ].sort();
  const clearanceOpt =
    user.user_attribute_assignments_user_attribute_assignments_user_idTousers?.[0]
      ?.attribute_options;
  const activeClearance = clearanceOpt && clearanceOpt.is_active !== false ? clearanceOpt : null;

  return {
    id: user.id,
    username: user.username,
    email: user.email,
    passwordHash: user.password_hash,
    fullName: user.full_name,
    status: user.status,
    lockedUntil: user.locked_until,
    failedLoginCount: user.failed_login_count,
    roles: user.user_roles_user_roles_user_idTousers.map((assignment) => assignment.roles.code),
    requiresMfa,
    profile: {
      id: user.id.toString(),
      username: user.username,
      email: user.email,
      fullName: user.full_name,
      departmentId: user.department_id?.toString() ?? null,
      departmentName: user.departments?.name ?? null,
      clearanceOptionId: activeClearance ? activeClearance.id.toString() : null,
      clearanceCode: activeClearance?.value_code ?? null,
      clearanceName: activeClearance?.display_name ?? null,
      clearanceRank: activeClearance?.numeric_rank ?? 0,
      status: user.status,
      version: user.version ?? 0,
      roles: [...roleCodes].sort(),
      permissions: permissionCodes,
    },
    mfaMethod: method
      ? {
          id: method.id,
          encryptedSecret: method.secret_encrypted,
          recoveryCodeHashes: recoveryHashes,
        }
      : null,
  };
}

/**
 * Algorithm / Thuật toán: Khóa tài khoản lũy thừa đơn điệu theo ngưỡng thất bại liên tiếp (`GREATEST(existingLockedUntil, candidateLockUntil)`).
 *   - Tính bước phạt tự động `min(900s, 30 * 2^min(failures - 5, 5))` khi `failures >= 5`.
 *   - Đối chiếu với `locked_until` hiện hữu của quản trị viên; chỉ nâng mốc khóa về tương lai xa hơn (MED-02).
 */
export async function recordUserLoginFailure(
  database: PrismaClient,
  user: AuthUser,
): Promise<void> {
  const failures = user.failedLoginCount + 1;
  const lockSeconds = failures < 5 ? 0 : Math.min(900, 30 * 2 ** Math.min(failures - 5, 5));
  const candidateLockUntil = lockSeconds > 0 ? new Date(Date.now() + lockSeconds * 1_000) : null;
  const latestRow =
    typeof database.user.findUnique === 'function'
      ? await database.user.findUnique({
          where: { id: user.id },
          select: { locked_until: true },
        })
      : null;
  const existingLock = [
    user.lockedUntil ?? null,
    latestRow?.locked_until ?? null,
  ].reduce<Date | null>((acc, cur) => {
    if (!cur) return acc;
    if (!acc) return cur;
    return cur.getTime() > acc.getTime() ? cur : acc;
  }, null);
  // CONFLICT-RESOLVED: Giữ nguyên mốc khóa quản trị viên dài hạn thay vì ghi đè bằng null hoặc thời hạn khóa tự động ngắn hơn (MED-02).
  const effectiveLockUntil =
    existingLock && (!candidateLockUntil || existingLock.getTime() > candidateLockUntil.getTime())
      ? existingLock
      : candidateLockUntil;

  await database.user.update({
    where: { id: user.id },
    data: {
      failed_login_count: { increment: 1 },
      ...(effectiveLockUntil !== null ? { locked_until: effectiveLockUntil } : {}),
    },
  });
}

/**
 * Algorithm / Thuật toán: Vô hiệu hóa nguyên tử toàn bộ mã đặt lại mật khẩu cũ chưa dùng của tài khoản trước khi phát hành mã mới.
 */
export async function createUserPasswordReset(
  database: PrismaClient,
  userId: bigint,
  tokenHash: string,
  expiresAt: Date,
  ip: string,
): Promise<void> {
  await database.$transaction(async (transaction) => {
    await transaction.passwordResetToken.updateMany({
      where: { user_id: userId, used_at: null },
      data: { used_at: new Date() },
    });
    await transaction.passwordResetToken.create({
      data: {
        id: randomUUID(),
        user_id: userId,
        token_hash: tokenHash,
        expires_at: expiresAt,
        requested_ip: ip,
      },
    });
  });
}

/**
 * Algorithm / Thuật toán: Tra cứu định danh chủ sở hữu của mã đặt lại mật khẩu còn hiệu lực trước khi tiêu thụ token.
 */
export async function findPasswordResetTokenOwner(
  database: PrismaClient,
  tokenHash: string,
): Promise<{ userId: bigint; username: string; email: string } | null> {
  const token = await database.passwordResetToken.findUnique({
    where: { token_hash: tokenHash },
    include: { users: { select: { id: true, username: true, email: true, status: true } } },
  });
  if (
    !token ||
    token.used_at ||
    token.expires_at <= new Date() ||
    token.users.status === 'DISABLED'
  ) {
    return null;
  }
  return {
    userId: token.users.id,
    username: token.users.username,
    email: token.users.email,
  };
}

/**
 * Algorithm / Thuật toán: Tiêu thụ nguyên tử một lần mã đặt lại mật khẩu bằng Compare-And-Swap (Single-Use Atomic CAS Consumption).
 */
export async function consumeUserPasswordReset(
  database: PrismaClient,
  tokenHash: string,
  passwordHash: string,
): Promise<bigint | null> {
  return database.$transaction(async (transaction) => {
    const token = await transaction.passwordResetToken.findUnique({
      where: { token_hash: tokenHash },
      include: { users: true },
    });
    if (
      !token ||
      token.used_at ||
      token.expires_at <= new Date() ||
      token.users.status === 'DISABLED'
    ) {
      return null;
    }
    const claimed = await transaction.passwordResetToken.updateMany({
      where: { id: token.id, used_at: null, expires_at: { gt: new Date() } },
      data: { used_at: new Date() },
    });
    if (claimed.count !== 1) return null;
    await transaction.user.update({
      where: { id: token.user_id },
      data: { password_hash: passwordHash, failed_login_count: 0, locked_until: null },
    });
    const sessions = await transaction.authSession.findMany({
      where: { user_id: token.user_id, status: 'ACTIVE' },
    });
    for (const session of sessions) {
      await revokeTokenFamily(transaction, session.token_family_id, session.id, 'PASSWORD_RESET');
    }
    return token.user_id;
  });
}

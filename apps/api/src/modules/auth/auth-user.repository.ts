/**
 * @module AuthUserRepository
 * Algorithm: Active User Role/MFA Projection & Single-Use Atomic CAS Password Reset Persistence.
 */
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient, Prisma } from '@sda/database';
import { revokeTokenFamily } from './auth-session.repository.js';
import type { AuthUser } from './auth.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm / Thuật toán: Xây dựng điều kiện `include` chuẩn hóa cho vai trò còn hiệu lực và nhân tố MFA đang bật.
 */
export function buildActiveUserInclude(now: Date) {
  // CONFLICT-RESOLVED: Unified duplicate active user role + MFA Prisma include block across findUserByIdentifier and findUserById
  return {
    user_roles_user_roles_user_idTousers: {
      where: {
        valid_from: { lte: now },
        AND: [
          { OR: [{ valid_to: null }, { valid_to: { gt: now } }] },
          { OR: [{ scope_department_id: null }, { departments: { is: { is_active: true } } }] },
        ],
        roles: { is_active: true },
      },
      include: { roles: true },
    },
    mfa_methods: {
      where: { enabled_at: { not: null }, disabled_at: null },
      take: 1,
    },
  } satisfies Prisma.UserInclude;
}

/**
 * Algorithm / Thuật toán: Ánh xạ bản ghi ORM người dùng kèm quan hệ vai trò và MFA sang thực thể miền `AuthUser`.
 */
export function mapRecordToAuthUser(user: {
  id: bigint;
  username: string;
  email: string;
  password_hash: string;
  full_name: string;
  status: 'PENDING' | 'ACTIVE' | 'LOCKED' | 'DISABLED';
  locked_until: Date | null;
  failed_login_count: number;
  user_roles_user_roles_user_idTousers: Array<{ roles: { code: string } }>;
  mfa_methods: Array<{ id: string; secret_encrypted: string; recovery_code_hashes: unknown }>;
}): AuthUser {
  const method = user.mfa_methods[0];
  const recoveryHashes = Array.isArray(method?.recovery_code_hashes)
    ? method.recovery_code_hashes.filter((value): value is string => typeof value === 'string')
    : [];
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

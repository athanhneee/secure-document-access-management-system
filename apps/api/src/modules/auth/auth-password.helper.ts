/**
 * @module AuthPasswordHelper
 * Algorithm: Constant-Floor Anti-Enumeration Password Reset (1250ms) & Session-Invalidating Password Change.
 */
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import type { AuthAuditService } from './auth-audit.service.js';
import type { AuthRepository } from './auth.repository.js';
import type { AuthPrincipal, RequestContext } from './auth.types.js';
import type { LoginRateLimitService } from './login-rate-limit.service.js';
import type { PasswordService } from './password.service.js';
import type { ResetMailerService } from './reset-mailer.service.js';
import type { TokenService } from './token.service.js';

export const GENERIC_LOGIN_ERROR = 'Unable to authenticate with the supplied credentials.';
export const GENERIC_RESET_RESPONSE =
  'If the account is eligible, password reset instructions will be sent.';

export interface AuthPasswordDeps {
  repository: AuthRepository;
  passwords: PasswordService;
  tokens: TokenService;
  rateLimit: LoginRateLimitService;
  audit: AuthAuditService;
  mailer: ResetMailerService;
  resetTtl: number;
  onUserSessionsRevoked?: ((userId: bigint, reason: string) => void) | undefined;
}

/**
 * Algorithm / Thuật toán: Đổi mật khẩu có giới hạn tần suất bucket riêng (`change-password`), ghi nhật ký kiểm toán `DENIED` khi sai mật khẩu hiện hành,
 * kiểm tra từ điển cá nhân và thu hồi toàn bộ phiên cũ (BUG-107).
 */
export async function executeChangePassword(
  deps: AuthPasswordDeps,
  principal: AuthPrincipal,
  currentPassword: string,
  newPassword: string,
  context: RequestContext,
): Promise<void> {
  const rateKey = `user:${principal.userId.toString()}`;
  if (typeof deps.rateLimit?.assertAllowed === 'function') {
    await deps.rateLimit.assertAllowed(context.ip, rateKey, 'change-password');
  }
  const user = await deps.repository.findUserById(principal.userId);
  if (!user || !(await deps.passwords.verify(user.passwordHash, currentPassword))) {
    const delayMs =
      typeof deps.rateLimit?.recordFailure === 'function'
        ? await deps.rateLimit.recordFailure(context.ip, rateKey, 'change-password')
        : 0;
    await deps.audit.record(
      {
        action: 'PASSWORD_CHANGE',
        outcome: 'DENIED',
        actorUserId: principal.userId,
        actorUsername: user?.username ?? principal.username,
        reasonCode: 'INVALID_CURRENT_PASSWORD',
        details: { delayMs },
      },
      context,
    );
    throw new UnauthorizedException(GENERIC_LOGIN_ERROR);
  }
  deps.passwords.validate(newPassword, [user.username, user.email]);
  const newPasswordHash = await deps.passwords.hash(newPassword);
  if (typeof deps.repository.changePasswordAndRevokeAll === 'function') {
    await deps.repository.changePasswordAndRevokeAll(user.id, newPasswordHash, 'PASSWORD_CHANGED');
  } else {
    await deps.repository.updatePassword(user.id, newPasswordHash);
    await deps.repository.revokeAllSessions(user.id, 'PASSWORD_CHANGED');
  }
  deps.onUserSessionsRevoked?.(user.id, 'PASSWORD_CHANGED');
  if (typeof deps.rateLimit?.clearAccount === 'function') {
    await deps.rateLimit.clearAccount(rateKey, 'change-password');
  }
  await deps.audit.record(
    {
      action: 'PASSWORD_CHANGE',
      outcome: 'SUCCESS',
      actorUserId: user.id,
      actorUsername: user.username,
    },
    context,
  );
}

/**
 * Algorithm / Thuật toán: Khởi tạo đặt lại mật khẩu đệm thời gian sàn hằng số 1250ms chống dò tài khoản trên bucket cô lập `forgot-password` (BUG-107).
 *   1. Ghi mốc `startedAt`, áp giới hạn tần suất không gian tên `forgot-password` (không ảnh hưởng `login-failures`) và đốt công Argon2id tương đương.
 *   2. Nếu tài khoản tồn tại và `ACTIVE`, sinh Opaque Token 256-bit (chỉ lưu băm SHA-256) và gửi email.
 *   3. Đệm phần thời gian còn thiếu `max(0, 1250ms - elapsed)` trước khi trả thông điệp chuẩn hóa.
 */
export async function executeForgotPassword(
  deps: AuthPasswordDeps,
  identifier: string,
  context: RequestContext,
): Promise<{ message: string }> {
  const startedAt = Date.now();
  const normalized = identifier.normalize('NFKC').trim().toLowerCase();
  const rateKey = `reset:${normalized}`;
  await deps.rateLimit.assertAllowed(context.ip, rateKey, 'forgot-password');
  await deps.rateLimit.recordFailure(context.ip, rateKey, 'forgot-password');
  await deps.passwords.burnEquivalentWork(normalized);
  const user = await deps.repository.findUserByIdentifier(normalized);
  const now = new Date();
  const isEligibleForReset =
    user?.status === 'ACTIVE' && (!user.lockedUntil || user.lockedUntil <= now);
  if (isEligibleForReset && user) {
    const token = deps.tokens.newOpaqueToken();
    await deps.repository.createPasswordReset(
      user.id,
      deps.tokens.hashOpaqueToken(token),
      new Date(Date.now() + deps.resetTtl * 1_000),
      context.ip,
    );
    try {
      await deps.mailer.send(user.email, token);
      await deps.audit.record(
        { action: 'PASSWORD_RESET_REQUEST', outcome: 'SUCCESS', actorUserId: user.id },
        context,
      );
    } catch {
      await deps.audit.record(
        {
          action: 'PASSWORD_RESET_REQUEST',
          outcome: 'FAILED',
          actorUserId: user.id,
          reasonCode: 'DELIVERY_FAILED',
        },
        context,
      );
    }
  } else {
    await deps.audit.record(
      { action: 'PASSWORD_RESET_REQUEST', outcome: 'SUCCESS', actorUsername: 'anonymous' },
      context,
    );
  }
  const remainingDelay = 1_250 - (Date.now() - startedAt);
  if (remainingDelay > 0) await new Promise((resolve) => setTimeout(resolve, remainingDelay));
  return { message: GENERIC_RESET_RESPONSE };
}

/**
 * Algorithm / Thuật toán: Đặt lại mật khẩu bằng tiêu thụ nguyên tử một lần mã khôi phục (Single-Use Reset Token Consumption).
 */
export async function executeResetPassword(
  deps: AuthPasswordDeps,
  token: string,
  newPassword: string,
  context: RequestContext,
): Promise<void> {
  const tokenHash = deps.tokens.hashOpaqueToken(token);
  if (typeof deps.repository.findPasswordResetOwner === 'function') {
    const owner = await deps.repository.findPasswordResetOwner(tokenHash);
    if (!owner) {
      deps.passwords.validate(newPassword);
      throw new BadRequestException('Reset request is invalid or expired.');
    }
    deps.passwords.validate(newPassword, [owner.username, owner.email]);
  } else {
    deps.passwords.validate(newPassword);
  }
  const userId = await deps.repository.consumePasswordReset(
    tokenHash,
    await deps.passwords.hash(newPassword),
  );
  if (!userId) throw new BadRequestException('Reset request is invalid or expired.');
  deps.onUserSessionsRevoked?.(userId, 'PASSWORD_RESET');
  await deps.audit.record(
    { action: 'PASSWORD_RESET', outcome: 'SUCCESS', actorUserId: userId },
    context,
  );
}

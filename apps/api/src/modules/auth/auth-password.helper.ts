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
}

/**
 * Algorithm / Thuật toán: Đổi mật khẩu có xác minh mật khẩu hiện hành, kiểm tra từ điển cá nhân và thu hồi toàn bộ phiên cũ.
 */
export async function executeChangePassword(
  deps: AuthPasswordDeps,
  principal: AuthPrincipal,
  currentPassword: string,
  newPassword: string,
  context: RequestContext,
): Promise<void> {
  const user = await deps.repository.findUserById(principal.userId);
  if (!user || !(await deps.passwords.verify(user.passwordHash, currentPassword))) {
    throw new UnauthorizedException(GENERIC_LOGIN_ERROR);
  }
  deps.passwords.validate(newPassword, [user.username, user.email]);
  await deps.repository.updatePassword(user.id, await deps.passwords.hash(newPassword));
  await deps.repository.revokeAllSessions(user.id, 'PASSWORD_CHANGED');
  await deps.audit.record(
    { action: 'PASSWORD_CHANGE', outcome: 'SUCCESS', actorUserId: user.id },
    context,
  );
}

/**
 * Algorithm / Thuật toán: Khởi tạo đặt lại mật khẩu đệm thời gian sàn hằng số 1250ms chống dò tài khoản (Constant-Floor Anti-Enumeration Reset).
 *   1. Ghi mốc `startedAt`, áp giới hạn tần suất và đốt công tính toán Argon2id tương đương.
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
  deps.rateLimit.assertAllowed(context.ip, rateKey);
  deps.rateLimit.recordFailure(context.ip, rateKey);
  await deps.passwords.burnEquivalentWork(normalized);
  const user = await deps.repository.findUserByIdentifier(normalized);
  if (user?.status === 'ACTIVE') {
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
  await deps.audit.record(
    { action: 'PASSWORD_RESET', outcome: 'SUCCESS', actorUserId: userId },
    context,
  );
}

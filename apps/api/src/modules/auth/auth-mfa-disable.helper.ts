/**
 * @module AuthMfaDisableHelper
 * Algorithm: Step-Up Dual-Factor Re-Authentication & Mandatory Privileged-Role Guard for MFA Removal.
 */
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { MFA_REQUIRED_ROLES, type AuthPrincipal, type RequestContext } from './auth.types.js';
import { verifyActiveMfaChallenge, type AuthMfaDeps } from './auth-mfa.helper.js';

/**
 * Algorithm / Thuật toán: Gỡ bỏ MFA có xác thực lại Step-Up hai nhân tố & khóa cứng vai trò bắt buộc MFA (`executeDisableMfa`).
 *   1. Yêu cầu phiên đã xác thực MFA (`principal.mfa === true`).
 *   2. Từ chối tuyệt đối nếu tài khoản giữ bất kỳ vai trò nào thuộc `MFA_REQUIRED_ROLES` (`SYSTEM_ADMIN`, `SECURITY_OFFICER`, `AUDITOR`) trên cả JWT lẫn cơ sở dữ liệu hiện hành.
 *   3. Giới hạn tần suất chống vét cạn và bắt buộc xác minh đồng thời mật khẩu hiện tại (`passwords.verify`) VÀ mã TOTP hoặc mã khôi phục còn hiệu lực trước khi xóa MFA và thu hồi toàn bộ phiên.
 */
export async function executeDisableMfa(
  deps: Pick<AuthMfaDeps, 'repository' | 'passwords' | 'mfa' | 'rateLimit' | 'audit'>,
  principal: AuthPrincipal,
  currentPassword: string,
  code: string | undefined,
  recoveryCode: string | undefined,
  context: RequestContext,
): Promise<void> {
  if (!principal.mfa) throw new ForbiddenException('Verified MFA is required.');
  if (!currentPassword || (!code && !recoveryCode)) {
    throw new UnauthorizedException('Password and live MFA verification are required.');
  }

  const hasMandatoryRoleInToken = (principal.roles ?? []).some((role) =>
    MFA_REQUIRED_ROLES.has(role),
  );
  if (hasMandatoryRoleInToken) {
    await deps.audit.record(
      {
        action: 'MFA_DISABLE_BLOCKED',
        outcome: 'DENIED',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        reasonCode: 'MFA_MANDATORY_FOR_ROLE',
      },
      context,
    );
    throw new ForbiddenException(
      'Privileged roles (SYSTEM_ADMIN, SECURITY_OFFICER, AUDITOR) must keep MFA enabled.',
    );
  }

  const rateKey = `mfa-disable:${principal.userId}`;
  deps.rateLimit.assertAllowed(context.ip, rateKey);

  const user = await deps.repository.findUserById(principal.userId);
  if (!user || user.status !== 'ACTIVE') {
    deps.rateLimit.recordFailure(context.ip, rateKey);
    throw new UnauthorizedException('Step-up authentication failed.');
  }

  if (user.roles.some((role) => MFA_REQUIRED_ROLES.has(role))) {
    await deps.audit.record(
      {
        action: 'MFA_DISABLE_BLOCKED',
        outcome: 'DENIED',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        reasonCode: 'MFA_MANDATORY_FOR_ROLE',
      },
      context,
    );
    throw new ForbiddenException(
      'Privileged roles (SYSTEM_ADMIN, SECURITY_OFFICER, AUDITOR) must keep MFA enabled.',
    );
  }

  const passwordValid = await deps.passwords.verify(user.passwordHash, currentPassword);
  const mfaValid = passwordValid
    ? await verifyActiveMfaChallenge(deps, principal.userId, code, recoveryCode)
    : false;
  if (!passwordValid || !mfaValid) {
    deps.rateLimit.recordFailure(context.ip, rateKey);
    await deps.audit.record(
      {
        action: 'MFA_DISABLE_DENIED',
        outcome: 'DENIED',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        reasonCode: passwordValid ? 'INVALID_MFA_CHALLENGE' : 'INVALID_PASSWORD',
      },
      context,
    );
    throw new UnauthorizedException('Step-up authentication failed.');
  }

  deps.rateLimit.clearAccount(rateKey);
  await deps.repository.disableMfa(principal.userId);
  await deps.repository.revokeAllSessions(principal.userId, 'MFA_CHANGED');
  await deps.audit.record(
    { action: 'MFA_DISABLED', outcome: 'SUCCESS', actorUserId: principal.userId },
    context,
  );
}

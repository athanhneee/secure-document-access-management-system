/**
 * @module AuthMfaDisableHelper
 * Algorithm: Step-Up Dual-Factor Re-Authentication, Serializable Row-Locked MFA Removal & Privileged-Capability Guard.
 */
import {
  BadRequestException,
  ForbiddenException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import {
  isPrivilegedSeparationRoleOrCapability,
  type PermissionCapabilityLike,
} from '../rbac/permission-matrix.js';
import {
  MFA_REQUIRED_ROLES,
  type AuthPrincipal,
  type AuthUser,
  type RequestContext,
} from './auth.types.js';
import { verifyActiveMfaChallenge, type AuthMfaDeps } from './auth-mfa.helper.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MANDATORY_MFA_DISABLE_MESSAGE =
  'Privileged roles (SYSTEM_ADMIN, SECURITY_OFFICER, AUDITOR, or custom privileged roles) must keep MFA enabled.';
const MANDATORY_MFA_LAST_FACTOR_MESSAGE =
  'Cannot remove the last active MFA factor for a privileged role.';

export interface RemoveMfaMethodResult {
  remainingFactors: number;
  allMfaRemoved: boolean;
}

function parsePermissionCapability(raw: string): PermissionCapabilityLike {
  const separatorIdx = raw.indexOf(':');
  if (separatorIdx <= 0) {
    return { code: raw };
  }
  const resourceType = raw.slice(0, separatorIdx);
  const action = raw.slice(separatorIdx + 1);
  return {
    code: `${resourceType}_${action}`,
    resource_type: resourceType,
    action,
  };
}

/**
 * Algorithm / Thuật toán: Xác Định Tài Khoản Có Nắm Giữ Vai Trò Hệ Thống Hoặc Custom Role Đặc Quyền Bắt Buộc MFA (`hasMandatoryMfaPrivilegedCapability`, BUG-003).
 * Mục đích: Kết hợp cờ DB `hasMandatoryMfaRole`, danh sách mã vai trò `MFA_REQUIRED_ROLES` và phân tích năng lực thực tế qua `isPrivilegedSeparationRoleOrCapability`.
 */
export function hasMandatoryMfaPrivilegedCapability(
  user: Pick<AuthUser, 'roles' | 'hasMandatoryMfaRole' | 'profile'> | null | undefined,
  fallbackRoles?: readonly string[],
): boolean {
  if ((fallbackRoles ?? []).some((role) => MFA_REQUIRED_ROLES.has(role))) {
    return true;
  }
  if (!user) return false;
  if (user.hasMandatoryMfaRole === true) {
    return true;
  }
  if (user.roles.some((role) => MFA_REQUIRED_ROLES.has(role))) {
    return true;
  }
  const profilePermissions = user.profile?.permissions;
  if (Array.isArray(profilePermissions) && profilePermissions.length > 0) {
    const capabilities = profilePermissions.map(parsePermissionCapability);
    if (isPrivilegedSeparationRoleOrCapability(undefined, capabilities)) {
      return true;
    }
  }
  return false;
}

/**
 * Algorithm / Thuật toán: Gỡ bỏ toàn bộ MFA có xác thực lại Step-Up hai nhân tố, kiểm tra Custom Role đặc quyền & giao dịch `SERIALIZABLE` (`executeDisableMfa`, BUG-003).
 *   1. Yêu cầu phiên đã xác thực MFA (`principal.mfa === true`).
 *   2. Từ chối tuyệt đối nếu tài khoản giữ vai trò hệ thống bắt buộc MFA hoặc Custom Role mang năng lực đặc quyền (`isPrivilegedSeparationRoleOrCapability`).
 *   3. Giới hạn tần suất chống vét cạn và bắt buộc xác minh đồng thời mật khẩu hiện tại (`passwords.verify`) VÀ mã TOTP hoặc mã khôi phục còn hiệu lực.
 *   4. Thực thi khóa nguyên tử `SELECT ... FOR UPDATE` trong giao dịch `SERIALIZABLE` (`disableMfaAtomic`), thu hồi toàn bộ phiên và phát sự kiện SSE `USER_SESSION_REVOKED`.
 */
export async function executeDisableMfa(
  deps: Pick<
    AuthMfaDeps,
    'repository' | 'passwords' | 'mfa' | 'rateLimit' | 'audit' | 'onUserSessionsRevoked'
  >,
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
    throw new ForbiddenException(MANDATORY_MFA_DISABLE_MESSAGE);
  }

  const rateKey = `mfa-disable:${principal.userId}`;
  await deps.rateLimit.assertAllowed(context.ip, rateKey, 'mfa');

  const user = await deps.repository.findUserById(principal.userId);
  if (!user || user.status !== 'ACTIVE') {
    await deps.rateLimit.recordFailure(context.ip, rateKey, 'mfa');
    throw new UnauthorizedException('Step-up authentication failed.');
  }

  if (hasMandatoryMfaPrivilegedCapability(user, principal.roles)) {
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
    throw new ForbiddenException(MANDATORY_MFA_DISABLE_MESSAGE);
  }

  const passwordValid = await deps.passwords.verify(user.passwordHash, currentPassword);
  const mfaValid = passwordValid
    ? await verifyActiveMfaChallenge(deps, principal.userId, code, recoveryCode)
    : false;
  if (!passwordValid || !mfaValid) {
    await deps.rateLimit.recordFailure(context.ip, rateKey, 'mfa');
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

  await deps.rateLimit.clearAccount(rateKey, 'mfa');

  if (typeof deps.repository.disableMfaAtomic === 'function') {
    const outcome = await deps.repository.disableMfaAtomic(principal.userId);
    if (outcome.kind === 'mandatory_role_blocked') {
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
      throw new ForbiddenException(MANDATORY_MFA_DISABLE_MESSAGE);
    }
  } else {
    await deps.repository.disableMfa(principal.userId);
  }

  await deps.repository.revokeAllSessions(principal.userId, 'MFA_CHANGED');
  deps.onUserSessionsRevoked?.(principal.userId, 'MFA_CHANGED');
  await deps.audit.record(
    { action: 'MFA_DISABLED', outcome: 'SUCCESS', actorUserId: principal.userId },
    context,
  );
}

/**
 * Algorithm / Thuật toán: Gỡ Một Nhân Tố MFA Đơn Lẻ Có Step-Up Hai Yếu Tố, Chống Race Condition `SERIALIZABLE` + `FOR UPDATE`,
 * Kiểm Tra Custom Role Đặc Quyền & Thu Hồi Toàn Bộ Phiên Khi Gỡ Nhân Tố Cuối (`executeRemoveMfaMethod`, BUG-003).
 */
export async function executeRemoveMfaMethod(
  deps: Pick<
    AuthMfaDeps,
    'repository' | 'passwords' | 'mfa' | 'rateLimit' | 'audit' | 'onUserSessionsRevoked'
  >,
  principal: AuthPrincipal,
  methodId: string,
  currentPassword: string,
  code: string | undefined,
  recoveryCode: string | undefined,
  context: RequestContext,
): Promise<RemoveMfaMethodResult> {
  if (!UUID_REGEX.test(methodId)) {
    throw new BadRequestException('MFA method identifier must be a valid UUID.');
  }
  if (!principal.mfa) {
    throw new ForbiddenException(
      'Step-up MFA verification is required to enroll or modify MFA factors.',
    );
  }
  if (!currentPassword || (!code && !recoveryCode)) {
    throw new UnauthorizedException('Password and live MFA verification are required.');
  }

  const rateKey = `mfa-remove:${principal.userId}`;
  await deps.rateLimit.assertAllowed(context.ip, rateKey, 'mfa');

  const user = await deps.repository.findUserById(principal.userId);
  if (!user || user.status !== 'ACTIVE') {
    await deps.rateLimit.recordFailure(context.ip, rateKey, 'mfa');
    throw new UnauthorizedException('Step-up authentication failed.');
  }

  const activeMethods = await deps.repository.getActiveMfaMethods(principal.userId);
  const target = activeMethods.find((m) => m.id === methodId);
  if (!target) {
    throw new NotFoundException('Active MFA method was not found.');
  }

  const requiresMandatoryMfa = hasMandatoryMfaPrivilegedCapability(user, principal.roles);
  if (requiresMandatoryMfa && activeMethods.length <= 1) {
    await deps.audit.record(
      {
        action: 'MFA_FACTOR_REMOVE_BLOCKED',
        outcome: 'DENIED',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        objectId: methodId,
        reasonCode: 'MFA_MANDATORY_FOR_ROLE',
      },
      context,
    );
    throw new ForbiddenException(MANDATORY_MFA_LAST_FACTOR_MESSAGE);
  }

  const passwordValid = await deps.passwords.verify(user.passwordHash, currentPassword);
  const mfaValid = passwordValid
    ? await verifyActiveMfaChallenge(deps, principal.userId, code, recoveryCode)
    : false;
  if (!passwordValid || !mfaValid) {
    await deps.rateLimit.recordFailure(context.ip, rateKey, 'mfa');
    await deps.audit.record(
      {
        action: 'MFA_FACTOR_REMOVE_DENIED',
        outcome: 'DENIED',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        objectId: methodId,
        reasonCode: passwordValid ? 'INVALID_MFA_CHALLENGE' : 'INVALID_PASSWORD',
      },
      context,
    );
    throw new UnauthorizedException('Step-up authentication failed.');
  }

  await deps.rateLimit.clearAccount(rateKey, 'mfa');

  let remainingFactors: number;
  let removedMethodType: 'TOTP' | 'WEBAUTHN' = target.methodType;
  let removedLabel: string | null = target.label ?? null;

  if (typeof deps.repository.disableSingleMfaMethodAtomic === 'function') {
    const outcome = await deps.repository.disableSingleMfaMethodAtomic(principal.userId, methodId);
    if (outcome.kind === 'not_found') {
      throw new NotFoundException('Active MFA method was not found.');
    }
    if (outcome.kind === 'mandatory_role_last_factor') {
      await deps.audit.record(
        {
          action: 'MFA_FACTOR_REMOVE_BLOCKED',
          outcome: 'DENIED',
          actorUserId: principal.userId,
          actorUsername: principal.username,
          objectId: methodId,
          reasonCode: 'MFA_MANDATORY_FOR_ROLE',
        },
        context,
      );
      throw new ForbiddenException(MANDATORY_MFA_LAST_FACTOR_MESSAGE);
    }
    remainingFactors = outcome.remainingCount;
    removedMethodType = outcome.methodType;
    removedLabel = outcome.label;
  } else {
    const disabled = await deps.repository.disableSingleMfaMethod(principal.userId, methodId);
    if (!disabled) {
      throw new NotFoundException('Active MFA method was not found.');
    }
    remainingFactors = Math.max(0, activeMethods.length - 1);
  }

  const allMfaRemoved = remainingFactors === 0;
  if (allMfaRemoved) {
    await deps.repository.revokeAllSessions(principal.userId, 'MFA_CHANGED');
    deps.onUserSessionsRevoked?.(principal.userId, 'MFA_CHANGED');
  }

  await deps.audit.record(
    {
      action: 'MFA_FACTOR_REMOVED',
      outcome: 'SUCCESS',
      actorUserId: principal.userId,
      actorUsername: principal.username,
      objectId: methodId,
      details: {
        methodType: removedMethodType,
        label: removedLabel,
        remainingFactors,
        sessionsRevoked: allMfaRemoved,
      },
    },
    context,
  );

  return { remainingFactors, allMfaRemoved };
}

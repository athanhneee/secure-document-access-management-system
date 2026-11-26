/**
 * @module AuthWebAuthnHelper
 * Algorithm: FIDO2 / WebAuthn Hardware Key Enrollment & Sign-Counter Clone Detection Workflow.
 */
import { BadRequestException, ConflictException, UnauthorizedException } from '@nestjs/common';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { AppErrorCode } from '@sda/contracts';
import {
  activateVerifiedMfaSession,
  activateVerifiedMfaSessionWithId,
  assertMfaEnrollmentAllowed,
  revokeOtherUnverifiedSessionsOnMfaEnrollment,
  type AuthMfaDeps,
} from './auth-mfa.helper.js';
import type { SessionArtifacts } from './auth.service.js';
import type { AuthPrincipal, RequestContext } from './auth.types.js';
import type { StoredWebAuthnCredential, WebAuthnService } from './webauthn.service.js';

export interface AuthWebAuthnDeps extends AuthMfaDeps {
  webauthn: WebAuthnService;
  onSecurityAlertCreated?: ((alertType: string, alertId?: string) => void) | undefined;
}

/**
 * Algorithm / Thuật toán: Khởi tạo đăng ký khóa bảo mật phần cứng FIDO2/WebAuthn kèm loại trừ khóa đã đăng ký.
 */
export async function executeBeginWebAuthnEnrollment(
  deps: AuthWebAuthnDeps,
  principal: AuthPrincipal,
  label: string | undefined,
  context: RequestContext,
) {
  await assertMfaEnrollmentAllowed(deps, principal, context);
  const existing = await deps.repository.getActiveMfaMethods(principal.userId);
  const existingCreds = existing
    .map((m) => deps.webauthn.parseStoredCredential(m.encryptedSecret))
    .filter((c): c is StoredWebAuthnCredential => c !== null);

  const { options, challengeToken } = await deps.webauthn.generateRegistrationOptions(
    principal.userId,
    principal.username,
    existingCreds,
  );

  await deps.audit.record(
    {
      action: 'MFA_WEBAUTHN_ENROLL_START',
      outcome: 'SUCCESS',
      actorUserId: principal.userId,
      actorUsername: principal.username,
      details: { label: label ?? null },
    },
    context,
  );

  return { options, challengeToken };
}

/**
 * Algorithm / Thuật toán: Xác minh đăng ký khóa FIDO2/WebAuthn, chặn đăng ký trùng `credentialId`,
 * chỉ sinh mã khôi phục khi tài khoản chưa có mã khôi phục hoạt động, lưu khóa công khai mã hóa và thăng cấp phiên MFA (BUG-109).
 */
export async function executeVerifyWebAuthnEnrollment(
  deps: AuthWebAuthnDeps,
  principal: AuthPrincipal,
  response: RegistrationResponseJSON,
  challengeToken: string,
  label: string | undefined,
  context: RequestContext,
): Promise<SessionArtifacts & { recoveryCodes: string[] }> {
  await assertMfaEnrollmentAllowed(deps, principal, context);
  const existingMethods =
    typeof deps.repository.getActiveMfaMethods === 'function'
      ? await deps.repository.getActiveMfaMethods(principal.userId)
      : [];

  const verification = await deps.webauthn.verifyRegistration(
    response,
    challengeToken,
    principal.userId,
    label,
  );

  const isDuplicateCredential = existingMethods.some((m) => {
    const cred = deps.webauthn.parseStoredCredential(m.encryptedSecret);
    return cred !== null && cred.credentialId === verification.credential.credentialId;
  });
  if (isDuplicateCredential) {
    throw new ConflictException({
      errorCode: AppErrorCode.RESOURCE_CONFLICT,
      message: 'This security key credential is already registered for this account.',
    });
  }

  const hasActiveRecoveryCodes = existingMethods.some(
    (m) => Array.isArray(m.recoveryCodeHashes) && m.recoveryCodeHashes.length > 0,
  );
  const recovery = hasActiveRecoveryCodes
    ? { plaintext: [] as string[], hashes: [] as string[] }
    : deps.mfa.createRecoveryCodes();

  const methodId = await deps.repository.createMfaEnrollment(
    principal.userId,
    verification.encryptedSecret,
    label ?? 'FIDO2 / WebAuthn Key',
    'WEBAUTHN',
  );
  await deps.repository.enableMfa(methodId, principal.userId, recovery.hashes);

  const { artifacts, rotatedSessionId } = await activateVerifiedMfaSessionWithId(deps, principal);
  await revokeOtherUnverifiedSessionsOnMfaEnrollment(deps, principal, rotatedSessionId);
  await deps.audit.record(
    {
      action: 'MFA_WEBAUTHN_ENROLLED',
      outcome: 'SUCCESS',
      actorUserId: principal.userId,
      actorUsername: principal.username,
      objectId: methodId,
      details: {
        credentialId: verification.credential.credentialId,
        deviceName: verification.credential.deviceName ?? null,
        aaguid: verification.credential.aaguid ?? null,
      },
    },
    context,
  );

  return { ...artifacts, recoveryCodes: recovery.plaintext };
}

/**
 * Algorithm / Thuật toán: Tạo thử thách xác thực FIDO2/WebAuthn yêu cầu phiên tiền-MFA đã xác thực bước 1, triệt tiêu hoàn toàn Oracle dò tài khoản bật Passkey (N05).
 */
export async function executeGetWebAuthnAuthOptions(
  deps: AuthWebAuthnDeps,
  principal: AuthPrincipal | undefined,
  _username: string | undefined,
  context: RequestContext,
) {
  // CONFLICT-RESOLVED: Chặn truy vấn không phiên theo username để đóng lỗ hổng Passkey Enumeration Oracle (N05).
  if (!principal) {
    throw new UnauthorizedException(
      'Authentication required before initiating WebAuthn verification.',
    );
  }
  const userId = principal.userId;

  const activeMethods = await deps.repository.getActiveMfaMethods(userId);
  const webauthnCreds = activeMethods
    .map((m) => deps.webauthn.parseStoredCredential(m.encryptedSecret))
    .filter((c): c is StoredWebAuthnCredential => c !== null);

  if (webauthnCreds.length === 0) {
    throw new BadRequestException('No WebAuthn security keys found for this account.');
  }

  const { options, challengeToken } = await deps.webauthn.generateAuthenticationOptions(
    webauthnCreds,
    userId,
  );

  await deps.audit.record(
    { action: 'MFA_WEBAUTHN_AUTH_OPTIONS', outcome: 'SUCCESS', actorUserId: userId },
    context,
  );

  return { options, challengeToken };
}

/**
 * Algorithm / Thuật toán: Xác thực khóa bảo mật phần cứng FIDO2/WebAuthn kèm phát hiện nhân bản khóa (Sign-Counter Clone Detection).
 * Giải mã thông tin khóa công khai đã đăng ký, kiểm chứng chữ ký mật mã trên thử thách đã ký HMAC,
 * kiểm tra bộ đếm chữ ký tăng đơn điệu (`newCounter > stored.counter`), phát cảnh báo `CRITICAL` nếu phát hiện lùi bộ đếm,
 * và nâng cấp phiên tiền-MFA lên phiên xác thực đầy đủ.
 */
export async function executeVerifyWebAuthnAuth(
  deps: AuthWebAuthnDeps,
  principal: AuthPrincipal,
  response: AuthenticationResponseJSON,
  challengeToken: string,
  context: RequestContext,
): Promise<SessionArtifacts> {
  const rateKey = `webauthn:${principal.userId}`;
  await deps.rateLimit.assertAllowed(context.ip, rateKey, 'mfa');
  const activeMethods = await deps.repository.getActiveMfaMethods(principal.userId);
  let matchedMethod: (typeof activeMethods)[number] | null = null;
  let matchedCred: StoredWebAuthnCredential | null = null;

  for (const m of activeMethods) {
    const cred = deps.webauthn.parseStoredCredential(m.encryptedSecret);
    if (cred && cred.credentialId === response.id) {
      matchedMethod = m;
      matchedCred = cred;
      break;
    }
  }

  if (!matchedMethod || !matchedCred) {
    await deps.rateLimit.recordFailure(context.ip, rateKey, 'mfa');
    await deps.audit.record(
      {
        action: 'MFA_WEBAUTHN_VERIFY',
        outcome: 'DENIED',
        actorUserId: principal.userId,
        reasonCode: 'CREDENTIAL_NOT_FOUND',
      },
      context,
    );
    throw new UnauthorizedException('Security key credential was not recognized for this user.');
  }

  let result: Awaited<ReturnType<WebAuthnService['verifyAuthentication']>>;
  try {
    result = await deps.webauthn.verifyAuthentication(
      response,
      challengeToken,
      matchedCred,
      principal.userId,
    );
  } catch (error) {
    await deps.rateLimit.recordFailure(context.ip, rateKey, 'mfa');
    throw error;
  }

  let cloneDetected = result.cloneDetected;
  if (!cloneDetected && typeof deps.repository.advanceWebAuthnCounter === 'function') {
    const counterStatus = await deps.repository.advanceWebAuthnCounter(
      matchedMethod.id,
      principal.userId,
      result.newCounter,
      (enc) => deps.webauthn.parseStoredCredential(enc),
      (cred) => deps.mfa.encryptPayload(cred),
    );
    if (counterStatus === 'clone_detected') {
      cloneDetected = true;
    } else if (counterStatus === 'not_found') {
      await deps.rateLimit.recordFailure(context.ip, rateKey, 'mfa');
      throw new UnauthorizedException('Security key credential is no longer active.');
    }
  }

  if (cloneDetected) {
    await deps.rateLimit.recordFailure(context.ip, rateKey, 'mfa');
    await deps.repository.recordSecurityAlert({
      alertType: 'WEBAUTHN_CLONE_DETECTED',
      severity: 'CRITICAL',
      title: 'Cảnh báo khẩn cấp: Phát hiện dấu hiệu nhân bản khóa FIDO2 / Passkey',
      description: `Phát hiện lùi bộ đếm chữ ký hoặc nhân bản khóa bảo mật WebAuthn trên tài khoản #${principal.userId}.`,
      detectedUserId: principal.userId,
    });
    deps.onSecurityAlertCreated?.('WEBAUTHN_CLONE_DETECTED');
    await deps.audit.record(
      {
        action: 'MFA_WEBAUTHN_VERIFY',
        outcome: 'DENIED',
        actorUserId: principal.userId,
        reasonCode: 'CLONE_DETECTED',
        details: { credentialId: matchedCred.credentialId },
      },
      context,
    );
    throw new UnauthorizedException('Security key cloning or replay attack detected.');
  }

  await deps.rateLimit.clearAccount(rateKey, 'mfa');
  if (typeof deps.repository.advanceWebAuthnCounter !== 'function') {
    await deps.repository.updateMfaSecret(matchedMethod.id, result.updatedEncryptedSecret);
  }
  const artifacts = await activateVerifiedMfaSession(deps, principal);
  await deps.audit.record(
    {
      action: 'MFA_WEBAUTHN_VERIFY',
      outcome: 'SUCCESS',
      actorUserId: principal.userId,
      actorUsername: principal.username,
      objectId: matchedMethod.id,
      details: { credentialId: matchedCred.credentialId, counter: result.newCounter },
    },
    context,
  );

  return artifacts;
}

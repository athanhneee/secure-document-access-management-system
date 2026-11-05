/**
 * @module AuthWebAuthnHelper
 * Algorithm: FIDO2 / WebAuthn Hardware Key Enrollment & Sign-Counter Clone Detection Workflow.
 */
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import {
  activateVerifiedMfaSession,
  assertMfaEnrollmentAllowed,
  type AuthMfaDeps,
} from './auth-mfa.helper.js';
import type { SessionArtifacts } from './auth.service.js';
import type { AuthPrincipal, RequestContext } from './auth.types.js';
import type { StoredWebAuthnCredential, WebAuthnService } from './webauthn.service.js';

export interface AuthWebAuthnDeps extends AuthMfaDeps {
  webauthn: WebAuthnService;
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
 * Algorithm / Thuật toán: Xác minh đăng ký khóa FIDO2/WebAuthn, lưu khóa công khai đã mã hóa và thăng cấp phiên MFA.
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
  const verification = await deps.webauthn.verifyRegistration(
    response,
    challengeToken,
    principal.userId,
    label,
  );

  const recovery = deps.mfa.createRecoveryCodes();
  const methodId = await deps.repository.createMfaEnrollment(
    principal.userId,
    verification.encryptedSecret,
    label ?? 'FIDO2 / WebAuthn Key',
    'WEBAUTHN',
  );
  await deps.repository.enableMfa(methodId, principal.userId, recovery.hashes);

  const artifacts = await activateVerifiedMfaSession(deps, principal);
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
 * Algorithm / Thuật toán: Tạo thử thách xác thực FIDO2/WebAuthn chống dò tài khoản khi gọi không phiên.
 */
export async function executeGetWebAuthnAuthOptions(
  deps: AuthWebAuthnDeps,
  principal: AuthPrincipal | undefined,
  username: string | undefined,
  context: RequestContext,
) {
  let userId: bigint | undefined = principal?.userId;
  const normalizedUsername = username?.normalize('NFKC').trim().toLowerCase();
  if (!userId && normalizedUsername) {
    deps.rateLimit.assertAllowed(context.ip, `webauthn-opt:${normalizedUsername}`);
    const user = await deps.repository.findUserByIdentifier(normalizedUsername);
    if (user && user.status === 'ACTIVE') userId = user.id;
  }

  if (!userId) {
    if (!principal && normalizedUsername) {
      deps.rateLimit.recordFailure(context.ip, `webauthn-opt:${normalizedUsername}`);
      throw new BadRequestException(
        'Unable to initiate WebAuthn authentication for the supplied identifier.',
      );
    }
    throw new BadRequestException('User identification is required for WebAuthn authentication.');
  }

  const activeMethods = await deps.repository.getActiveMfaMethods(userId);
  const webauthnCreds = activeMethods
    .map((m) => deps.webauthn.parseStoredCredential(m.encryptedSecret))
    .filter((c): c is StoredWebAuthnCredential => c !== null);

  if (webauthnCreds.length === 0) {
    if (!principal && normalizedUsername) {
      deps.rateLimit.recordFailure(context.ip, `webauthn-opt:${normalizedUsername}`);
      throw new BadRequestException(
        'Unable to initiate WebAuthn authentication for the supplied identifier.',
      );
    }
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
  deps.rateLimit.assertAllowed(context.ip, rateKey);
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
    deps.rateLimit.recordFailure(context.ip, rateKey);
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
    deps.rateLimit.recordFailure(context.ip, rateKey);
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
      deps.rateLimit.recordFailure(context.ip, rateKey);
      throw new UnauthorizedException('Security key credential is no longer active.');
    }
  }

  if (cloneDetected) {
    deps.rateLimit.recordFailure(context.ip, rateKey);
    await deps.repository.recordSecurityAlert({
      alertType: 'WEBAUTHN_CLONE_DETECTED',
      severity: 'CRITICAL',
      title: 'FIDO2 / WebAuthn clone attack detected',
      description: `Authenticator counter rollback or cloned key detected for user ID ${principal.userId}.`,
      detectedUserId: principal.userId,
    });
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

  deps.rateLimit.clearAccount(rateKey);
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

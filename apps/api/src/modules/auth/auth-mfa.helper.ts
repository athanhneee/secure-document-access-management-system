/**
 * @module AuthMfaHelper
 * Algorithm: Step-Up MFA Enrollment Guard, QR Code Provisioning, RFC 6238 TOTP Verification & One-Time Recovery Code Fallback.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import QRCode from 'qrcode';
import type { AuthAuditService } from './auth-audit.service.js';
import type { AuthRepository } from './auth.repository.js';
import type { SessionArtifacts } from './auth.service.js';
import type { AuthPrincipal, RequestContext } from './auth.types.js';
import type { LoginRateLimitService } from './login-rate-limit.service.js';
import type { MfaService } from './mfa.service.js';
import type { PasswordService } from './password.service.js';
import type { TokenService } from './token.service.js';

export { executeDisableMfa } from './auth-mfa-disable.helper.js';

export interface AuthMfaDeps {
  repository: AuthRepository;
  passwords: PasswordService;
  tokens: TokenService;
  mfa: MfaService;
  rateLimit: LoginRateLimitService;
  audit: AuthAuditService;
  accessTtl: number;
  refreshTtl: number;
}

/**
 * Algorithm / Thuật toán: Chốt chặn đăng ký nhân tố mới yêu cầu Step-Up MFA nếu tài khoản đã có MFA kích hoạt.
 */
export async function assertMfaEnrollmentAllowed(
  deps: Pick<AuthMfaDeps, 'repository' | 'audit'>,
  principal: AuthPrincipal,
  context: RequestContext,
): Promise<void> {
  if (principal.mfa) return;
  const activeMethods =
    typeof deps.repository.getActiveMfaMethods === 'function'
      ? await deps.repository.getActiveMfaMethods(principal.userId)
      : [];
  if (activeMethods.length > 0) {
    await deps.audit.record(
      {
        action: 'MFA_ENROLLMENT_BLOCKED',
        outcome: 'DENIED',
        actorUserId: principal.userId,
        actorUsername: principal.username,
        reasonCode: 'STEP_UP_MFA_REQUIRED',
      },
      context,
    );
    throw new ForbiddenException(
      'Step-up MFA verification is required to enroll or modify MFA factors.',
    );
  }
}

/**
 * Algorithm / Thuật toán: Thăng cấp phiên tiền-MFA thành phiên xác thực đầy đủ kèm phát hành Refresh Token & CSRF mới.
 */
export async function activateVerifiedMfaSession(
  deps: Pick<AuthMfaDeps, 'repository' | 'tokens' | 'accessTtl' | 'refreshTtl'>,
  principal: AuthPrincipal,
): Promise<SessionArtifacts> {
  const refreshToken = deps.tokens.newOpaqueToken();
  const activated = (await deps.repository.activateMfaSession(
    principal.sessionId,
    principal.userId,
    {
      id: randomUUID(),
      hash: deps.tokens.hashOpaqueToken(refreshToken),
      expiresAt: new Date(Date.now() + deps.refreshTtl * 1_000),
    },
  )) as string | boolean | null;
  if (!activated) throw new UnauthorizedException('Session is no longer valid.');
  const rotatedSessionId = typeof activated === 'string' ? activated : randomUUID();
  return {
    accessToken: await deps.tokens.issueAccessToken(principal.userId, rotatedSessionId, true),
    refreshToken,
    csrfToken: randomBytes(32).toString('base64url'),
    accessMaxAge: deps.accessTtl,
    refreshMaxAge: deps.refreshTtl,
    mfaRequired: false,
    enrollmentRequired: false,
  };
}

/**
 * Algorithm / Thuật toán: Khởi tạo đăng ký TOTP (mã hóa bí mật AES-256-GCM, tạo URI otpauth và kết xuất ảnh QR DataURL).
 */
export async function executeBeginMfaEnrollment(
  deps: Pick<AuthMfaDeps, 'repository' | 'mfa' | 'audit'>,
  principal: AuthPrincipal,
  label: string | undefined,
  context: RequestContext,
): Promise<{ secret: string; uri: string; qrCodeDataUrl: string }> {
  await assertMfaEnrollmentAllowed(deps, principal, context);
  const enrollment = deps.mfa.createEnrollment(principal.username);
  await deps.repository.createMfaEnrollment(principal.userId, enrollment.encryptedSecret, label);
  // CONFLICT-RESOLVED: Sinh trực tiếp ảnh QR DataURL từ otpauth URI trên máy chủ để giao diện đăng ký MFA hiển thị tức thời (HIGH-09)
  const qrCodeDataUrl = await QRCode.toDataURL(enrollment.uri, {
    errorCorrectionLevel: 'M',
    margin: 1,
    width: 220,
  });
  await deps.audit.record(
    { action: 'MFA_ENROLLMENT_STARTED', outcome: 'SUCCESS', actorUserId: principal.userId },
    context,
  );
  return { secret: enrollment.secret, uri: enrollment.uri, qrCodeDataUrl };
}

/**
 * Algorithm / Thuật toán: Xác minh mã TOTP đầu tiên, sinh bộ mã khôi phục dự phòng và kích hoạt phiên MFA.
 */
export async function executeVerifyMfaEnrollment(
  deps: Pick<
    AuthMfaDeps,
    'repository' | 'tokens' | 'mfa' | 'rateLimit' | 'audit' | 'accessTtl' | 'refreshTtl'
  >,
  principal: AuthPrincipal,
  code: string,
  context: RequestContext,
): Promise<SessionArtifacts & { recoveryCodes: string[] }> {
  const rateKey = `mfa-enroll:${principal.userId}`;
  deps.rateLimit.assertAllowed(context.ip, rateKey);
  await assertMfaEnrollmentAllowed(deps, principal, context);
  const pending = await deps.repository.pendingMfaMethod(principal.userId);
  if (!pending || !deps.mfa.verifyTotp(pending.encryptedSecret, code)) {
    deps.rateLimit.recordFailure(context.ip, rateKey);
    throw new UnauthorizedException('MFA verification failed.');
  }
  deps.rateLimit.clearAccount(rateKey);
  const recovery = deps.mfa.createRecoveryCodes();
  await deps.repository.enableMfa(pending.id, principal.userId, recovery.hashes);
  const artifacts = await activateVerifiedMfaSession(deps, principal);
  await deps.audit.record(
    { action: 'MFA_ENABLED', outcome: 'SUCCESS', actorUserId: principal.userId },
    context,
  );
  return { ...artifacts, recoveryCodes: recovery.plaintext };
}

/**
 * Thuật toán: Xác minh thử thách MFA đang hoạt động qua mã TOTP RFC 6238 hoặc tiêu thụ nguyên tử mã khôi phục một lần.
 */
export async function verifyActiveMfaChallenge(
  deps: Pick<AuthMfaDeps, 'repository' | 'mfa'>,
  userId: bigint,
  code: string | undefined,
  recoveryCode: string | undefined,
): Promise<boolean> {
  const activeMethods = await deps.repository.getActiveMfaMethods(userId);
  if (activeMethods.length === 0) return false;

  if (code) {
    for (const method of activeMethods) {
      try {
        if (deps.mfa.verifyTotp(method.encryptedSecret, code)) {
          return true;
        }
      } catch {
        // Ignore non-TOTP secrets (e.g. WebAuthn JSON credential payloads)
      }
    }
  }

  if (recoveryCode) {
    if (typeof deps.repository.consumeRecoveryCodeAtomic === 'function') {
      return deps.repository.consumeRecoveryCodeAtomic(userId, recoveryCode, (hashes, candidate) =>
        deps.mfa.consumeRecoveryCode(hashes, candidate),
      );
    }
    for (const method of activeMethods) {
      const remaining = deps.mfa.consumeRecoveryCode(method.recoveryCodeHashes, recoveryCode);
      if (remaining) {
        await deps.repository.consumeRecoveryCode(method.id, remaining);
        return true;
      }
    }
  }

  return false;
}

/**
 * Algorithm / Thuật toán: Xác thực nhân tố thứ hai đa phương thức (RFC 6238 TOTP fallback sang One-Time Recovery Code).
 */
export async function executeVerifyMfa(
  deps: Pick<
    AuthMfaDeps,
    'repository' | 'tokens' | 'mfa' | 'rateLimit' | 'audit' | 'accessTtl' | 'refreshTtl'
  >,
  principal: AuthPrincipal,
  code: string | undefined,
  recoveryCode: string | undefined,
  context: RequestContext,
): Promise<SessionArtifacts> {
  const rateKey = `mfa:${principal.userId}`;
  deps.rateLimit.assertAllowed(context.ip, rateKey);
  const valid = await verifyActiveMfaChallenge(deps, principal.userId, code, recoveryCode);
  if (!valid) {
    deps.rateLimit.recordFailure(context.ip, rateKey);
    await deps.audit.record(
      { action: 'MFA_VERIFY', outcome: 'DENIED', actorUserId: principal.userId },
      context,
    );
    throw new UnauthorizedException('MFA verification failed.');
  }
  deps.rateLimit.clearAccount(rateKey);
  const artifacts = await activateVerifiedMfaSession(deps, principal);
  await deps.audit.record(
    { action: 'MFA_VERIFY', outcome: 'SUCCESS', actorUserId: principal.userId },
    context,
  );
  return artifacts;
}

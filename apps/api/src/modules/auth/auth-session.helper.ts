/**
 * @module AuthSessionHelper
 * Algorithm: Constant-Work Multi-Stage Login, Pre-MFA Session Isolation & RFC 9700 Refresh Token Rotation.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { UnauthorizedException } from '@nestjs/common';
import type { AuthAuditService } from './auth-audit.service.js';
import { GENERIC_LOGIN_ERROR } from './auth-password.helper.js';
import type { AuthRepository } from './auth.repository.js';
import type { SessionArtifacts } from './auth.service.js';
import { MFA_REQUIRED_ROLES, type RequestContext } from './auth.types.js';
import type { LoginRateLimitService } from './login-rate-limit.service.js';
import type { PasswordService } from './password.service.js';
import type { TokenService } from './token.service.js';

export interface AuthSessionLifecycleDeps {
  repository: AuthRepository;
  passwords: PasswordService;
  tokens: TokenService;
  rateLimit: LoginRateLimitService;
  audit: AuthAuditService;
  accessTtl: number;
  refreshTtl: number;
}

/**
 * Algorithm / Thuật toán: Xác thực đăng nhập đa tầng kháng dò tài khoản và phân tách phiên tiền-MFA (Constant-Work Multi-Stage Login).
 *   1. Chuẩn hóa NFKC chữ thường và kiểm tra giới hạn tần suất theo IP + tài khoản.
 *   2. Luôn thực thi Argon2id (trên mật khẩu thật hoặc `burnEquivalentWork` giả) để triệt tiêu Timing Side-Channel.
 *   3. Cấp phiên tiền-MFA hạn chế (TTL 300s, chưa có Refresh Token) nếu tài khoản bật MFA hoặc thuộc `MFA_REQUIRED_ROLES`.
 */
export async function executeLogin(
  deps: AuthSessionLifecycleDeps,
  identifier: string,
  password: string,
  context: RequestContext,
): Promise<SessionArtifacts> {
  const accountKey = identifier.normalize('NFKC').trim().toLowerCase();
  deps.rateLimit.assertAllowed(context.ip, accountKey);
  const user = await deps.repository.findUserByIdentifier(accountKey);
  const passwordMatches = user
    ? await deps.passwords.verify(user.passwordHash, password)
    : (await deps.passwords.burnEquivalentWork(password), false);
  const eligible =
    user?.status === 'ACTIVE' && (!user.lockedUntil || user.lockedUntil <= new Date());
  if (!user || !passwordMatches || !eligible) {
    const delayMs = deps.rateLimit.recordFailure(context.ip, accountKey);
    if (user) await deps.repository.recordLoginFailure(user);
    await deps.audit.record(
      {
        action: 'LOGIN',
        outcome: 'DENIED',
        actorUserId: user?.id,
        actorUsername: user?.username ?? accountKey.slice(0, 80),
        reasonCode: 'INVALID_CREDENTIALS',
        details: { delayMs },
      },
      context,
    );
    throw new UnauthorizedException(GENERIC_LOGIN_ERROR);
  }

  deps.rateLimit.clearAccount(accountKey);
  await deps.repository.recordLoginSuccess(user.id);
  const mfaRequired =
    Boolean(user.mfaMethod) || user.roles.some((role) => MFA_REQUIRED_ROLES.has(role));
  const artifacts = await startAuthSession(deps, user.id, context, !mfaRequired, mfaRequired);
  await deps.audit.record(
    {
      action: 'LOGIN',
      outcome: 'SUCCESS',
      actorUserId: user.id,
      actorUsername: user.username,
      objectId: artifacts.sessionId,
      details: { mfaRequired },
    },
    context,
  );
  return { ...artifacts, mfaRequired, enrollmentRequired: mfaRequired && !user.mfaMethod };
}

/**
 * Algorithm / Thuật toán: Làm mới phiên bằng xoay vòng Opaque Refresh Token kèm phát hiện đánh cắp (RFC 9700 Rotation & CSRF Renewal).
 */
export async function executeRefresh(
  deps: AuthSessionLifecycleDeps,
  refreshToken: string,
  context: RequestContext,
): Promise<SessionArtifacts> {
  const nextToken = deps.tokens.newOpaqueToken();
  const result = await deps.repository.rotateRefreshToken(
    deps.tokens.hashOpaqueToken(refreshToken),
    {
      id: randomUUID(),
      hash: deps.tokens.hashOpaqueToken(nextToken),
      expiresAt: new Date(Date.now() + deps.refreshTtl * 1_000),
    },
  );
  if (result.kind === 'reuse') {
    await deps.audit.record(
      {
        action: 'REFRESH_REUSE',
        outcome: 'DENIED',
        actorUserId: result.userId,
        objectId: result.sessionId,
        reasonCode: 'REFRESH_TOKEN_REUSE',
      },
      context,
    );
    throw new UnauthorizedException('Session is no longer valid.');
  }
  if (result.kind !== 'rotated') throw new UnauthorizedException('Session is no longer valid.');
  const accessToken = await deps.tokens.issueAccessToken(
    result.user.id,
    result.sessionId,
    result.mfa,
  );
  await deps.audit.record(
    {
      action: 'TOKEN_REFRESH',
      outcome: 'SUCCESS',
      actorUserId: result.user.id,
      objectId: result.sessionId,
    },
    context,
  );
  return {
    accessToken,
    refreshToken: nextToken,
    csrfToken: randomBytes(32).toString('base64url'),
    accessMaxAge: deps.accessTtl,
    refreshMaxAge: deps.refreshTtl,
    mfaRequired: false,
    enrollmentRequired: false,
  };
}

/**
 * Algorithm / Thuật toán: Khởi tạo phiên xác thực mới kèm cặp khóa họ Refresh Token và mã CSRF ngẫu nhiên 256-bit.
 */
async function startAuthSession(
  deps: AuthSessionLifecycleDeps,
  userId: bigint,
  context: RequestContext,
  issueRefresh: boolean,
  preMfa: boolean,
): Promise<SessionArtifacts & { sessionId: string }> {
  const sessionId = randomUUID();
  const familyId = randomUUID();
  const refreshToken = issueRefresh ? deps.tokens.newOpaqueToken() : undefined;
  const lifetime = preMfa ? 300 : deps.refreshTtl;
  await deps.repository.createSession({
    userId,
    sessionId,
    familyId,
    refreshTokenId: refreshToken ? randomUUID() : undefined,
    refreshTokenHash: refreshToken ? deps.tokens.hashOpaqueToken(refreshToken) : undefined,
    refreshExpiresAt: refreshToken ? new Date(Date.now() + deps.refreshTtl * 1_000) : undefined,
    sessionExpiresAt: new Date(Date.now() + lifetime * 1_000),
    mfaVerified: !preMfa,
    context,
  });
  return {
    sessionId,
    accessToken: await deps.tokens.issueAccessToken(userId, sessionId, !preMfa),
    refreshToken,
    csrfToken: randomBytes(32).toString('base64url'),
    accessMaxAge: preMfa ? 300 : deps.accessTtl,
    refreshMaxAge: deps.refreshTtl,
    mfaRequired: preMfa,
    enrollmentRequired: false,
  };
}

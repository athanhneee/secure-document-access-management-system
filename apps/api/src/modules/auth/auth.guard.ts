/**
 * @module AuthGuard
 * Thuật toán: Cổng kiểm soát xác thực phiên có trạng thái kết hợp bộ đệm phân tán TTL ngắn 5 giây (`auth-session:${sessionId}`)
 * và cưỡng chế cách ly phiên tiền-MFA theo vai trò đặc quyền / nhân tố MFA đã đăng ký.
 */
import {
  Injectable,
  Optional,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { FastifyRequest } from 'fastify';
import { AppConfigService } from '../../config/config.service.js';
import { DefaultDenyGuard } from '../../default-deny.guard.js';
import { DistributedStateService } from '../concurrency/distributed-state.service.js';
import { ALLOW_PRE_MFA_METADATA } from './allow-pre-mfa.js';
import { AuthRepository } from './auth.repository.js';
import { MFA_REQUIRED_ROLES, type AuthPrincipal } from './auth.types.js';
import { TokenService } from './token.service.js';

const AUTH_SESSION_CACHE_TTL_MS = 5_000;

interface CachedAuthPrincipal {
  userId: string;
  sessionId: string;
  username: string;
  roles: string[];
  mfa: boolean;
  mfaPending?: boolean | undefined;
  userEpoch: number;
  globalEpoch: number;
}

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly defaultDenyGuard: DefaultDenyGuard;
  private readonly stateStore: DistributedStateService;

  constructor(
    private readonly reflector: Reflector,
    private readonly tokens: TokenService,
    private readonly repository: AuthRepository,
    @Optional() defaultDenyGuard?: DefaultDenyGuard,
    @Optional() config?: AppConfigService,
    @Optional() stateStore?: DistributedStateService,
  ) {
    this.defaultDenyGuard = defaultDenyGuard ?? new DefaultDenyGuard(reflector);
    this.stateStore = stateStore ?? new DistributedStateService(config);
  }

  /**
   * Thuật toán: Thẩm định JWT EdDSA, tra cứu bộ đệm phân tán `auth-session:${sessionId}` (TTL 5.000ms gắn Epoch người dùng & toàn cục),
   * đóng an toàn (fail-closed) khi phiên bị thu hồi hoặc tài khoản khóa/vô hiệu hóa, và chặn phiên `mfaPending` trên endpoint thường.
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (this.defaultDenyGuard.canActivate(context)) {
      return true;
    }
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const token = request.cookies?.['sda_access'];
    if (!token) throw new UnauthorizedException('Authentication required.');
    const claims = await this.tokens.verifyAccessToken(token);
    const userId = BigInt(claims.sub);
    const sessionId = claims['sid'];
    const principal = await this.resolveSessionPrincipal(userId, sessionId);
    if (!principal || principal.mfa !== claims.mfa) {
      await this.stateStore.deleteKey('auth-session', sessionId);
      throw new UnauthorizedException('Session is no longer valid.');
    }
    const preMfaAllowed =
      this.reflector.get<unknown>(ALLOW_PRE_MFA_METADATA, context.getHandler()) === true;
    const mfaPending =
      !principal.mfa &&
      (principal.mfaPending === true ||
        (principal.mfaPending === undefined &&
          (principal.roles ?? []).some((role) => MFA_REQUIRED_ROLES.has(role))));
    if (mfaPending && !preMfaAllowed) {
      throw new UnauthorizedException('MFA verification is required.');
    }
    request.auth = principal;
    return true;
  }

  /**
   * Thuật toán: Phân giải `AuthPrincipal` qua bộ đệm 5 giây có kiểm chứng số hiệu thế hệ (`auth-global` & `auth-user:${userId}`);
   * tuyệt đối không lưu đệm kết quả `null` để tài khoản bị thu hồi/vô hiệu hóa luôn bị từ chối tức thì.
   */
  private async resolveSessionPrincipal(
    userId: bigint,
    sessionId: string,
  ): Promise<AuthPrincipal | null> {
    const userIdStr = userId.toString();
    const [globalEpoch, userEpoch, cached] = await Promise.all([
      this.stateStore.getNamespaceEpoch('auth-global'),
      this.stateStore.getNamespaceEpoch(`auth-user:${userIdStr}`),
      this.stateStore.getJson<CachedAuthPrincipal>('auth-session', sessionId),
    ]);
    if (
      cached &&
      cached.globalEpoch === globalEpoch &&
      cached.userEpoch === userEpoch &&
      cached.userId === userIdStr &&
      cached.sessionId === sessionId
    ) {
      return {
        userId: BigInt(cached.userId),
        sessionId: cached.sessionId,
        username: cached.username,
        roles: cached.roles,
        mfa: cached.mfa,
        mfaPending: cached.mfaPending,
      };
    }

    const fresh = await this.repository.principalForSession(userId, sessionId);
    if (!fresh) {
      return null;
    }
    await this.stateStore.putEphemeral<CachedAuthPrincipal>(
      'auth-session',
      sessionId,
      {
        userId: fresh.userId.toString(),
        sessionId: fresh.sessionId,
        username: fresh.username,
        roles: fresh.roles,
        mfa: fresh.mfa,
        mfaPending: fresh.mfaPending,
        userEpoch,
        globalEpoch,
      },
      AUTH_SESSION_CACHE_TTL_MS,
    );
    return fresh;
  }
}

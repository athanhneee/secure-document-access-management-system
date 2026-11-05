import {
  Injectable,
  Optional,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { FastifyRequest } from 'fastify';
import { DefaultDenyGuard } from '../../default-deny.guard.js';
import { ALLOW_PRE_MFA_METADATA } from './allow-pre-mfa.js';
import { AuthRepository } from './auth.repository.js';
import { TokenService } from './token.service.js';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly defaultDenyGuard: DefaultDenyGuard;

  constructor(
    private readonly reflector: Reflector,
    private readonly tokens: TokenService,
    private readonly repository: AuthRepository,
    @Optional() defaultDenyGuard?: DefaultDenyGuard,
  ) {
    this.defaultDenyGuard = defaultDenyGuard ?? new DefaultDenyGuard(reflector);
  }

  /**
   * Thuật toán: Cổng kiểm soát xác thực phiên trực tuyến kết hợp cưỡng chế bước nâng cấp MFA (Stateful JWT + Step-Up MFA Guard).
   * Cơ chế hoạt động:
   *   1. Ủy quyền cho `DefaultDenyGuard` thẩm định siêu dữ liệu công khai tường minh (`PUBLIC_ENDPOINT_METADATA === true`).
   *   2. Xác minh chữ ký EdDSA của JWT trong cookie `sda_access` và đối chiếu chéo trạng thái phiên trực tiếp trong DB
   *      (đảm bảo thu hồi phiên có hiệu lực tức thì và cờ `mfa` trong JWT không bị lệch với trạng thái phiên).
   *   3. Chặn mọi phiên chưa hoàn tất MFA trừ các endpoint đăng ký/xác minh được đánh dấu `ALLOW_PRE_MFA_METADATA`.
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
    const principal = await this.repository.principalForSession(userId, claims['sid']);
    if (!principal || principal.mfa !== claims.mfa) {
      throw new UnauthorizedException('Session is no longer valid.');
    }
    const preMfaAllowed =
      this.reflector.get<unknown>(ALLOW_PRE_MFA_METADATA, context.getHandler()) === true;
    if (!principal.mfa && !preMfaAllowed) {
      throw new UnauthorizedException('MFA verification is required.');
    }
    request.auth = principal;
    return true;
  }
}

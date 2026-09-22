import {
  Injectable,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { FastifyRequest } from 'fastify';
import { PUBLIC_ENDPOINT_METADATA } from '../../public-endpoint.js';
import { ALLOW_PRE_MFA_METADATA } from './allow-pre-mfa.js';
import { AuthRepository } from './auth.repository.js';
import { TokenService } from './token.service.js';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly tokens: TokenService,
    private readonly repository: AuthRepository,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (this.reflector.get<unknown>(PUBLIC_ENDPOINT_METADATA, context.getHandler()) === true) {
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

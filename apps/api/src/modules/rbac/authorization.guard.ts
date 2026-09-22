import {
  ForbiddenException,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { FastifyRequest } from 'fastify';
import { PUBLIC_ENDPOINT_METADATA } from '../../public-endpoint.js';
import { AuthorizationService } from './authorization.service.js';
import { REQUIRED_PERMISSION_METADATA, type RequiredPermission } from './require-permission.js';

@Injectable()
export class AuthorizationGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly authorization: AuthorizationService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (this.reflector.get<unknown>(PUBLIC_ENDPOINT_METADATA, context.getHandler()) === true)
      return true;
    const required = this.reflector.get<RequiredPermission>(
      REQUIRED_PERMISSION_METADATA,
      context.getHandler(),
    );
    if (!required) return true;
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    if (!request.auth) throw new ForbiddenException('Authenticated principal is unavailable.');
    await this.authorization.assertPermission(request.auth, required.resource, required.action, {
      requireGlobal: required.global ?? false,
      anyScope: !required.global,
    });
    return true;
  }
}

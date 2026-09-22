import { Injectable, type CanActivate, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { isExplicitlyPublicEndpoint } from '@sda/security';
import { PUBLIC_ENDPOINT_METADATA } from './public-endpoint.js';

@Injectable()
export class DefaultDenyGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const declaration = this.reflector.get<unknown>(PUBLIC_ENDPOINT_METADATA, context.getHandler());
    return isExplicitlyPublicEndpoint(declaration);
  }
}

import { timingSafeEqual } from 'node:crypto';
import { ForbiddenException, Injectable } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { AppConfigService } from '../../config/config.service.js';

@Injectable()
export class CsrfService {
  private readonly allowedOrigins: Set<string>;

  constructor(config: AppConfigService) {
    this.allowedOrigins = new Set(config.corsOrigins);
  }

  assertRequest(request: FastifyRequest): void {
    const origin = request.headers.origin;
    if (typeof origin !== 'string' || !this.allowedOrigins.has(origin)) {
      throw new ForbiddenException('Request origin is not allowed.');
    }
    const cookieToken = request.cookies?.['sda_csrf'];
    const headerToken = request.headers['x-csrf-token'];
    if (
      typeof cookieToken !== 'string' ||
      typeof headerToken !== 'string' ||
      cookieToken.length < 32 ||
      cookieToken.length !== headerToken.length ||
      !timingSafeEqual(Buffer.from(cookieToken), Buffer.from(headerToken))
    ) {
      throw new ForbiddenException('CSRF validation failed.');
    }
  }
}

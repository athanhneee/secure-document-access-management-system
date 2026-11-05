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
import {
  ALLOW_AUTHENTICATED_SELF_METADATA,
  REQUIRED_ANY_PERMISSION_METADATA,
  REQUIRED_PERMISSION_METADATA,
  type RequiredPermission,
} from './require-permission.js';

@Injectable()
export class AuthorizationGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly authorization: AuthorizationService,
  ) {}

  /**
   * Thuật toán: Tra cứu siêu dữ liệu phân cấp Handler -> Controller an toàn cho cả runtime NestJS và mock kiểm thử đơn vị.
   */
  private readMetadata<T>(key: string | symbol, context: ExecutionContext): T | undefined {
    const handlerVal = this.reflector.get<T>(key, context.getHandler());
    if (handlerVal !== undefined) return handlerVal;
    if (typeof context.getClass === 'function') {
      return this.reflector.get<T>(key, context.getClass());
    }
    return undefined;
  }

  /**
   * Thuật toán: Cổng kiểm tra quyền siêu dữ liệu khai báo theo nguyên lý Mặc định Từ chối (Fail-Closed Declarative Authorization Guard).
   * Cơ chế hoạt động:
   *   1. Cho phép đi qua nếu endpoint được đánh dấu `@PublicEndpoint()` tường minh.
   *   2. Với endpoint tự phục vụ phiên cá nhân (`@AllowAuthenticatedSelf()`), bắt buộc phải có `request.auth`.
   *   3. Với `@RequirePermission` hoặc `@RequireAnyPermission`, thẩm định quyền và phạm vi qua `AuthorizationService`.
   *   4. Nếu route không khai báo bất kỳ chính sách phân quyền nào ở trên, lập tức ném `ForbiddenException` (Fail-Closed).
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (this.readMetadata<unknown>(PUBLIC_ENDPOINT_METADATA, context) === true) {
      return true;
    }
    const required = this.readMetadata<RequiredPermission>(REQUIRED_PERMISSION_METADATA, context);
    const requiredAny = this.readMetadata<RequiredPermission[]>(
      REQUIRED_ANY_PERMISSION_METADATA,
      context,
    );
    const allowSelf =
      this.readMetadata<unknown>(ALLOW_AUTHENTICATED_SELF_METADATA, context) === true;

    // CONFLICT-RESOLVED: Chuyển AuthorizationGuard từ Fail-Open sang Fail-Closed (Default-Deny) khi endpoint quên gắn decorator quyền (HIGH-03).
    if (!required && (!requiredAny || requiredAny.length === 0) && !allowSelf) {
      throw new ForbiddenException(
        'Endpoint lacks an explicit authorization policy (default-deny).',
      );
    }

    const request = context.switchToHttp().getRequest<FastifyRequest>();
    if (!request.auth) throw new ForbiddenException('Authenticated principal is unavailable.');

    if (required) {
      await this.authorization.assertPermission(request.auth, required.resource, required.action, {
        requireGlobal: required.global ?? false,
        anyScope: !required.global,
      });
      return true;
    }

    if (requiredAny && requiredAny.length > 0) {
      for (const candidate of requiredAny) {
        const granted = await this.authorization.hasPermission(
          request.auth,
          candidate.resource,
          candidate.action,
          {
            requireGlobal: candidate.global ?? false,
            anyScope: !candidate.global,
          },
        );
        if (granted) return true;
      }
      throw new ForbiddenException('Insufficient permissions for the requested resource.');
    }

    return true;
  }
}

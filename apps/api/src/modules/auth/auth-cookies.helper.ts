/**
 * @module AuthCookiesHelper
 * Algorithm: HttpOnly SameSite=Strict Cookie Binding, Double-Submit CSRF Guard & Request Context Extractor.
 */
import { BadRequestException } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { z } from 'zod';
import { parseAuthBody } from './auth.schemas.js';
import type { SessionArtifacts } from './auth.service.js';
import type { AuthPrincipal, RequestContext } from './auth.types.js';
import type { CsrfService } from './csrf.service.js';

/**
 * Algorithm / Thuật toán: Thiết lập bộ ba cookie phiên (`sda_access` HttpOnly giới hạn `/api/v1`, `sda_refresh` HttpOnly giới hạn `/api/v1/auth`, và `sda_csrf` đặt tại `/` để client đọc qua `document.cookie` trên mọi route giao diện theo mẫu Double-Submit Cookie, đồng thời dọn bỏ bản ghi `sda_csrf` đường dẫn `/api/v1` cũ tránh che khuất theo RFC 6265 §5.4).
 */
export function setAuthSessionCookies(
  reply: FastifyReply,
  result: SessionArtifacts,
  secureCookies: boolean,
): void {
  const base = { secure: secureCookies, sameSite: 'strict' as const };
  reply.setCookie('sda_access', result.accessToken, {
    ...base,
    httpOnly: true,
    path: '/api/v1',
    maxAge: result.accessMaxAge,
  });
  if (result.refreshToken) {
    reply.setCookie('sda_refresh', result.refreshToken, {
      ...base,
      httpOnly: true,
      path: '/api/v1/auth',
      maxAge: result.refreshMaxAge,
    });
  } else {
    reply.clearCookie('sda_refresh', { ...base, path: '/api/v1/auth' });
  }
  // CONFLICT-RESOLVED: Đặt sda_csrf tại path '/' (và xóa bản ghi '/api/v1' kế thừa) để document.cookie trên mọi route giao diện đọc được mã Double-Submit CSRF.
  reply.clearCookie('sda_csrf', { ...base, path: '/api/v1' });
  reply.setCookie('sda_csrf', result.csrfToken, {
    ...base,
    httpOnly: false,
    path: '/',
    maxAge: result.refreshMaxAge,
  });
}

/**
 * Algorithm / Thuật toán: Thu hồi đồng bộ toàn bộ cookie xác thực và CSRF (cả đường dẫn gốc `/` lẫn đường dẫn kế thừa `/api/v1`) trên trình duyệt.
 */
export function clearAuthSessionCookies(reply: FastifyReply, secureCookies: boolean): void {
  const base = { secure: secureCookies, sameSite: 'strict' as const };
  reply.clearCookie('sda_access', { ...base, path: '/api/v1' });
  reply.clearCookie('sda_refresh', { ...base, path: '/api/v1/auth' });
  reply.clearCookie('sda_csrf', { ...base, path: '/api/v1' });
  reply.clearCookie('sda_csrf', { ...base, path: '/' });
}

/**
 * Algorithm / Thuật toán: Trích xuất ngữ cảnh mạng và mã tương quan truy vết từ FastifyRequest.
 */
export function extractAuthRequestContext(request: FastifyRequest): RequestContext {
  return {
    ip: request.ip,
    userAgent: request.headers['user-agent'],
    correlationId: request.correlationId ?? 'unknown',
  };
}

/**
 * Algorithm / Thuật toán: Bảo đảm ngữ cảnh định danh `AuthPrincipal` đã được nạp bởi AuthGuard.
 */
export function requireAuthPrincipal(request: FastifyRequest): AuthPrincipal {
  if (!request.auth) throw new BadRequestException('Authentication context is unavailable.');
  return request.auth;
}

/**
 * Algorithm / Thuật toán: Kiểm chứng đồng bộ CSRF, trích xuất `AuthPrincipal` và xác thực payload Zod cho thao tác ghi đã đăng nhập.
 */
export function guardAuthenticatedBody<T>(
  csrf: CsrfService,
  request: FastifyRequest,
  schema: z.ZodType<T>,
  body: unknown,
): { input: T; principal: AuthPrincipal; context: RequestContext } {
  csrf.assertRequest(request);
  const input = parseAuthBody(schema, body);
  return {
    input,
    principal: requireAuthPrincipal(request),
    context: extractAuthRequestContext(request),
  };
}

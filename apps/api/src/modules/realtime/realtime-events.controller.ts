/**
 * @module RealtimeEventsController
 * Thuật toán: Điểm cuối luồng Server-Sent Events (`GET /api/v1/events/stream`) bảo vệ bằng `AuthGuard` + `@AllowAuthenticatedSelf()`,
 * chiếm quyền phản hồi Fastify (`reply.hijack()`), vô hiệu hóa timeout socket cho luồng dài hạn và áp đặt đầy đủ tiêu đề bảo mật OWASP.
 */
import {
  Controller,
  ForbiddenException,
  Get,
  Optional,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppConfigService } from '../../config/config.service.js';
import { AllowAuthenticatedSelf } from '../rbac/require-permission.js';
import { RealtimeEventsService } from './realtime-events.service.js';

/**
 * Thuật toán: Kiểm Định Danh Sách Trắng Nguồn Chéo Cho Luồng SSE Hijacked (`isAllowedSseOrigin`)
 * Mục đích: Ngăn phản chiếu `Origin` tùy ý kèm `Access-Control-Allow-Credentials: true` khi `reply.hijack()` bỏ qua middleware CORS của Fastify (V-03, N01).
 */
export function isAllowedSseOrigin(
  origin: string | undefined,
  allowedOrigins: readonly string[] | undefined,
): boolean {
  if (!origin || !allowedOrigins || allowedOrigins.length === 0) return false;
  const normalized = origin.trim().toLowerCase();
  if (!normalized || normalized === '*') return false;
  return allowedOrigins.some((candidate) => candidate.trim().toLowerCase() === normalized);
}

@ApiTags('events')
@AllowAuthenticatedSelf()
@Controller('events')
export class RealtimeEventsController {
  constructor(
    private readonly realtime: RealtimeEventsService,
    @Optional() private readonly config?: AppConfigService,
  ) {}

  /**
   * Thuật toán: Khởi tạo luồng SSE liên tục một chiều (`text/event-stream`) gắn định danh phiên người dùng
   * và tự giải phóng ngay khi trình duyệt đóng kết nối.
   */
  @Get('stream')
  @ApiOperation({ summary: 'Subscribe to authenticated real-time Server-Sent Events stream' })
  stream(@Req() request: FastifyRequest, @Res() reply: FastifyReply): void {
    const principal = request.auth;
    if (!principal) {
      throw new UnauthorizedException('Authentication required.');
    }

    const origin = request.headers.origin;
    const originAllowed = isAllowedSseOrigin(origin, this.config?.corsOrigins);
    // CONFLICT-RESOLVED: Từ chối ngay mọi kết nối SSE có header Origin nằm ngoài danh sách trắng trước khi hijack socket (N01).
    if (
      origin &&
      this.config?.corsOrigins &&
      this.config.corsOrigins.length > 0 &&
      !originAllowed
    ) {
      throw new ForbiddenException('Request origin is not allowed.');
    }

    reply.hijack();
    const rawReq = request.raw;
    const rawRes = reply.raw;
    rawReq.setTimeout(0);
    rawReq.socket?.setTimeout(0);
    rawReq.socket?.setKeepAlive(true, 15_000);

    const headers: Record<string, string> = {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; sandbox",
      ...(this.config?.isProduction
        ? { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' }
        : {}),
      ...(request.correlationId ? { 'X-Correlation-Id': request.correlationId } : {}),
      ...(origin && originAllowed
        ? {
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Credentials': 'true',
            Vary: 'Origin',
          }
        : {}),
    };

    rawRes.writeHead(200, headers);
    rawRes.flushHeaders?.();
    rawRes.write('retry: 3000\n');
    rawRes.write(
      `event: connected\ndata: ${JSON.stringify({
        connected: true,
        timestamp: new Date().toISOString(),
      })}\n\n`,
    );

    const clientId = this.realtime.registerClient({
      userId: principal.userId.toString(),
      sessionId: principal.sessionId,
      roles: principal.roles ?? [],
      writeFrame: (frame: string) => {
        if (rawRes.destroyed || rawRes.writableEnded) return false;
        try {
          rawRes.write(frame);
          return true;
        } catch {
          return false;
        }
      },
      close: () => {
        if (!rawRes.destroyed && !rawRes.writableEnded) {
          rawRes.end();
        }
      },
    });

    const cleanup = () => {
      this.realtime.unregisterClient(clientId);
    };
    rawReq.once('close', cleanup);
    rawRes.once('close', cleanup);
    rawRes.once('error', cleanup);
  }
}

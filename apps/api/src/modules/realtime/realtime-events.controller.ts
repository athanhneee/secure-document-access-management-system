/**
 * @module RealtimeEventsController
 * Thuật toán: Điểm cuối luồng Server-Sent Events (`GET /api/v1/events/stream`) bảo vệ bằng `AuthGuard` + `@AllowAuthenticatedSelf()`,
 * chiếm quyền phản hồi Fastify (`reply.hijack()`), vô hiệu hóa timeout socket cho luồng dài hạn và áp đặt đầy đủ tiêu đề bảo mật OWASP.
 */
import { Controller, Get, Req, Res, UnauthorizedException } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AllowAuthenticatedSelf } from '../rbac/require-permission.js';
import { RealtimeEventsService } from './realtime-events.service.js';

@ApiTags('events')
@AllowAuthenticatedSelf()
@Controller('events')
export class RealtimeEventsController {
  constructor(private readonly realtime: RealtimeEventsService) {}

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

    reply.hijack();
    const rawReq = request.raw;
    const rawRes = reply.raw;
    rawReq.setTimeout(0);
    rawReq.socket?.setTimeout(0);
    rawReq.socket?.setKeepAlive(true, 15_000);

    const origin = request.headers.origin;
    const headers: Record<string, string> = {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; sandbox",
      ...(request.correlationId ? { 'X-Correlation-Id': request.correlationId } : {}),
      ...(origin
        ? {
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Credentials': 'true',
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

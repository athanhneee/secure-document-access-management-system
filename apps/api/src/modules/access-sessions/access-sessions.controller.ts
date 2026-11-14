/**
 * @module AccessSessionsController
 * Thuật toán: Điều phối API giám sát và cưỡng chế chấm dứt phiên đọc tài liệu đang hoạt động,
 * kiểm chứng lược đồ `ListAccessSessionsSchema` / `TerminateAccessSessionSchema` từ `@sda/contracts`,
 * cưỡng chế CSRF trước khi xử lý thao tác ghi và chuyển ngữ cảnh chủ thể cho tầng phân lập phòng ban.
 */
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { ListAccessSessionsSchema, TerminateAccessSessionSchema } from '@sda/contracts';
import type { session_status } from '@sda/database';
import { CsrfService } from '../auth/csrf.service.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { AccessSessionsService, SESSION_UUID_REGEX } from './access-sessions.service.js';

@ApiTags('access-sessions')
@ApiBearerAuth()
@Controller('access-sessions')
export class AccessSessionsController {
  constructor(
    private readonly accessSessionsService: AccessSessionsService,
    private readonly csrf: CsrfService,
  ) {}

  @Get()
  @RequirePermission('ACCESS_SESSION', 'TERMINATE')
  @ApiOperation({ summary: 'List active document access sessions' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Active sessions list' })
  async listSessions(
    @Req() request: FastifyRequest,
    @Query() rawQuery?: unknown,
  ): Promise<{ data: unknown[] }> {
    if (!request.auth) throw new UnauthorizedException('Authentication required.');
    const querySource = rawQuery ?? request.query ?? {};
    const parsed = ListAccessSessionsSchema.safeParse(querySource);
    if (!parsed.success) {
      throw new BadRequestException(parsed.error.flatten());
    }
    return this.accessSessionsService.listSessions(
      {
        status: parsed.data.status as session_status,
        limit: parsed.data.limit,
        page: parsed.data.page,
      },
      request.auth,
    );
  }

  @Post(':id/terminate')
  @HttpCode(HttpStatus.OK)
  @RequirePermission('ACCESS_SESSION', 'TERMINATE')
  @ApiOperation({ summary: 'Terminate active session' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Session terminated' })
  async terminateSession(
    @Param('id') id: string,
    @Req() request: FastifyRequest,
    @Body() rawBody?: unknown,
  ): Promise<{ id: string; status: string }> {
    this.csrf.assertRequest(request);
    if (!request.auth) throw new UnauthorizedException('Authentication required.');
    if (!SESSION_UUID_REGEX.test(id)) {
      throw new BadRequestException('Session identifier must be a valid UUID.');
    }
    const bodyCandidate = rawBody ?? request.body;
    let reason = 'Terminated by security officer';
    if (bodyCandidate !== undefined && bodyCandidate !== null) {
      const parsedBody = TerminateAccessSessionSchema.safeParse(bodyCandidate);
      if (!parsedBody.success) {
        throw new BadRequestException(parsedBody.error.flatten());
      }
      if (parsedBody.data.reason) {
        reason = parsedBody.data.reason;
      }
    }
    const rawUa = request.headers?.['user-agent'];
    return this.accessSessionsService.terminateSession(id, reason, request.auth, {
      ip: request.ip,
      ...(typeof rawUa === 'string' ? { userAgent: rawUa } : {}),
      ...(typeof request.correlationId === 'string'
        ? { correlationId: request.correlationId }
        : {}),
    });
  }
}

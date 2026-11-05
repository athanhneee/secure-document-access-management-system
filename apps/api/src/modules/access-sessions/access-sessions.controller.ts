import {
  BadRequestException,
  Controller,
  Get,
  Post,
  Param,
  HttpStatus,
  HttpCode,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
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
  async listSessions(@Req() request: FastifyRequest): Promise<{ data: unknown[] }> {
    if (!request.auth) throw new UnauthorizedException('Authentication required.');
    return this.accessSessionsService.listSessions();
  }

  @Post(':id/terminate')
  @HttpCode(HttpStatus.OK)
  @RequirePermission('ACCESS_SESSION', 'TERMINATE')
  @ApiOperation({ summary: 'Terminate active session' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Session terminated' })
  async terminateSession(
    @Param('id') id: string,
    @Req() request: FastifyRequest,
  ): Promise<{ id: string; status: string }> {
    this.csrf.assertRequest(request);
    if (!request.auth) throw new UnauthorizedException('Authentication required.');
    if (!SESSION_UUID_REGEX.test(id)) {
      throw new BadRequestException('Session identifier must be a valid UUID.');
    }
    const rawUa = request.headers?.['user-agent'];
    return this.accessSessionsService.terminateSession(
      id,
      'Terminated by security officer',
      request.auth,
      {
        ip: request.ip,
        ...(typeof rawUa === 'string' ? { userAgent: rawUa } : {}),
        ...(typeof request.correlationId === 'string'
          ? { correlationId: request.correlationId }
          : {}),
      },
    );
  }
}

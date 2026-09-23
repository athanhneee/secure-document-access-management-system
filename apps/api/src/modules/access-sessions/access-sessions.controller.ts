import {
  Controller,
  Get,
  Post,
  Param,
  HttpStatus,
  HttpCode,
  Req,
  ForbiddenException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { RequirePermission } from '../rbac/require-permission.js';
import { AccessSessionsService } from './access-sessions.service.js';

@ApiTags('access-sessions')
@Controller('access-sessions')
export class AccessSessionsController {
  constructor(private readonly accessSessionsService: AccessSessionsService) {}

  @Get()
  @ApiOperation({ summary: 'List active document access sessions' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Active sessions list' })
  listSessions(): { data: unknown[] } {
    return this.accessSessionsService.listSessions();
  }

  @Post(':id/terminate')
  @HttpCode(HttpStatus.OK)
  @RequirePermission('ACCESS_SESSION', 'TERMINATE')
  @ApiOperation({ summary: 'Terminate active session' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Session terminated' })
  terminateSession(
    @Param('id') id: string,
    @Req() request: FastifyRequest,
  ): { id: string; status: string } {
    if (!request.auth) throw new ForbiddenException('Authentication required.');
    return this.accessSessionsService.terminateSession(id);
  }
}

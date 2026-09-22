import { Controller, Get, Post, Param, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AccessSessionsService } from './access-sessions.service.js';

@ApiTags('access-sessions')
@ApiBearerAuth()
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
  @ApiOperation({ summary: 'Terminate active session' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Session terminated' })
  terminateSession(@Param('id') id: string): { id: string; status: string } {
    return this.accessSessionsService.terminateSession(id);
  }
}

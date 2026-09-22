import { Controller, Get, Post, Param, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AccessGrantsService } from './access-grants.service.js';

@ApiTags('access-grants')
@ApiBearerAuth()
@Controller('access-grants')
export class AccessGrantsController {
  constructor(private readonly accessGrantsService: AccessGrantsService) {}

  @Get()
  @ApiOperation({ summary: 'List active access grants' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Active grants list' })
  listGrants(): { data: unknown[] } {
    return this.accessGrantsService.listGrants();
  }

  @Post(':id/revoke')
  @ApiOperation({ summary: 'Revoke an access grant and terminate related sessions immediately' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Grant revoked' })
  revokeGrant(@Param('id') id: string): { id: string; status: string } {
    return this.accessGrantsService.revokeGrant(id);
  }
}

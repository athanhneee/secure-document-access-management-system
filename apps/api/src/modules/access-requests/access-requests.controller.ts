import { Controller, Get, Post, Param, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AccessRequestsService } from './access-requests.service.js';

@ApiTags('access-requests')
@ApiBearerAuth()
@Controller('access-requests')
export class AccessRequestsController {
  constructor(private readonly accessRequestsService: AccessRequestsService) {}

  @Get()
  @ApiOperation({ summary: 'List user access requests' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Access requests list' })
  listRequests(): { data: unknown[] } {
    return this.accessRequestsService.listRequests();
  }

  @Post(':id/cancel')
  @ApiOperation({ summary: 'Cancel pending access request' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Request cancelled' })
  cancelRequest(@Param('id') id: string): { id: string; status: string } {
    return this.accessRequestsService.cancelRequest(id);
  }
}

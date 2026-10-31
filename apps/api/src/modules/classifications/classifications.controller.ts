import { Controller, Get, HttpStatus, Req, UnauthorizedException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { ClassificationsService } from './classifications.service.js';

@ApiTags('classifications')
@ApiBearerAuth()
@Controller('classifications')
export class ClassificationsController {
  constructor(private readonly classificationsService: ClassificationsService) {}

  @Get('levels')
  @ApiOperation({ summary: 'List security classification levels' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Classification levels list' })
  async listClassificationLevels(@Req() request: FastifyRequest): Promise<{ data: unknown[] }> {
    if (!request.auth) throw new UnauthorizedException('Authentication required.');
    return this.classificationsService.listClassificationLevels();
  }

  @Get('categories')
  @ApiOperation({ summary: 'List business categories' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Business categories list' })
  async listBusinessCategories(@Req() request: FastifyRequest): Promise<{ data: unknown[] }> {
    if (!request.auth) throw new UnauthorizedException('Authentication required.');
    return this.classificationsService.listBusinessCategories();
  }
}

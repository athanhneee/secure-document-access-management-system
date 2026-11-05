import { Controller, Get, HttpStatus, Req, UnauthorizedException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { RequireAnyPermission } from '../rbac/require-permission.js';
import { ClassificationsService } from './classifications.service.js';

const CLASSIFICATION_CATALOG_PERMISSIONS = [
  { resource: 'DOCUMENT', action: 'DISCOVER' },
  { resource: 'DOCUMENT', action: 'UPLOAD' },
  { resource: 'DOCUMENT', action: 'CLASSIFY' },
  { resource: 'POLICY', action: 'MANAGE' },
  { resource: 'POLICY', action: 'SIMULATE' },
  { resource: 'AUDIT_LOG', action: 'VIEW' },
  { resource: 'SECURITY_ALERT', action: 'VIEW' },
] as const;

@ApiTags('classifications')
@ApiBearerAuth()
@Controller('classifications')
export class ClassificationsController {
  constructor(private readonly classificationsService: ClassificationsService) {}

  @Get('levels')
  @RequireAnyPermission(CLASSIFICATION_CATALOG_PERMISSIONS)
  @ApiOperation({ summary: 'List security classification levels' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Classification levels list' })
  async listClassificationLevels(@Req() request: FastifyRequest): Promise<{ data: unknown[] }> {
    if (!request.auth) throw new UnauthorizedException('Authentication required.');
    return this.classificationsService.listClassificationLevels();
  }

  @Get('categories')
  @RequireAnyPermission(CLASSIFICATION_CATALOG_PERMISSIONS)
  @ApiOperation({ summary: 'List business categories' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Business categories list' })
  async listBusinessCategories(@Req() request: FastifyRequest): Promise<{ data: unknown[] }> {
    if (!request.auth) throw new UnauthorizedException('Authentication required.');
    return this.classificationsService.listBusinessCategories();
  }
}

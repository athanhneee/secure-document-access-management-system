import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Req,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';
import {
  CreateAccessGrantSchema,
  RevokeAccessGrantSchema,
  ListAccessGrantsSchema,
  UuidParamSchema,
  type CreateAccessGrantInput,
  type RevokeAccessGrantInput,
  type ListAccessGrantsInput,
} from '@sda/contracts';
import { CsrfService } from '../auth/csrf.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { RequirePermission } from '../rbac/require-permission.js';
import {
  AccessGrantsService,
  type GrantDetail,
  type GrantListResult,
} from './access-grants.service.js';

@ApiTags('access-grants')
@Controller('access-grants')
export class AccessGrantsController {
  constructor(
    private readonly accessGrantsService: AccessGrantsService,
    private readonly csrf: CsrfService,
  ) {}

  /**
   * Create a time-bound access grant. Owner cấp cho USER hoặc ROLE.
   * D-BR14: Chỉ VIEW/DOWNLOAD, bắt buộc valid_from và valid_until.
   */
  @Post()
  @HttpCode(HttpStatus.CREATED)
  @RequirePermission('ACCESS_GRANT', 'CREATE')
  @ApiOperation({ summary: 'Create a time-bound access grant for a document' })
  @ApiResponse({ status: HttpStatus.CREATED, description: 'Grant created successfully' })
  @ApiResponse({ status: HttpStatus.BAD_REQUEST, description: 'Invalid input' })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions or clearance',
  })
  @ApiResponse({ status: HttpStatus.CONFLICT, description: 'Overlapping grant exists' })
  async createGrant(@Body() body: unknown, @Req() request: FastifyRequest): Promise<GrantDetail> {
    this.csrf.assertRequest(request);
    const parsed = CreateAccessGrantSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException(parsed.error.flatten());
    }

    return this.accessGrantsService.createGrant(
      parsed.data as CreateAccessGrantInput,
      this.principal(request),
      this.context(request),
    );
  }

  /**
   * List access grants with pagination and filters.
   */
  @Get()
  @RequirePermission('ACCESS_GRANT', 'VIEW')
  @ApiOperation({ summary: 'List access grants' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Paginated grant list' })
  async listGrants(
    @Query() query: unknown,
    @Req() request: FastifyRequest,
  ): Promise<GrantListResult> {
    const parsed = ListAccessGrantsSchema.safeParse(query);
    if (!parsed.success) {
      throw new BadRequestException(parsed.error.flatten());
    }

    return this.accessGrantsService.listGrants(
      parsed.data as ListAccessGrantsInput,
      this.principal(request),
    );
  }

  /**
   * Get a single grant by ID.
   */
  @Get(':id')
  @RequirePermission('ACCESS_GRANT', 'VIEW')
  @ApiOperation({ summary: 'Get access grant details' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Grant details' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Grant not found' })
  async getGrant(@Param() params: unknown, @Req() request: FastifyRequest): Promise<GrantDetail> {
    const parsed = UuidParamSchema.safeParse(params);
    if (!parsed.success) {
      throw new BadRequestException('Invalid grant UUID.');
    }

    return this.accessGrantsService.getGrant(parsed.data.id, this.principal(request));
  }

  /**
   * Revoke a grant immediately: change status to REVOKED, terminate active sessions,
   * invalidate cache and distribution tokens.
   *
   * D-BR15: Thu hồi có reason, giữ lịch sử, terminate session.
   * Idempotent: revoking an already-revoked grant returns the existing record.
   * Optimistic concurrency via optional expectedVersion in body.
   */
  @Post(':id/revoke')
  @HttpCode(HttpStatus.OK)
  @RequirePermission('ACCESS_GRANT', 'REVOKE')
  @ApiOperation({ summary: 'Revoke an access grant and terminate related sessions immediately' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Grant revoked and sessions terminated' })
  @ApiResponse({ status: HttpStatus.NOT_FOUND, description: 'Grant not found' })
  @ApiResponse({ status: HttpStatus.CONFLICT, description: 'Optimistic concurrency conflict' })
  async revokeGrant(
    @Param() params: unknown,
    @Body() body: unknown,
    @Req() request: FastifyRequest,
  ): Promise<GrantDetail> {
    this.csrf.assertRequest(request);
    const parsedParams = UuidParamSchema.safeParse(params);
    if (!parsedParams.success) {
      throw new BadRequestException('Invalid grant UUID.');
    }
    const parsedBody = RevokeAccessGrantSchema.safeParse(body);
    if (!parsedBody.success) {
      throw new BadRequestException(parsedBody.error.flatten());
    }

    return this.accessGrantsService.revokeGrant(
      parsedParams.data.id,
      parsedBody.data as RevokeAccessGrantInput,
      this.principal(request),
      this.context(request),
    );
  }

  private principal(request: FastifyRequest): AuthPrincipal {
    if (!request.auth) throw new ForbiddenException('Authentication required.');
    return request.auth;
  }

  private context(request: FastifyRequest): RequestContext {
    return {
      ip: request.ip,
      ...(request.headers['user-agent'] ? { userAgent: request.headers['user-agent'] } : {}),
      correlationId: request.correlationId ?? randomUUID(),
    };
  }
}

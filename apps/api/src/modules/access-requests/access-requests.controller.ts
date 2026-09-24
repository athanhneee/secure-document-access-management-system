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
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import {
  CreateAccessRequestSchema,
  DecideAccessRequestSchema,
  ListAccessRequestsSchema,
  UuidParamSchema,
  type CreateAccessRequestInput,
  type DecideAccessRequestInput,
  type ListAccessRequestsInput,
} from '@sda/contracts';
import { CsrfService } from '../auth/csrf.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { AccessRequestsService, type AccessRequestDetail } from './access-requests.service.js';

@ApiTags('access-requests')
@ApiBearerAuth()
@Controller('access-requests')
export class AccessRequestsController {
  constructor(
    private readonly accessRequestsService: AccessRequestsService,
    private readonly csrf: CsrfService,
  ) {}

  private principal(request: FastifyRequest): AuthPrincipal {
    if (!request.auth) throw new UnauthorizedException('Authentication required.');
    return request.auth;
  }

  private context(request: FastifyRequest): RequestContext {
    return {
      ip: (request.headers['x-forwarded-for'] as string) || request.ip || '127.0.0.1',
      userAgent: (request.headers['user-agent'] as string) || undefined,
      correlationId: (request.headers['x-correlation-id'] as string) || 'default-correlation-id',
    };
  }

  /**
   * UC12: Reader creates an access request for a document.
   */
  @Post()
  @HttpCode(HttpStatus.CREATED)
  @RequirePermission('ACCESS_REQUEST', 'CREATE')
  @ApiOperation({ summary: 'Submit an access request for a document' })
  @ApiResponse({ status: HttpStatus.CREATED, description: 'Access request submitted' })
  async createRequest(
    @Body() body: unknown,
    @Req() request: FastifyRequest,
  ): Promise<AccessRequestDetail> {
    this.csrf.assertRequest(request);
    const parsed = CreateAccessRequestSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException(parsed.error.flatten());
    }

    return this.accessRequestsService.createRequest(
      parsed.data as CreateAccessRequestInput,
      this.principal(request),
      this.context(request),
    );
  }

  /**
   * UC13 & UC15: List user access requests (scope: 'my' or 'incoming').
   */
  @Get()
  @ApiOperation({ summary: 'List user access requests' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Access requests list' })
  async listRequests(
    @Query() query: unknown,
    @Req() request: FastifyRequest,
  ): Promise<{ data: AccessRequestDetail[]; total: number }> {
    const parsed = ListAccessRequestsSchema.safeParse(query);
    if (!parsed.success) {
      throw new BadRequestException(parsed.error.flatten());
    }

    return this.accessRequestsService.listRequests(
      this.principal(request),
      parsed.data as ListAccessRequestsInput,
    );
  }

  /**
   * UC14: Cancel pending access request.
   */
  @Post(':id/cancel')
  @RequirePermission('ACCESS_REQUEST', 'CANCEL')
  @ApiOperation({ summary: 'Cancel pending access request' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Request cancelled' })
  async cancelRequest(
    @Param() params: unknown,
    @Req() request: FastifyRequest,
  ): Promise<{ id: string; status: string }> {
    this.csrf.assertRequest(request);
    const parsed = UuidParamSchema.safeParse(params);
    if (!parsed.success) throw new BadRequestException('Invalid request UUID.');

    return this.accessRequestsService.cancelRequest(
      parsed.data.id,
      this.principal(request),
      this.context(request),
    );
  }

  /**
   * UC16: Owner approves or rejects an access request.
   */
  @Post(':id/decide')
  @RequirePermission('ACCESS_REQUEST', 'DECIDE')
  @ApiOperation({ summary: 'Approve or reject an access request' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Decision recorded' })
  async decideRequest(
    @Param() params: unknown,
    @Body() body: unknown,
    @Req() request: FastifyRequest,
  ): Promise<{ id: string; status: string; grantId?: string }> {
    this.csrf.assertRequest(request);
    const parsedParams = UuidParamSchema.safeParse(params);
    if (!parsedParams.success) throw new BadRequestException('Invalid request UUID.');

    const parsedBody = DecideAccessRequestSchema.safeParse(body);
    if (!parsedBody.success) {
      throw new BadRequestException(parsedBody.error.flatten());
    }

    return this.accessRequestsService.decideRequest(
      parsedParams.data.id,
      parsedBody.data as DecideAccessRequestInput,
      this.principal(request),
      this.context(request),
    );
  }
}

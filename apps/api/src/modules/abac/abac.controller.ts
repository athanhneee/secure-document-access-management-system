import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { PositiveBigIntSchema } from '@sda/contracts';
import { z } from 'zod';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { CsrfService } from '../auth/csrf.service.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { UpsertAbacPolicySchema } from './abac-policy-mutation.helper.js';
import { AbacService } from './abac.service.js';

const IdSchema = PositiveBigIntSchema;
const SimulationSchema = z
  .object({
    subjectUserId: PositiveBigIntSchema,
    resourceDocumentId: z.string().uuid(),
    action: z.enum(['DISCOVER', 'VIEW', 'DOWNLOAD', 'SHARE', 'MANAGE']),
    environment: z
      .object({
        currentTime: z
          .string()
          .datetime({ offset: true })
          .transform((value) => new Date(value))
          .optional(),
        ip: z
          .string()
          .refine((val) => isIP(val) !== 0, 'Invalid IP address')
          .optional(),
        deviceTrust: z.boolean().optional(),
        mfa: z.boolean().optional(),
        riskScore: z.number().min(0).max(100).optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

@ApiTags('abac')
@ApiBearerAuth()
@Controller('abac')
export class AbacController {
  constructor(
    private readonly abacService: AbacService,
    private readonly csrf: CsrfService,
  ) {}

  @Get('policies')
  @RequirePermission('POLICY', 'MANAGE', true)
  @ApiOperation({ summary: 'List ABAC policy rules' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Policy rules list' })
  listPolicies() {
    return this.abacService.listPolicies();
  }

  @Post('policies')
  @HttpCode(HttpStatus.CREATED)
  @RequirePermission('POLICY', 'MANAGE', true)
  @ApiOperation({ summary: 'Create a new ABAC policy rule with DNF conditions' })
  createPolicy(@Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    const parsed = UpsertAbacPolicySchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.flatten());
    return this.abacService.createPolicy(
      this.principal(request),
      parsed.data,
      this.context(request),
    );
  }

  @Put('policies/:id')
  @RequirePermission('POLICY', 'MANAGE', true)
  @ApiOperation({ summary: 'Update an existing ABAC policy rule and DNF conditions' })
  updatePolicy(@Param('id') id: string, @Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    const parsedId = IdSchema.safeParse(id);
    if (!parsedId.success) throw new BadRequestException('Invalid policy rule ID.');
    const parsedBody = UpsertAbacPolicySchema.safeParse(body);
    if (!parsedBody.success) throw new BadRequestException(parsedBody.error.flatten());
    return this.abacService.updatePolicy(
      this.principal(request),
      parsedId.data,
      parsedBody.data,
      this.context(request),
    );
  }

  @Get('attributes')
  @RequirePermission('ATTRIBUTE', 'MANAGE', true)
  @ApiOperation({ summary: 'List attribute definitions' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Attribute definitions' })
  listAttributes() {
    return this.abacService.listAttributes();
  }

  @Post('simulate')
  @RequirePermission('POLICY', 'SIMULATE', true)
  async simulate(@Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    const parsed = SimulationSchema.parse(body);
    return this.abacService.simulate(
      this.principal(request),
      {
        subjectUserId: parsed.subjectUserId,
        resourceDocumentId: parsed.resourceDocumentId,
        action: parsed.action,
        time: parsed.environment?.currentTime ?? new Date(),
        ip: parsed.environment?.ip ?? request.ip,
        deviceTrust: parsed.environment?.deviceTrust ?? false,
        mfa: parsed.environment?.mfa ?? request.auth?.mfa ?? false,
        riskScore: parsed.environment?.riskScore ?? 100,
      },
      this.context(request),
    );
  }

  @Post('policies/:id/activate')
  @RequirePermission('POLICY', 'MANAGE', true)
  activate(@Param('id') id: string, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    return this.abacService.activateRule(
      this.principal(request),
      IdSchema.parse(id),
      this.context(request),
    );
  }

  private principal(request: FastifyRequest): AuthPrincipal {
    if (!request.auth) throw new UnauthorizedException('Authentication required.');
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

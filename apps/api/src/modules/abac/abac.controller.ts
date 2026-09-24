import { randomUUID } from 'node:crypto';
import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Param,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { CsrfService } from '../auth/csrf.service.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { AbacService } from './abac.service.js';

const IdSchema = z.string().regex(/^\d+$/u).transform(BigInt);
const SimulationSchema = z
  .object({
    subjectUserId: z.string().regex(/^\d+$/u).transform(BigInt),
    resourceDocumentId: z.string().uuid(),
    action: z.enum(['DISCOVER', 'VIEW', 'DOWNLOAD', 'SHARE', 'MANAGE']),
    environment: z
      .object({
        currentTime: z
          .string()
          .datetime({ offset: true })
          .transform((value) => new Date(value))
          .optional(),
        ip: z.string().ip().optional(),
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

import { Body, Controller, ForbiddenException, Get, Param, Patch, Post, Req } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { CsrfService } from '../auth/csrf.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { DepartmentsService } from './departments.service.js';

const IdSchema = z.string().regex(/^\d+$/u).transform(BigInt);
const CreateSchema = z
  .object({
    code: z
      .string()
      .trim()
      .min(2)
      .max(30)
      .regex(/^[A-Z0-9_]+$/u),
    name: z.string().trim().min(1).max(150),
    parentId: z.string().regex(/^\d+$/u).transform(BigInt).nullable().optional(),
  })
  .strict();
const UpdateSchema = z
  .object({
    expectedVersion: z.number().int().min(0),
    name: z.string().trim().min(1).max(150).optional(),
    parentId: z.string().regex(/^\d+$/u).transform(BigInt).nullable().optional(),
  })
  .strict();
const VersionSchema = z.object({ expectedVersion: z.number().int().min(0) }).strict();

@Controller('departments')
export class DepartmentsController {
  constructor(
    private readonly departments: DepartmentsService,
    private readonly csrf: CsrfService,
  ) {}

  @Get()
  @RequirePermission('DEPARTMENT', 'MANAGE')
  list(@Req() request: FastifyRequest) {
    return this.departments.list(this.principal(request));
  }

  @Get(':id')
  @RequirePermission('DEPARTMENT', 'MANAGE')
  get(@Param('id') id: string, @Req() request: FastifyRequest) {
    return this.departments.get(this.principal(request), IdSchema.parse(id));
  }

  @Post()
  @RequirePermission('DEPARTMENT', 'MANAGE')
  create(@Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    return this.departments.create(
      this.principal(request),
      CreateSchema.parse(body),
      this.context(request),
    );
  }

  @Patch(':id')
  @RequirePermission('DEPARTMENT', 'MANAGE')
  update(@Param('id') id: string, @Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    return this.departments.update(
      this.principal(request),
      IdSchema.parse(id),
      UpdateSchema.parse(body),
      this.context(request),
    );
  }

  @Post(':id/deactivate')
  @RequirePermission('DEPARTMENT', 'MANAGE')
  deactivate(@Param('id') id: string, @Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    return this.departments.deactivate(
      this.principal(request),
      IdSchema.parse(id),
      VersionSchema.parse(body).expectedVersion,
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

import { Body, Controller, ForbiddenException, Get, Param, Patch, Post, Req } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { CsrfService } from '../auth/csrf.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { UsersService } from './users.service.js';

const IdSchema = z.string().regex(/^\d+$/u).transform(BigInt);
const VersionSchema = z.object({ expectedVersion: z.number().int().min(0) }).strict();
const CreateSchema = z
  .object({
    username: z
      .string()
      .trim()
      .min(3)
      .max(80)
      .regex(/^[a-zA-Z0-9._-]+$/u),
    email: z.string().email().max(255),
    fullName: z.string().trim().min(1).max(150),
    employeeCode: z.string().trim().min(1).max(50).nullable().optional(),
    departmentId: z.string().regex(/^\d+$/u).transform(BigInt).nullable().optional(),
    password: z.string().min(15).max(128),
  })
  .strict();
const UpdateSchema = z
  .object({
    expectedVersion: z.number().int().min(0),
    email: z.string().email().max(255).optional(),
    fullName: z.string().trim().min(1).max(150).optional(),
    employeeCode: z.string().trim().min(1).max(50).nullable().optional(),
    departmentId: z.string().regex(/^\d+$/u).transform(BigInt).nullable().optional(),
  })
  .strict();

@Controller('users')
export class UsersController {
  constructor(
    private readonly users: UsersService,
    private readonly csrf: CsrfService,
  ) {}

  @Get('me')
  me(@Req() request: FastifyRequest) {
    return this.users.currentUser(this.principal(request));
  }

  @Get()
  @RequirePermission('USER', 'MANAGE')
  list(@Req() request: FastifyRequest) {
    return this.users.list(this.principal(request));
  }

  @Get(':id')
  @RequirePermission('USER', 'MANAGE')
  get(@Param('id') id: string, @Req() request: FastifyRequest) {
    return this.users.get(this.principal(request), IdSchema.parse(id));
  }

  @Post()
  @RequirePermission('USER', 'MANAGE')
  create(@Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    return this.users.create(
      this.principal(request),
      CreateSchema.parse(body),
      this.context(request),
    );
  }

  @Patch(':id')
  @RequirePermission('USER', 'MANAGE')
  update(@Param('id') id: string, @Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    return this.users.update(
      this.principal(request),
      IdSchema.parse(id),
      UpdateSchema.parse(body),
      this.context(request),
    );
  }

  @Post(':id/lock')
  @RequirePermission('USER', 'MANAGE')
  lock(@Param('id') id: string, @Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    return this.users.lock(
      this.principal(request),
      IdSchema.parse(id),
      VersionSchema.parse(body).expectedVersion,
      this.context(request),
    );
  }

  @Post(':id/unlock')
  @RequirePermission('USER', 'MANAGE')
  unlock(@Param('id') id: string, @Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    return this.users.unlock(
      this.principal(request),
      IdSchema.parse(id),
      VersionSchema.parse(body).expectedVersion,
      this.context(request),
    );
  }

  @Post(':id/disable')
  @RequirePermission('USER', 'MANAGE')
  disable(@Param('id') id: string, @Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    return this.users.disable(
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

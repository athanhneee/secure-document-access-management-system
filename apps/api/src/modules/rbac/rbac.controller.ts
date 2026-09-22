import {
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Put,
  Req,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { CsrfService } from '../auth/csrf.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { RequirePermission } from './require-permission.js';
import { RbacService } from './rbac.service.js';

const IdSchema = z.string().regex(/^\d+$/u).transform(BigInt);
const RoleCreateSchema = z
  .object({
    code: z
      .string()
      .trim()
      .min(2)
      .max(50)
      .regex(/^[A-Z0-9_]+$/u),
    name: z.string().trim().min(1).max(120),
    description: z.string().trim().max(2000).nullable().optional(),
  })
  .strict();
const RoleUpdateSchema = z
  .object({
    expectedVersion: z.number().int().min(0),
    code: z
      .string()
      .trim()
      .min(2)
      .max(50)
      .regex(/^[A-Z0-9_]+$/u)
      .optional(),
    name: z.string().trim().min(1).max(120).optional(),
    description: z.string().trim().max(2000).nullable().optional(),
  })
  .strict();
const VersionSchema = z.object({ expectedVersion: z.number().int().min(0) }).strict();
const PermissionMappingSchema = z
  .object({ permissionIds: z.array(z.string().regex(/^\d+$/u).transform(BigInt)).max(100) })
  .strict();
const AssignmentSchema = z
  .object({
    roleId: z.string().regex(/^\d+$/u).transform(BigInt),
    scopeDepartmentId: z.string().regex(/^\d+$/u).transform(BigInt).nullable(),
    validFrom: z.coerce.date(),
    validTo: z.coerce.date().nullable(),
  })
  .strict()
  .refine((value) => value.validTo === null || value.validTo > value.validFrom, {
    message: 'validTo must be later than validFrom',
  });

@Controller('rbac')
export class RbacController {
  constructor(
    private readonly rbac: RbacService,
    private readonly csrf: CsrfService,
  ) {}

  @Get('roles')
  @RequirePermission('ROLE', 'MANAGE', true)
  listRoles() {
    return this.rbac.listRoles();
  }

  @Get('roles/:id')
  @RequirePermission('ROLE', 'MANAGE', true)
  getRole(@Param('id') id: string) {
    return this.rbac.getRole(IdSchema.parse(id));
  }

  @Post('roles')
  @RequirePermission('ROLE', 'MANAGE', true)
  createRole(@Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    return this.rbac.createRole(
      this.principal(request),
      RoleCreateSchema.parse(body),
      this.context(request),
    );
  }

  @Patch('roles/:id')
  @RequirePermission('ROLE', 'MANAGE', true)
  updateRole(@Param('id') id: string, @Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    return this.rbac.updateRole(
      this.principal(request),
      IdSchema.parse(id),
      RoleUpdateSchema.parse(body),
      this.context(request),
    );
  }

  @Post('roles/:id/disable')
  @RequirePermission('ROLE', 'MANAGE', true)
  disableRole(@Param('id') id: string, @Body() body: unknown, @Req() request: FastifyRequest) {
    this.csrf.assertRequest(request);
    return this.rbac.disableRole(
      this.principal(request),
      IdSchema.parse(id),
      VersionSchema.parse(body).expectedVersion,
      this.context(request),
    );
  }

  @Delete('roles/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @RequirePermission('ROLE', 'MANAGE', true)
  async deleteRole(@Param('id') id: string, @Req() request: FastifyRequest): Promise<void> {
    this.csrf.assertRequest(request);
    await this.rbac.deleteRole(this.principal(request), IdSchema.parse(id), this.context(request));
  }

  @Put('roles/:id/permissions')
  @RequirePermission('ROLE', 'MANAGE', true)
  replacePermissions(
    @Param('id') id: string,
    @Body() body: unknown,
    @Req() request: FastifyRequest,
  ) {
    this.csrf.assertRequest(request);
    return this.rbac.replacePermissions(
      this.principal(request),
      IdSchema.parse(id),
      PermissionMappingSchema.parse(body).permissionIds,
      this.context(request),
    );
  }

  @Get('permissions')
  @RequirePermission('ROLE', 'MANAGE', true)
  listPermissions() {
    return this.rbac.listPermissions();
  }

  @Post('users/:userId/roles')
  @RequirePermission('USER', 'MANAGE')
  assignUserRole(
    @Param('userId') userId: string,
    @Body() body: unknown,
    @Req() request: FastifyRequest,
  ) {
    this.csrf.assertRequest(request);
    return this.rbac.assignUserRole(
      this.principal(request),
      IdSchema.parse(userId),
      AssignmentSchema.parse(body),
      this.context(request),
    );
  }

  @Delete('users/:userId/roles/:assignmentId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @RequirePermission('USER', 'MANAGE')
  async revokeUserRole(
    @Param('userId') userId: string,
    @Param('assignmentId') assignmentId: string,
    @Req() request: FastifyRequest,
  ): Promise<void> {
    this.csrf.assertRequest(request);
    await this.rbac.revokeUserRole(
      this.principal(request),
      IdSchema.parse(userId),
      IdSchema.parse(assignmentId),
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

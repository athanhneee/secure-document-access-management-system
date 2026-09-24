import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import type { FastifyRequest, FastifyReply } from 'fastify';
import {
  QueryAuditLogsSchema,
  ExportAuditLogsSchema,
  CreateAuditAnchorSchema,
  VerifyAuditChainSchema,
  AppErrorCode,
} from '@sda/contracts';
import { CsrfService } from '../auth/csrf.service.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { AuditService, type PaginatedAuditLogs } from './audit.service.js';

@ApiTags('audit-logs')
@Controller('audit-logs')
export class AuditController {
  constructor(
    private readonly auditService: AuditService,
    private readonly csrf: CsrfService,
  ) {}

  /**
   * Query audit logs with allowlist filtering and stable pagination.
   * Scoped to owned documents for DOCUMENT_OWNER; global for SECURITY_OFFICER and AUDITOR.
   */
  @Get()
  @RequirePermission('AUDIT_LOG', 'VIEW')
  @ApiOperation({ summary: 'Query audit trail logs with allowlist filtering' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Audit logs retrieved' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Insufficient permissions' })
  async queryLogs(
    @Query() rawQuery: unknown,
    @Req() request: FastifyRequest,
  ): Promise<PaginatedAuditLogs> {
    if (!request.auth) {
      throw new UnauthorizedException('Authenticated principal is required');
    }

    const parsed = QueryAuditLogsSchema.safeParse(rawQuery);
    if (!parsed.success) {
      throw new BadRequestException({
        code: AppErrorCode.VALIDATION_FAILED,
        message: 'Invalid audit log query parameters',
        details: parsed.error.format(),
      });
    }

    return await this.auditService.queryAuditLogs(request.auth, parsed.data);
  }

  /**
   * Export audit logs in CSV or JSON format.
   * Strictly enforces no data leakage and Cache-Control: no-store.
   */
  @Post('export')
  @HttpCode(HttpStatus.OK)
  @RequirePermission('AUDIT_LOG', 'VIEW')
  @ApiOperation({ summary: 'Export audit logs in CSV or JSON format' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Audit export payload' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Insufficient permissions' })
  async exportLogs(
    @Body() body: unknown,
    @Req() request: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    this.csrf.assertRequest(request);
    if (!request.auth) {
      throw new UnauthorizedException('Authenticated principal is required');
    }

    const parsed = ExportAuditLogsSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        code: AppErrorCode.VALIDATION_FAILED,
        message: 'Invalid audit export parameters',
        details: parsed.error.format(),
      });
    }

    const result = await this.auditService.exportAuditLogs(request.auth, parsed.data);

    reply.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    reply.header('Pragma', 'no-cache');

    if (result.format === 'CSV') {
      reply.header('Content-Type', 'text/csv; charset=utf-8');
      reply.header('Content-Disposition', 'attachment; filename="audit_export.csv"');
      await reply.send(result.data);
      return;
    }

    reply.header('Content-Type', 'application/json; charset=utf-8');
    await reply.send(result.data);
  }

  /**
   * Verify partition hash chain integrity, detects broken links, sequence gaps, and tampering.
   */
  @Get('verify')
  @RequirePermission('AUDIT_LOG', 'VIEW')
  @ApiOperation({ summary: 'Verify audit log cryptographic hash chain integrity' })
  @ApiResponse({ status: HttpStatus.OK, description: 'Verification report' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Insufficient permissions' })
  async verifyChain(@Query() rawQuery: unknown, @Req() request: FastifyRequest): Promise<unknown> {
    if (!request.auth) {
      throw new UnauthorizedException('Authenticated principal is required');
    }

    const parsed = VerifyAuditChainSchema.safeParse(rawQuery);
    if (!parsed.success) {
      throw new BadRequestException({
        code: AppErrorCode.VALIDATION_FAILED,
        message: 'Invalid verification parameters',
        details: parsed.error.format(),
      });
    }

    return await this.auditService.verifyChain(request.auth, parsed.data);
  }

  /**
   * Create a signed checkpoint anchor for an audit partition.
   */
  @Post('anchors')
  @HttpCode(HttpStatus.CREATED)
  @RequirePermission('AUDIT_LOG', 'VIEW')
  @ApiOperation({ summary: 'Create a signed checkpoint anchor for an audit partition' })
  @ApiResponse({ status: HttpStatus.CREATED, description: 'Anchor created successfully' })
  @ApiResponse({ status: HttpStatus.FORBIDDEN, description: 'Insufficient permissions' })
  async createAnchor(@Body() body: unknown, @Req() request: FastifyRequest): Promise<unknown> {
    this.csrf.assertRequest(request);
    if (!request.auth) {
      throw new UnauthorizedException('Authenticated principal is required');
    }

    const parsed = CreateAuditAnchorSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        code: AppErrorCode.VALIDATION_FAILED,
        message: 'Invalid anchor creation parameters',
        details: parsed.error.format(),
      });
    }

    return await this.auditService.createAnchor(request.auth, parsed.data.chainPartition);
  }
}

import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Req,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';
import {
  CreateDocumentDraftSchema,
  UpdateDocumentMetadataSchema,
  ReclassifyDocumentSchema,
  SetCurrentVersionSchema,
  TransferDocumentOwnerSchema,
  ArchiveDocumentSchema,
  UuidParamSchema,
  type CreateDocumentDraftInput,
  type UpdateDocumentMetadataInput,
  type ReclassifyDocumentInput,
  type SetCurrentVersionInput,
  type TransferDocumentOwnerInput,
  type ArchiveDocumentInput,
} from '@sda/contracts';
import { CsrfService } from '../auth/csrf.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { DocumentsService, type DocumentDetail } from './documents.service.js';

@Controller('documents')
export class DocumentsController {
  constructor(
    private readonly documentsService: DocumentsService,
    private readonly csrf: CsrfService,
  ) {}

  @Get()
  async listDocuments(): Promise<{ data: unknown[] }> {
    return this.documentsService.listDocuments();
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @RequirePermission('DOCUMENT', 'UPLOAD')
  async createDocumentDraft(
    @Body() body: unknown,
    @Req() request: FastifyRequest,
  ): Promise<DocumentDetail> {
    this.csrf.assertRequest(request);
    const parsed = CreateDocumentDraftSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException(parsed.error.flatten());
    }

    return this.documentsService.createDocumentDraft(
      parsed.data as CreateDocumentDraftInput,
      this.principal(request),
      this.context(request),
    );
  }

  @Get(':id')
  async getDocumentById(@Param() params: unknown): Promise<DocumentDetail> {
    const parsed = UuidParamSchema.safeParse(params);
    if (!parsed.success) {
      throw new BadRequestException('Invalid document UUID.');
    }
    return this.documentsService.getDocumentById(parsed.data.id);
  }

  @Patch(':id')
  async updateMetadata(
    @Param() params: unknown,
    @Body() body: unknown,
    @Req() request: FastifyRequest,
  ): Promise<DocumentDetail> {
    this.csrf.assertRequest(request);
    const parsedParams = UuidParamSchema.safeParse(params);
    if (!parsedParams.success) {
      throw new BadRequestException('Invalid document UUID.');
    }
    const parsedBody = UpdateDocumentMetadataSchema.safeParse(body);
    if (!parsedBody.success) {
      throw new BadRequestException(parsedBody.error.flatten());
    }

    return this.documentsService.updateMetadata(
      parsedParams.data.id,
      parsedBody.data as UpdateDocumentMetadataInput,
      this.principal(request),
      this.context(request),
    );
  }

  @Post(':id/activate')
  @HttpCode(HttpStatus.OK)
  async activateDocument(
    @Param() params: unknown,
    @Req() request: FastifyRequest,
  ): Promise<DocumentDetail> {
    this.csrf.assertRequest(request);
    const parsed = UuidParamSchema.safeParse(params);
    if (!parsed.success) {
      throw new BadRequestException('Invalid document UUID.');
    }
    return this.documentsService.activateDocument(
      parsed.data.id,
      this.principal(request),
      this.context(request),
    );
  }

  @Post(':id/classify')
  @HttpCode(HttpStatus.OK)
  async reclassifyDocument(
    @Param() params: unknown,
    @Body() body: unknown,
    @Req() request: FastifyRequest,
  ): Promise<DocumentDetail> {
    this.csrf.assertRequest(request);
    const parsedParams = UuidParamSchema.safeParse(params);
    if (!parsedParams.success) {
      throw new BadRequestException('Invalid document UUID.');
    }
    const parsedBody = ReclassifyDocumentSchema.safeParse(body);
    if (!parsedBody.success) {
      throw new BadRequestException(parsedBody.error.flatten());
    }

    return this.documentsService.reclassifyDocument(
      parsedParams.data.id,
      parsedBody.data as ReclassifyDocumentInput,
      this.principal(request),
      this.context(request),
    );
  }

  @Post(':id/current-version')
  @HttpCode(HttpStatus.OK)
  async setCurrentVersion(
    @Param() params: unknown,
    @Body() body: unknown,
    @Req() request: FastifyRequest,
  ): Promise<DocumentDetail> {
    this.csrf.assertRequest(request);
    const parsedParams = UuidParamSchema.safeParse(params);
    if (!parsedParams.success) {
      throw new BadRequestException('Invalid document UUID.');
    }
    const parsedBody = SetCurrentVersionSchema.safeParse(body);
    if (!parsedBody.success) {
      throw new BadRequestException(parsedBody.error.flatten());
    }

    return this.documentsService.setCurrentVersion(
      parsedParams.data.id,
      parsedBody.data as SetCurrentVersionInput,
      this.principal(request),
      this.context(request),
    );
  }

  @Post(':id/archive')
  @HttpCode(HttpStatus.OK)
  async archiveDocument(
    @Param() params: unknown,
    @Body() body: unknown,
    @Req() request: FastifyRequest,
  ): Promise<DocumentDetail> {
    this.csrf.assertRequest(request);
    const parsedParams = UuidParamSchema.safeParse(params);
    if (!parsedParams.success) {
      throw new BadRequestException('Invalid document UUID.');
    }
    const parsedBody = ArchiveDocumentSchema.safeParse(body ?? {});
    if (!parsedBody.success) {
      throw new BadRequestException(parsedBody.error.flatten());
    }

    return this.documentsService.archiveDocument(
      parsedParams.data.id,
      parsedBody.data as ArchiveDocumentInput,
      this.principal(request),
      this.context(request),
    );
  }

  @Post(':id/transfer-owner')
  @HttpCode(HttpStatus.OK)
  async transferOwner(
    @Param() params: unknown,
    @Body() body: unknown,
    @Req() request: FastifyRequest,
  ): Promise<DocumentDetail> {
    this.csrf.assertRequest(request);
    const parsedParams = UuidParamSchema.safeParse(params);
    if (!parsedParams.success) {
      throw new BadRequestException('Invalid document UUID.');
    }
    const parsedBody = TransferDocumentOwnerSchema.safeParse(body);
    if (!parsedBody.success) {
      throw new BadRequestException(parsedBody.error.flatten());
    }

    return this.documentsService.transferOwner(
      parsedParams.data.id,
      parsedBody.data as TransferDocumentOwnerInput,
      this.principal(request),
      this.context(request),
    );
  }

  @Get(':id/classification-history')
  async getClassificationHistory(@Param() params: unknown): Promise<unknown[]> {
    const parsed = UuidParamSchema.safeParse(params);
    if (!parsed.success) {
      throw new BadRequestException('Invalid document UUID.');
    }
    return this.documentsService.getClassificationHistory(parsed.data.id);
  }

  @Get(':id/versions')
  async getDocumentVersions(@Param() params: unknown): Promise<unknown[]> {
    const parsed = UuidParamSchema.safeParse(params);
    if (!parsed.success) {
      throw new BadRequestException('Invalid document UUID.');
    }
    return this.documentsService.getDocumentVersions(parsed.data.id);
  }

  @Post('retention/check')
  @HttpCode(HttpStatus.OK)
  @RequirePermission('DOCUMENT', 'CLASSIFY')
  async checkRetention(): Promise<unknown> {
    return this.documentsService.checkRetentionWarnings();
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

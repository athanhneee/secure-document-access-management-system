import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { randomUUID } from 'node:crypto';
import { PublicEndpoint } from '../../public-endpoint.js';
import {
  CreateDocumentDraftSchema,
  UpdateDocumentMetadataSchema,
  ReclassifyDocumentSchema,
  SetCurrentVersionSchema,
  TransferDocumentOwnerSchema,
  ArchiveDocumentSchema,
  SearchDocumentsSchema,
  MyGrantedDocumentsSchema,
  CreateAccessSessionSchema,
  DownloadTicketParamSchema,
  UuidParamSchema,
  type CreateDocumentDraftInput,
  type UpdateDocumentMetadataInput,
  type ReclassifyDocumentInput,
  type SetCurrentVersionInput,
  type TransferDocumentOwnerInput,
  type ArchiveDocumentInput,
  type SearchDocumentsInput,
  type MyGrantedDocumentsInput,
  type CreateAccessSessionInput,
} from '@sda/contracts';
import { CsrfService } from '../auth/csrf.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { DocumentsService, type DocumentDetail } from './documents.service.js';
import {
  DocumentSearchService,
  type SearchResult,
  type GrantedDocumentsResult,
} from './document-search.service.js';
import { DocumentDeliveryService } from './document-delivery.service.js';
import type { PepEvaluationResult } from './document-pep.service.js';

@Controller('documents')
export class DocumentsController {
  constructor(
    private readonly documentsService: DocumentsService,
    private readonly searchService: DocumentSearchService,
    private readonly deliveryService: DocumentDeliveryService,
    private readonly csrf: CsrfService,
  ) {}

  @Get()
  @RequirePermission('DOCUMENT', 'DISCOVER')
  async searchDocuments(
    @Query() query: unknown,
    @Req() request: FastifyRequest,
  ): Promise<SearchResult> {
    const parsed = SearchDocumentsSchema.safeParse(query);
    if (!parsed.success) {
      throw new BadRequestException(parsed.error.flatten());
    }
    return this.searchService.searchDocuments(
      parsed.data as SearchDocumentsInput,
      this.principal(request),
      this.context(request),
    );
  }

  @Get('my-grants')
  async getMyGrantedDocuments(
    @Query() query: unknown,
    @Req() request: FastifyRequest,
  ): Promise<GrantedDocumentsResult> {
    const parsed = MyGrantedDocumentsSchema.safeParse(query);
    if (!parsed.success) {
      throw new BadRequestException(parsed.error.flatten());
    }
    return this.searchService.getMyGrantedDocuments(
      parsed.data as MyGrantedDocumentsInput,
      this.principal(request),
    );
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
  async getDocumentDetail(
    @Param() params: unknown,
    @Req() _request: FastifyRequest,
  ): Promise<DocumentDetail> {
    const parsed = UuidParamSchema.safeParse(params);
    if (!parsed.success) {
      throw new BadRequestException('Invalid document UUID.');
    }
    return this.documentsService.getDocumentById(parsed.data.id);
  }

  @Patch(':id')
  async updateDocumentMetadata(
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

  @Post(':id/classify')
  @HttpCode(HttpStatus.OK)
  @RequirePermission('DOCUMENT', 'CLASSIFY')
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

  @Post(':id/archive')
  @HttpCode(HttpStatus.OK)
  @RequirePermission('DOCUMENT', 'ARCHIVE')
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
    const parsedBody = ArchiveDocumentSchema.safeParse(body);
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
  async checkRetention(@Req() request: FastifyRequest): Promise<unknown> {
    this.csrf.assertRequest(request);
    return this.documentsService.checkRetentionWarnings();
  }

  // ── Controlled Distribution & Delivery Endpoints (Prompt 13) ───────────────

  @Post(':id/sessions')
  @HttpCode(HttpStatus.CREATED)
  async createAccessSession(
    @Param() params: unknown,
    @Body() body: unknown,
    @Req() request: FastifyRequest,
  ): Promise<PepEvaluationResult> {
    this.csrf.assertRequest(request);
    const parsedParams = UuidParamSchema.safeParse(params);
    if (!parsedParams.success) throw new BadRequestException('Invalid document UUID.');
    const parsedBody = CreateAccessSessionSchema.safeParse(body);
    if (!parsedBody.success) throw new BadRequestException(parsedBody.error.flatten());

    return this.deliveryService.createSession(
      parsedParams.data.id,
      parsedBody.data as CreateAccessSessionInput,
      this.principal(request),
      this.context(request),
    );
  }

  @Get(':id/preview')
  async previewDocument(
    @Param() params: unknown,
    @Query('sessionId') sessionId: string | undefined,
    @Req() request: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const parsedParams = UuidParamSchema.safeParse(params);
    if (!parsedParams.success) throw new BadRequestException('Invalid document UUID.');
    const sid = sessionId || (request.headers['x-access-session-id'] as string);
    if (!sid) {
      throw new BadRequestException(
        'sessionId query parameter or X-Access-Session-Id header is required.',
      );
    }

    const result = await this.deliveryService.getPreviewPdf(
      parsedParams.data.id,
      sid,
      undefined,
      this.principal(request),
      this.context(request),
    );

    reply
      .type(result.mimeType)
      .header('Cache-Control', 'no-store, no-cache, must-revalidate, private')
      .header('Pragma', 'no-cache')
      .header('Content-Disposition', `inline; filename="${result.filename}"`)
      .send(result.buffer);
  }

  @Get(':id/preview/page/:pageNumber')
  async previewDocumentPage(
    @Param() params: unknown,
    @Query('sessionId') sessionId: string | undefined,
    @Req() request: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const rawParams = params as Record<string, string>;
    const parsedId = UuidParamSchema.safeParse({ id: rawParams['id'] });
    if (!parsedId.success) throw new BadRequestException('Invalid document UUID.');
    const pageNum = Number(rawParams['pageNumber']);
    if (isNaN(pageNum) || pageNum < 1) throw new BadRequestException('Invalid page number.');
    const sid = sessionId || (request.headers['x-access-session-id'] as string);
    if (!sid) {
      throw new BadRequestException(
        'sessionId query parameter or X-Access-Session-Id header is required.',
      );
    }

    const result = await this.deliveryService.getPreviewPdf(
      parsedId.data.id,
      sid,
      pageNum,
      this.principal(request),
      this.context(request),
    );

    reply
      .type(result.mimeType)
      .header('Cache-Control', 'no-store, no-cache, must-revalidate, private')
      .header('Pragma', 'no-cache')
      .header('Content-Disposition', `inline; filename="${result.filename}"`)
      .send(result.buffer);
  }

  @Get(':id/download')
  async downloadDocument(
    @Param() params: unknown,
    @Query('sessionId') sessionId: string | undefined,
    @Req() request: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const parsedParams = UuidParamSchema.safeParse(params);
    if (!parsedParams.success) throw new BadRequestException('Invalid document UUID.');
    const sid = sessionId || (request.headers['x-access-session-id'] as string);
    if (!sid) {
      throw new BadRequestException(
        'sessionId query parameter or X-Access-Session-Id header is required.',
      );
    }

    const result = await this.deliveryService.downloadDocument(
      parsedParams.data.id,
      sid,
      this.principal(request),
      this.context(request),
    );

    reply
      .type(result.mimeType)
      .header('Cache-Control', 'no-store, no-cache, must-revalidate, private')
      .header('Pragma', 'no-cache')
      .header('Content-Disposition', `attachment; filename="${result.filename}"`)
      .send(result.buffer);
  }

  @Post(':id/download-ticket')
  @HttpCode(HttpStatus.CREATED)
  async createDownloadTicket(
    @Param() params: unknown,
    @Body('sessionId') sessionId: string | undefined,
    @Req() request: FastifyRequest,
  ): Promise<{ ticket: string; expiresAt: string; ttlSeconds: number }> {
    this.csrf.assertRequest(request);
    const parsedParams = UuidParamSchema.safeParse(params);
    if (!parsedParams.success) throw new BadRequestException('Invalid document UUID.');
    if (!sessionId) throw new BadRequestException('sessionId is required.');

    return this.deliveryService.createDownloadTicket(
      parsedParams.data.id,
      sessionId,
      this.principal(request),
      this.context(request),
    );
  }

  @PublicEndpoint()
  @Get('download-with-ticket/:ticket')
  async downloadWithTicket(
    @Param() params: unknown,
    @Req() request: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const parsed = DownloadTicketParamSchema.safeParse(params);
    if (!parsed.success) throw new BadRequestException('Invalid ticket format.');

    const result = await this.deliveryService.redeemDownloadTicket(
      parsed.data.ticket,
      this.context(request),
    );

    reply
      .type(result.mimeType)
      .header('Cache-Control', 'no-store, no-cache, must-revalidate, private')
      .header('Pragma', 'no-cache')
      .header('Content-Disposition', `attachment; filename="${result.filename}"`)
      .send(result.buffer);
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

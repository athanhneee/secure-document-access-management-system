/**
 * Module: Documents Catalog, Search & Lifecycle HTTP Controller
 * Algorithm: Enforces Zod input schemas, CSRF token verification on state-mutating routes,
 *   and RBAC permission metadata across document discovery, metadata, version, and classification APIs.
 */
import {
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
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import {
  ArchiveDocumentSchema,
  CreateDocumentDraftSchema,
  MyGrantedDocumentsSchema,
  ReclassifyDocumentSchema,
  SearchDocumentsSchema,
  SetCurrentVersionSchema,
  TransferDocumentOwnerSchema,
  UpdateDocumentMetadataSchema,
} from '@sda/contracts';
import { CsrfService } from '../auth/csrf.service.js';
import { RequireAnyPermission, RequirePermission } from '../rbac/require-permission.js';
import { DocumentsService, type DocumentDetail } from './documents.service.js';
import {
  DocumentSearchService,
  type GrantedDocumentsResult,
  type SearchResult,
} from './document-search.service.js';
import {
  extractDocumentPrincipal as principal,
  extractDocumentRequestContext as reqCtx,
  parseBodyOrQuery as parseInput,
  parseDocumentUuid as parseId,
} from './documents-controller.helpers.js';

@Controller('documents')
export class DocumentsController {
  constructor(
    private readonly documentsService: DocumentsService,
    private readonly searchService: DocumentSearchService,
    private readonly csrf: CsrfService,
  ) {}

  @Get()
  @RequirePermission('DOCUMENT', 'DISCOVER')
  async searchDocuments(
    @Query() query: unknown,
    @Req() req: FastifyRequest,
  ): Promise<SearchResult> {
    return this.searchService.searchDocuments(
      parseInput(SearchDocumentsSchema, query),
      principal(req),
      reqCtx(req),
    );
  }

  @Get('my-grants')
  @RequireAnyPermission([
    { resource: 'DOCUMENT', action: 'VIEW' },
    { resource: 'DOCUMENT', action: 'DISCOVER' },
  ])
  async getMyGrantedDocuments(
    @Query() query: unknown,
    @Req() req: FastifyRequest,
  ): Promise<GrantedDocumentsResult> {
    return this.searchService.getMyGrantedDocuments(
      parseInput(MyGrantedDocumentsSchema, query),
      principal(req),
    );
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @RequirePermission('DOCUMENT', 'UPLOAD')
  async createDocumentDraft(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
  ): Promise<DocumentDetail> {
    this.csrf.assertRequest(req);
    return this.documentsService.createDocumentDraft(
      parseInput(CreateDocumentDraftSchema, body),
      principal(req),
      reqCtx(req),
    );
  }

  @Get(':id')
  @RequireAnyPermission([
    { resource: 'DOCUMENT', action: 'VIEW' },
    { resource: 'DOCUMENT', action: 'DISCOVER' },
    { resource: 'DOCUMENT', action: 'CLASSIFY' },
    { resource: 'DOCUMENT', action: 'MANAGE' },
  ])
  async getDocumentDetail(
    @Param() params: unknown,
    @Req() req: FastifyRequest,
  ): Promise<DocumentDetail> {
    return this.documentsService.getDocumentById(parseId(params), principal(req));
  }

  @Patch(':id')
  @RequirePermission('DOCUMENT', 'CLASSIFY')
  async updateDocumentMetadata(
    @Param() params: unknown,
    @Body() body: unknown,
    @Req() req: FastifyRequest,
  ): Promise<DocumentDetail> {
    this.csrf.assertRequest(req);
    return this.documentsService.updateMetadata(
      parseId(params),
      parseInput(UpdateDocumentMetadataSchema, body),
      principal(req),
      reqCtx(req),
    );
  }

  @Post(':id/activate')
  @HttpCode(HttpStatus.OK)
  @RequirePermission('DOCUMENT', 'CLASSIFY')
  async activateDocument(
    @Param() params: unknown,
    @Req() req: FastifyRequest,
  ): Promise<DocumentDetail> {
    this.csrf.assertRequest(req);
    return this.documentsService.activateDocument(parseId(params), principal(req), reqCtx(req));
  }

  @Post(':id/current-version')
  @HttpCode(HttpStatus.OK)
  @RequirePermission('DOCUMENT_VERSION', 'CREATE')
  async setCurrentVersion(
    @Param() params: unknown,
    @Body() body: unknown,
    @Req() req: FastifyRequest,
  ): Promise<DocumentDetail> {
    this.csrf.assertRequest(req);
    return this.documentsService.setCurrentVersion(
      parseId(params),
      parseInput(SetCurrentVersionSchema, body),
      principal(req),
      reqCtx(req),
    );
  }

  @Post(':id/classify')
  @HttpCode(HttpStatus.OK)
  @RequirePermission('DOCUMENT', 'CLASSIFY')
  async reclassifyDocument(
    @Param() params: unknown,
    @Body() body: unknown,
    @Req() req: FastifyRequest,
  ): Promise<DocumentDetail> {
    this.csrf.assertRequest(req);
    return this.documentsService.reclassifyDocument(
      parseId(params),
      parseInput(ReclassifyDocumentSchema, body),
      principal(req),
      reqCtx(req),
    );
  }

  @Post(':id/archive')
  @HttpCode(HttpStatus.OK)
  @RequirePermission('DOCUMENT', 'ARCHIVE')
  async archiveDocument(
    @Param() params: unknown,
    @Body() body: unknown,
    @Req() req: FastifyRequest,
  ): Promise<DocumentDetail> {
    this.csrf.assertRequest(req);
    return this.documentsService.archiveDocument(
      parseId(params),
      parseInput(ArchiveDocumentSchema, body),
      principal(req),
      reqCtx(req),
    );
  }

  @Post(':id/transfer-owner')
  @HttpCode(HttpStatus.OK)
  @RequirePermission('DOCUMENT', 'MANAGE')
  async transferOwner(
    @Param() params: unknown,
    @Body() body: unknown,
    @Req() req: FastifyRequest,
  ): Promise<DocumentDetail> {
    this.csrf.assertRequest(req);
    return this.documentsService.transferOwner(
      parseId(params),
      parseInput(TransferDocumentOwnerSchema, body),
      principal(req),
      reqCtx(req),
    );
  }

  @Get(':id/classification-history')
  @RequireAnyPermission([
    { resource: 'DOCUMENT', action: 'VIEW' },
    { resource: 'DOCUMENT', action: 'DISCOVER' },
    { resource: 'DOCUMENT', action: 'CLASSIFY' },
    { resource: 'DOCUMENT', action: 'MANAGE' },
  ])
  async getClassificationHistory(
    @Param() params: unknown,
    @Req() req: FastifyRequest,
  ): Promise<unknown[]> {
    return this.documentsService.getClassificationHistory(parseId(params), principal(req));
  }

  @Get(':id/versions')
  @RequireAnyPermission([
    { resource: 'DOCUMENT', action: 'VIEW' },
    { resource: 'DOCUMENT', action: 'DISCOVER' },
    { resource: 'DOCUMENT', action: 'CLASSIFY' },
    { resource: 'DOCUMENT', action: 'MANAGE' },
  ])
  async getDocumentVersions(
    @Param() params: unknown,
    @Req() req: FastifyRequest,
  ): Promise<unknown[]> {
    return this.documentsService.getDocumentVersions(parseId(params), principal(req));
  }

  @Post('retention/check')
  @HttpCode(HttpStatus.OK)
  @RequirePermission('DOCUMENT', 'CLASSIFY')
  async checkRetention(@Req() req: FastifyRequest): Promise<unknown> {
    this.csrf.assertRequest(req);
    // CONFLICT-RESOLVED: Cưỡng chế xác thực `principal(req)` bắt buộc thay vì truyền `req.auth` tùy chọn dẫn tới bỏ qua phạm vi phòng ban (HIGH-08).
    return this.documentsService.checkRetentionWarnings(30, principal(req), reqCtx(req));
  }
}

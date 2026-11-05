/**
 * Module: Controlled Document Session, Watermarked Preview & Ticketed Download HTTP Controller
 * Algorithm: Enforces RBAC permission metadata, CSRF verification on ticket/session minting,
 *   and `Cache-Control: no-store` streaming binary replies via `DocumentDeliveryService`.
 */
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
  Res,
} from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { CreateAccessSessionSchema } from '@sda/contracts';
import { PublicEndpoint } from '../../public-endpoint.js';
import { CsrfService } from '../auth/csrf.service.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { DocumentDeliveryService } from './document-delivery.service.js';
import type { PepEvaluationResult } from './document-pep.service.js';
import {
  extractDocumentPrincipal as principal,
  extractDocumentRequestContext as reqCtx,
  parseBodyOrQuery as parseInput,
  parseDocumentUuid as parseId,
  parseDownloadTicketParam,
  parsePreviewPageParams,
  resolveAccessSessionId,
  sendAttachmentDownloadReply,
  sendInlinePreviewReply,
} from './documents-controller.helpers.js';

@Controller('documents')
export class DocumentDeliveryController {
  constructor(
    private readonly deliveryService: DocumentDeliveryService,
    private readonly csrf: CsrfService,
  ) {}

  @Post(':id/sessions')
  @HttpCode(HttpStatus.CREATED)
  @RequirePermission('DOCUMENT', 'VIEW')
  async createAccessSession(
    @Param() params: unknown,
    @Body() body: unknown,
    @Req() req: FastifyRequest,
  ): Promise<PepEvaluationResult> {
    this.csrf.assertRequest(req);
    return this.deliveryService.createSession(
      parseId(params),
      parseInput(CreateAccessSessionSchema, body),
      principal(req),
      reqCtx(req),
    );
  }

  @Get(':id/preview')
  @RequirePermission('DOCUMENT', 'VIEW')
  async previewDocument(
    @Param() params: unknown,
    @Query('sessionId') sessionId: string | undefined,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const result = await this.deliveryService.getPreviewPdf(
      parseId(params),
      resolveAccessSessionId(sessionId, req),
      undefined,
      principal(req),
      reqCtx(req),
    );
    sendInlinePreviewReply(reply, result);
  }

  @Get(':id/preview/page/:pageNumber')
  @RequirePermission('DOCUMENT', 'VIEW')
  async previewDocumentPage(
    @Param() params: unknown,
    @Query('sessionId') sessionId: string | undefined,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const { id, pageNum } = parsePreviewPageParams(params);
    const result = await this.deliveryService.getPreviewPdf(
      id,
      resolveAccessSessionId(sessionId, req),
      pageNum,
      principal(req),
      reqCtx(req),
    );
    sendInlinePreviewReply(reply, result);
  }

  @Get(':id/download')
  @RequirePermission('DOCUMENT', 'DOWNLOAD')
  async downloadDocument(
    @Param() params: unknown,
    @Query('sessionId') sessionId: string | undefined,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const result = await this.deliveryService.downloadDocument(
      parseId(params),
      resolveAccessSessionId(sessionId, req),
      principal(req),
      reqCtx(req),
    );
    sendAttachmentDownloadReply(reply, result);
  }

  @Post(':id/download-ticket')
  @HttpCode(HttpStatus.CREATED)
  @RequirePermission('DOCUMENT', 'DOWNLOAD')
  async createDownloadTicket(
    @Param() params: unknown,
    @Body('sessionId') sessionId: string | undefined,
    @Req() req: FastifyRequest,
  ): Promise<{ ticket: string; expiresAt: string; ttlSeconds: number }> {
    this.csrf.assertRequest(req);
    const id = parseId(params);
    if (!sessionId) throw new BadRequestException('sessionId is required.');
    const validSessionId = resolveAccessSessionId(sessionId, req);
    return this.deliveryService.createDownloadTicket(
      id,
      validSessionId,
      principal(req),
      reqCtx(req),
    );
  }

  @PublicEndpoint()
  @Get('download-with-ticket/:ticket')
  async downloadWithTicket(
    @Param() params: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const result = await this.deliveryService.redeemDownloadTicket(
      parseDownloadTicketParam(params),
      reqCtx(req),
    );
    sendAttachmentDownloadReply(reply, result);
  }
}

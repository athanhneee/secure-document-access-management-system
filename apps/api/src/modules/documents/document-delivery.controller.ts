/**
 * Module: Controlled Document Session, Watermarked Preview & Ticketed Download HTTP Controller
 * Thuật toán: Bộ Điều Khiển HTTP Phân Phối Tài Liệu Có Kiểm Soát (`DocumentDeliveryController`).
 *   1. Kiểm định quyền RBAC (`DOCUMENT:VIEW` / `DOCUMENT:DOWNLOAD`) và bảo vệ chống CSRF khi mở phiên hoặc xin cấp vé tải.
 *   2. Trả luồng nhị phân với tiêu đề chống lưu đệm nghiêm ngặt (`Cache-Control: no-store`) và `Referrer-Policy: no-referrer` trên đường dẫn vé một lần.
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

  /**
   * Thuật toán: Mở phiên truy cập tài liệu có kiểm soát sau khi xác thực CSRF và quyền `DOCUMENT:VIEW`.
   */
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

  /**
   * Thuật toán: Trả bản xem trước PDF đầy đủ gắn thủy vân theo phiên hoạt động.
   */
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

  /**
   * Thuật toán: Trả bản xem trước từng trang PDF lẻ của phiên (sử dụng bộ đệm dẫn xuất mã hóa từ trang thứ 2 trở đi).
   */
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

  /**
   * Thuật toán: Tải xuống trực tiếp tài liệu dẫn xuất theo phiên `DOWNLOAD` hợp lệ.
   */
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

  /**
   * Thuật toán: Cấp phát vé tải dùng một lần ngắn hạn cho trình duyệt sau khi kiểm định CSRF và phiên `DOWNLOAD`.
   */
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

  /**
   * Thuật toán: Đổi vé tải dùng một lần (`/download-with-ticket/:ticket`) kèm tái xác minh CSDL thời gian thực và tiêu đề chống rò rỉ Referrer.
   */
  @PublicEndpoint()
  @Get('download-with-ticket/:ticket')
  async downloadWithTicket(
    @Param() params: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    reply.header('Referrer-Policy', 'no-referrer');
    reply.header('X-Content-Type-Options', 'nosniff');
    const result = await this.deliveryService.redeemDownloadTicket(
      parseDownloadTicketParam(params),
      reqCtx(req),
    );
    sendAttachmentDownloadReply(reply, result);
  }
}

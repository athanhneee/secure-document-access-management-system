/**
 * Module: Bộ Điều phối Tiếp nhận Luồng Tệp Tải lên (Multipart Streaming Upload Controller)
 * Thuật toán: Xác thực CSRF và kiểm tra hợp lệ sớm các trường biểu mẫu multipart kèm cơ chế hủy luồng tức thì
 *   (`part.file.destroy()`) khi phát hiện tham số sai định dạng trước khi chuyển vào đường ống tiếp nhận.
 */
import {
  BadRequestException,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';
import { CsrfService } from '../auth/csrf.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { UuidParamSchema } from '@sda/contracts';
import {
  DocumentIngestionService,
  type IngestDocumentOutput,
} from './document-ingestion.service.js';

interface MultipartValueField {
  value?: unknown;
}

@Controller('documents')
export class DocumentIngestionController {
  constructor(
    private readonly ingestion: DocumentIngestionService,
    private readonly csrf: CsrfService,
  ) {}

  /**
   * Thuật toán: Bóc Tách Luồng Multipart Có Hủy Sớm Chống Rò Rỉ Tài Nguyên (Fail-Fast Multipart Stream Guard)
   * Mục đích: Xác thực token chống giả mạo yêu cầu chéo trang (CSRF) và định dạng siêu dữ liệu đi kèm tệp trước khi đọc luồng.
   * Cơ chế hoạt động:
   *   - Kiểm chứng CSRF, xác nhận kiểu `multipart/form-data` và lấy phần tử tệp đầu tiên.
   *   - Kiểm tra biểu thức chính quy chặt chẽ trên các trường ID số nguyên lớn, UUID, mã tài liệu và ngày lưu trữ;
   *     nếu bất kỳ trường nào vi phạm thì gọi `part.file.destroy()` giải phóng bộ đệm socket ngay lập tức trước khi ném lỗi 400.
   */
  @Post('upload')
  @HttpCode(HttpStatus.CREATED)
  @RequirePermission('DOCUMENT', 'UPLOAD')
  async uploadDocument(@Req() request: FastifyRequest): Promise<IngestDocumentOutput> {
    this.csrf.assertRequest(request);

    if (!request.isMultipart()) {
      throw new BadRequestException('Request must be multipart/form-data.');
    }

    const part = await request.file();
    if (!part) {
      throw new BadRequestException('No file provided in multipart body.');
    }

    const fields = part.fields as Record<string, MultipartValueField | undefined>;
    const getFieldValue = (fieldName: string): string | undefined => {
      const field = fields[fieldName];
      return typeof field?.value === 'string' ? field.value.trim() : undefined;
    };

    const abortPartAndThrow = (message: string): never => {
      part.file.destroy();
      throw new BadRequestException(message);
    };

    const title = getFieldValue('title');
    const rawDeptId = getFieldValue('departmentId');
    if (rawDeptId && !/^\d+$/u.test(rawDeptId)) {
      abortPartAndThrow('Invalid departmentId format.');
    }
    const departmentId = rawDeptId ? BigInt(rawDeptId) : undefined;

    const documentId = getFieldValue('documentId');
    if (documentId && !UuidParamSchema.safeParse({ id: documentId }).success) {
      abortPartAndThrow('Invalid documentId UUID format.');
    }

    const documentCode = getFieldValue('documentCode');
    if (documentCode && !/^[A-Za-z0-9][A-Za-z0-9_-]{0,59}$/u.test(documentCode)) {
      abortPartAndThrow('Invalid documentCode format.');
    }

    const changeNote = getFieldValue('changeNote');
    const description = getFieldValue('description');
    const rawClassificationLevelId = getFieldValue('classificationLevelId');
    if (rawClassificationLevelId && !/^\d+$/u.test(rawClassificationLevelId)) {
      abortPartAndThrow('Invalid classificationLevelId format.');
    }
    const classificationLevelId = rawClassificationLevelId
      ? BigInt(rawClassificationLevelId)
      : undefined;

    const rawBusinessCategoryId = getFieldValue('businessCategoryId');
    if (rawBusinessCategoryId && !/^\d+$/u.test(rawBusinessCategoryId)) {
      abortPartAndThrow('Invalid businessCategoryId format.');
    }
    const businessCategoryId = rawBusinessCategoryId ? BigInt(rawBusinessCategoryId) : undefined;
    const retentionUntil = getFieldValue('retentionUntil');
    if (retentionUntil && !/^\d{4}-\d{2}-\d{2}$/u.test(retentionUntil)) {
      abortPartAndThrow('Invalid retentionUntil date format (expected YYYY-MM-DD).');
    }

    return this.ingestion.ingestDocument({
      fileStream: part.file,
      rawFilename: part.filename,
      declaredMime: part.mimetype,
      title,
      departmentId,
      documentId,
      documentCode,
      description,
      classificationLevelId,
      businessCategoryId,
      retentionUntil,
      changeNote,
      principal: this.principal(request),
      context: this.context(request),
    });
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

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
  PayloadTooLargeException,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { Readable } from 'node:stream';
import { CsrfService } from '../auth/csrf.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { RequirePermission } from '../rbac/require-permission.js';
import { AppErrorCode, MAX_PG_BIGINT, UuidParamSchema } from '@sda/contracts';
import {
  DocumentIngestionService,
  type IngestDocumentOutput,
} from './document-ingestion.service.js';
import { parseIsoRetentionDate } from './document-draft-validation.helper.js';
import { spoolUploadStreamToTempFile } from './ingestion-validation.helper.js';

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

    const mapMultipartLimitError = (err: unknown): never => {
      const code =
        typeof err === 'object' && err !== null && 'code' in err
          ? String((err as { code?: unknown }).code)
          : '';
      if (code === 'FST_REQ_FILE_TOO_LARGE') {
        throw new PayloadTooLargeException({
          errorCode: AppErrorCode.FILE_SIZE_EXCEEDED,
          message: 'Uploaded file exceeds the maximum allowed size.',
        });
      }
      if (
        code === 'FST_FILES_LIMIT' ||
        code === 'FST_PARTS_LIMIT' ||
        code === 'FST_FIELDS_LIMIT' ||
        code === 'FST_INVALID_MULTIPART_CONTENT_TYPE'
      ) {
        throw new BadRequestException({
          errorCode: AppErrorCode.VALIDATION_FAILED,
          message: 'Invalid multipart upload request or limit exceeded.',
        });
      }
      throw err;
    };

    // MED-03: Duyệt `request.parts()` để thu đủ mọi trường văn bản bất kể thứ tự file-trước/field-sau, đồng thời chặn trùng trường hoặc đa tệp.
    let tempDir: string | null = null;
    let tempSpoolPath: string | null = null;
    let fileStream: Readable | null = null;
    let rawFilename = '';
    let declaredMime = '';
    const fields: Record<string, MultipartValueField | undefined> = Object.create(null) as Record<
      string,
      MultipartValueField | undefined
    >;

    try {
      if (typeof (request as { parts?: unknown }).parts === 'function') {
        const maxFileSize = this.ingestion.maxUploadFileSizeBytes ?? 50 * 1024 * 1024;
        try {
          for await (const part of request.parts()) {
            if (part.type === 'file') {
              if (tempSpoolPath !== null) {
                part.file.destroy();
                throw new BadRequestException({
                  errorCode: AppErrorCode.VALIDATION_FAILED,
                  message: 'Only a single file is allowed per upload request.',
                });
              }
              rawFilename = part.filename;
              declaredMime = part.mimetype;
              tempDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sda-mp-'));
              tempSpoolPath = path.join(tempDir, `upload-${randomUUID()}.tmp`);
              await spoolUploadStreamToTempFile(part.file, tempSpoolPath, maxFileSize);
            } else {
              if (Object.hasOwn(fields, part.fieldname)) {
                throw new BadRequestException({
                  errorCode: AppErrorCode.VALIDATION_FAILED,
                  message: `Duplicate multipart field: ${part.fieldname}.`,
                });
              }
              fields[part.fieldname] = { value: part.value };
            }
          }
        } catch (err: unknown) {
          mapMultipartLimitError(err);
        }
        if (!tempSpoolPath) {
          throw new BadRequestException('No file provided in multipart body.');
        }
        fileStream = fs.createReadStream(tempSpoolPath);
      } else {
        let part: Awaited<ReturnType<FastifyRequest['file']>>;
        try {
          part = await request.file();
        } catch (err: unknown) {
          mapMultipartLimitError(err);
        }
        if (!part!) {
          throw new BadRequestException('No file provided in multipart body.');
        }
        if ((part!.file as { truncated?: boolean | undefined }).truncated) {
          part!.file.destroy();
          throw new PayloadTooLargeException({
            errorCode: AppErrorCode.FILE_SIZE_EXCEEDED,
            message: 'Uploaded file exceeds the maximum allowed size.',
          });
        }
        fileStream = part!.file;
        rawFilename = part!.filename;
        declaredMime = part!.mimetype;
        const partFields = part!.fields as Record<string, MultipartValueField | undefined>;
        for (const [k, v] of Object.entries(partFields)) {
          fields[k] = v;
        }
      }

      const activeStream = fileStream;
      const getFieldValue = (fieldName: string): string | undefined => {
        const field = fields[fieldName];
        return typeof field?.value === 'string' ? field.value.trim() : undefined;
      };

      const abortPartAndThrow = (message: string): never => {
        activeStream.destroy();
        throw new BadRequestException(message);
      };

      const parsePositiveBigIntField = (
        raw: string | undefined,
        label: string,
      ): bigint | undefined => {
        if (!raw) return undefined;
        if (!/^[1-9]\d*$/u.test(raw)) {
          abortPartAndThrow(`Invalid ${label} format.`);
        }
        const parsed = BigInt(raw);
        if (parsed > MAX_PG_BIGINT) {
          abortPartAndThrow(`${label} exceeds PostgreSQL 64-bit BIGINT range.`);
        }
        return parsed;
      };

      const rawTitleField = fields['title']?.value;
      if (typeof rawTitleField === 'string' && rawTitleField.length > 0) {
        const trimmedTitle = rawTitleField.trim();
        if (trimmedTitle.length === 0 || trimmedTitle.length > 255) {
          abortPartAndThrow('Document title must be between 1 and 255 characters.');
        }
      }
      const title = getFieldValue('title') || undefined;
      const departmentId = parsePositiveBigIntField(getFieldValue('departmentId'), 'departmentId');

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
      const classificationLevelId = parsePositiveBigIntField(
        getFieldValue('classificationLevelId'),
        'classificationLevelId',
      );
      const businessCategoryId = parsePositiveBigIntField(
        getFieldValue('businessCategoryId'),
        'businessCategoryId',
      );
      const rawRetentionUntil = getFieldValue('retentionUntil');
      const retentionUntil = rawRetentionUntil ? rawRetentionUntil : undefined;
      if (retentionUntil) {
        try {
          parseIsoRetentionDate(retentionUntil);
        } catch (err) {
          activeStream.destroy();
          throw err;
        }
      }

      return await this.ingestion.ingestDocument({
        fileStream: activeStream,
        rawFilename,
        declaredMime,
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
    } finally {
      if (fileStream && !fileStream.destroyed && !fileStream.readableEnded) {
        fileStream.destroy();
      }
      if (tempSpoolPath) {
        await fsp.unlink(tempSpoolPath).catch(() => {});
      }
      if (tempDir) {
        await fsp.rm(tempDir, { recursive: true, force: true }).catch(() => {});
      }
    }
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

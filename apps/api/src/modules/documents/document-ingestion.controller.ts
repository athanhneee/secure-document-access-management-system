import {
  BadRequestException,
  Controller,
  ForbiddenException,
  HttpCode,
  HttpStatus,
  Post,
  Req,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';
import { CsrfService } from '../auth/csrf.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { RequirePermission } from '../rbac/require-permission.js';
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

    const title = getFieldValue('title');
    const rawDeptId = getFieldValue('departmentId');
    const departmentId = rawDeptId && /^\d+$/u.test(rawDeptId) ? BigInt(rawDeptId) : undefined;
    const documentId = getFieldValue('documentId');
    const documentCode = getFieldValue('documentCode');
    const changeNote = getFieldValue('changeNote');

    return this.ingestion.ingestDocument({
      fileStream: part.file,
      rawFilename: part.filename,
      declaredMime: part.mimetype,
      title,
      departmentId,
      documentId,
      documentCode,
      changeNote,
      principal: this.principal(request),
      context: this.context(request),
    });
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

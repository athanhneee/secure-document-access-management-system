/**
 * Module: Document Draft Creation & Metadata Mutation Helper
 * Thuật toán: Khởi Tạo Dự Thảo Tài Liệu Giao Dịch Nguyên Tử & Cập Nhật Siêu Dữ Liệu Có Cưỡng Chế Độ Mật.
 *   1. Kiểm tra phân tách nhiệm vụ (SoD), quyền phòng ban đích, hiệu lực phân loại/danh mục và trần độ mật Bell-LaPadula.
 *   2. Khởi tạo bản ghi `DRAFT` kèm lịch sử phân loại SCD Type 2 ban đầu trong một giao dịch nguyên tử.
 *   3. Khi cập nhật siêu dữ liệu, xác minh tài liệu chưa lưu trữ, thẩm quyền sở hữu/RBAC và độ mật người gọi (`assertDocumentMutationPermission`).
 */
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import {
  AppErrorCode,
  type CreateDocumentDraftInput,
  type UpdateDocumentMetadataInput,
} from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { DocumentAuditService } from './document-audit.service.js';
import {
  assertDocumentMutationPermission,
  assertSubjectAttributesReadyForAbac,
  getUserClearanceRank,
  isPureTechnicalOrAuditRole,
} from './document-access-guard.helper.js';
import {
  assertActiveDepartment,
  assertDepartmentWriteScope,
  parseIsoRetentionDate,
} from './document-draft-validation.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Khởi tạo dự thảo tài liệu (`DRAFT`) và lịch sử phân loại SCD Type 2 ban đầu trong giao dịch nguyên tử.
 */
export async function executeCreateDocumentDraft(params: {
  database: PrismaClient;
  authorization?: AuthorizationService | undefined;
  audit: DocumentAuditService;
  input: CreateDocumentDraftInput;
  principal: AuthPrincipal;
  context: RequestContext;
}): Promise<string> {
  const { database, authorization, audit, input, principal, context } = params;

  if (isPureTechnicalOrAuditRole(principal)) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.TECHNICAL_ADMIN_CANNOT_OWN,
      message: 'Technical administrator and auditor accounts cannot own business documents.',
    });
  }

  await assertSubjectAttributesReadyForAbac(database, principal);

  if (
    input.documentCode !== undefined &&
    !/^[A-Za-z0-9][A-Za-z0-9_-]{0,59}$/.test(input.documentCode)
  ) {
    throw new BadRequestException({
      errorCode: AppErrorCode.VALIDATION_FAILED,
      message: 'Invalid documentCode format.',
    });
  }

  const trimmedTitle = input.title.trim();
  if (!trimmedTitle) {
    throw new BadRequestException({
      errorCode: AppErrorCode.VALIDATION_FAILED,
      message: 'Document title cannot be empty.',
    });
  }

  await assertActiveDepartment(database, input.departmentId);
  await assertDepartmentWriteScope(authorization, principal, input.departmentId, true);

  if (input.classificationLevelId) {
    const level = await database.classificationLevel.findUnique({
      where: { id: input.classificationLevelId },
    });
    if (!level || !level.is_active) {
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message: 'Target classification level does not exist or is inactive.',
      });
    }
    const actorClearanceRank = await getUserClearanceRank(database, principal.userId, new Date());
    if (actorClearanceRank < level.rank) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
        message: `Insufficient clearance level (${actorClearanceRank}) to create document at classification rank ${level.rank}.`,
      });
    }
  }

  if (input.businessCategoryId) {
    const cat = await database.businessCategory.findUnique({
      where: { id: input.businessCategoryId },
    });
    if (!cat || !cat.is_active) {
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message: 'Target business category does not exist or is inactive.',
      });
    }
  }

  const retentionDate = input.retentionUntil ? parseIsoRetentionDate(input.retentionUntil) : null;
  const documentId = randomUUID();
  const docCode = input.documentCode ?? `DOC-${randomUUID().substring(0, 8).toUpperCase()}`;

  await database.$transaction(async (tx) => {
    await tx.document.create({
      data: {
        id: documentId,
        document_code: docCode,
        title: trimmedTitle,
        description: input.description ?? null,
        owner_id: principal.userId,
        department_id: input.departmentId,
        status: 'DRAFT',
        discoverable: true,
        retention_until: retentionDate,
      },
    });

    if (input.classificationLevelId && input.businessCategoryId) {
      await tx.documentClassificationHistory.create({
        data: {
          document_id: documentId,
          classification_level_id: input.classificationLevelId,
          business_category_id: input.businessCategoryId,
          reason: input.reason ?? 'Initial draft classification',
          classified_by: principal.userId,
          effective_from: new Date(),
          effective_to: null,
        },
      });
    }
  });

  await audit.record(
    {
      action: 'DOCUMENT_CREATED',
      outcome: 'SUCCESS',
      actorUserId: principal.userId,
      actorUsername: principal.username,
      documentId,
      details: {
        documentCode: docCode,
        title: trimmedTitle,
        departmentId: input.departmentId.toString(),
        classificationLevelId: input.classificationLevelId?.toString() ?? null,
        businessCategoryId: input.businessCategoryId?.toString() ?? null,
      },
    },
    context,
  );

  return documentId;
}

/**
 * Thuật toán: Cập nhật siêu dữ liệu tài liệu có kiểm soát phiên bản lạc quan và cưỡng chế độ mật của chủ sở hữu/quản trị viên.
 */
export async function executeUpdateDocumentMetadata(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  audit: DocumentAuditService;
  documentId: string;
  input: UpdateDocumentMetadataInput;
  principal: AuthPrincipal;
  context: RequestContext;
}): Promise<void> {
  const { database, authorization, audit, documentId, input, principal, context } = params;

  const doc = await database.document.findUnique({ where: { id: documentId } });
  if (!doc || doc.status === 'DELETED') {
    throw new NotFoundException({
      errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
      message: 'Document not found.',
    });
  }

  await assertDocumentMutationPermission(authorization, doc, principal, 'METADATA', { database });

  if (doc.status === 'ARCHIVED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
      message: 'Cannot modify an archived or deleted document.',
    });
  }

  const updateData: {
    title?: string;
    description?: string | null;
    department_id?: bigint;
    retention_until?: Date | null;
    version: { increment: number };
  } = { version: { increment: 1 } };

  if (input.title !== undefined) {
    const trimmed = input.title.trim();
    if (!trimmed) {
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message: 'Title cannot be empty.',
      });
    }
    updateData.title = trimmed;
  }

  if (input.description !== undefined) updateData.description = input.description;

  if (input.departmentId !== undefined) {
    await assertActiveDepartment(database, input.departmentId);
    if (input.departmentId !== doc.department_id) {
      await assertDepartmentWriteScope(authorization, principal, input.departmentId, false);
    }
    updateData.department_id = input.departmentId;
  }

  if (input.retentionUntil !== undefined) {
    updateData.retention_until =
      input.retentionUntil === null ? null : parseIsoRetentionDate(input.retentionUntil);
  }

  await database.document.update({ where: { id: documentId }, data: updateData });

  await audit.record(
    {
      action: 'DOCUMENT_METADATA_UPDATED',
      outcome: 'SUCCESS',
      actorUserId: principal.userId,
      actorUsername: principal.username,
      documentId,
      details: {
        title: input.title ?? null,
        departmentId: input.departmentId ? input.departmentId.toString() : null,
        retentionUntil: input.retentionUntil ?? null,
      },
    },
    context,
  );
}

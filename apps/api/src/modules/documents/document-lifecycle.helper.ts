/**
 * Module: Document Draft Creation & Metadata Mutation Helper
 * Algorithm: Validates SoD, department/classification/category existence, and ISO retention dates
 *   before creating `DRAFT` documents or incrementing optimistic concurrency version on metadata updates.
 */
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import {
  AppErrorCode,
  isValidIsoCalendarDate,
  type CreateDocumentDraftInput,
  type UpdateDocumentMetadataInput,
} from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { DocumentAuditService } from './document-audit.service.js';
import {
  assertDocumentMutationPermission,
  getUserClearanceRank,
  isPureTechnicalOrAuditRole,
} from './document-access-guard.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

async function assertActiveDepartment(database: PrismaClient, departmentId: bigint): Promise<void> {
  const dept = await database.department.findUnique({ where: { id: departmentId } });
  if (!dept || !dept.is_active) {
    throw new BadRequestException({
      errorCode: AppErrorCode.VALIDATION_FAILED,
      message: 'Target department does not exist or is inactive.',
    });
  }
}

/**
 * Thuật toán: Kiểm định thẩm quyền phòng ban đích khi khởi tạo dự thảo hoặc di chuyển phòng ban tài liệu (HIGH-05).
 */
async function assertDepartmentWriteScope(
  authorization: AuthorizationService | undefined,
  principal: AuthPrincipal,
  targetDepartmentId: bigint,
  allowUploadAction: boolean,
): Promise<void> {
  if (!authorization || typeof authorization.hasPermission !== 'function') return;
  const scope = { targetDepartmentId };
  const [canManage, canClassify, canUpload] = await Promise.all([
    authorization.hasPermission(principal, 'DOCUMENT', 'MANAGE', scope),
    authorization.hasPermission(principal, 'DOCUMENT', 'CLASSIFY', scope),
    allowUploadAction
      ? authorization.hasPermission(principal, 'DOCUMENT', 'UPLOAD', scope)
      : Promise.resolve(false),
  ]);
  if (!canManage && !canClassify && !canUpload) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Caller is not authorized to create or place documents in the target department.',
    });
  }
}

/**
 * Thuật toán: Phân tích ngày hạn lưu trữ ISO `YYYY-MM-DD` có kiểm định ngày lịch Gregorian thực.
 */
function parseIsoRetentionDate(isoDate: string): Date {
  if (!isValidIsoCalendarDate(isoDate)) {
    throw new BadRequestException({
      errorCode: AppErrorCode.RETENTION_DATE_INVALID,
      message: 'Invalid retention date format or impossible calendar date.',
    });
  }
  const retDate = new Date(`${isoDate}T00:00:00.000Z`);
  if (Number.isNaN(retDate.getTime())) {
    throw new BadRequestException({
      errorCode: AppErrorCode.RETENTION_DATE_INVALID,
      message: 'Invalid retention date format.',
    });
  }
  return retDate;
}

/**
 * Algorithm: Transactional Document Draft & Initial Classification Creation
 * Validates master-data references and atomically inserts the `DRAFT` document plus optional initial SCD2 classification.
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
  // CONFLICT-RESOLVED: Chặn BOLA liên phòng ban và kiểm tra độ mật Bell-LaPadula ngay khi khởi tạo bản nháp tài liệu (HIGH-05).
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
 * Algorithm: Optimistic-Versioned Document Metadata Mutation
 * Verifies non-archived status and scoped mutation rights before applying partial metadata updates.
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
  if (!doc) {
    throw new NotFoundException({
      errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
      message: 'Document not found.',
    });
  }
  if (doc.status === 'ARCHIVED' || doc.status === 'DELETED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
      message: 'Cannot modify an archived or deleted document.',
    });
  }

  await assertDocumentMutationPermission(authorization, doc, principal, 'METADATA');

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
      // CONFLICT-RESOLVED: Chặn chuyển phòng ban tài liệu sang đơn vị ngoài thẩm quyền quản lý/phân loại của người gọi (HIGH-05).
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

/**
 * @module IngestionVersionHelper
 * Thuật toán: Lưu trữ nguyên tử siêu dữ liệu phiên bản tài liệu qua cơ chế khóa kép (`Redlock` phân tán + khóa dòng
 * PostgreSQL `SELECT ... FOR UPDATE`), cấp phát số phiên bản tuần tự `max(version_no) + 1`, kiểm định trần độ mật
 * Bell-LaPadula của người tải lên và thực thi toàn bộ truy vấn bên trong giao dịch qua `tx` chống tự khóa chết Pool.
 */
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { RedlockService } from '../concurrency/redlock.service.js';
import { getUserClearanceRank } from './document-access-guard.helper.js';
import { parseIsoRetentionDate } from './document-draft-validation.helper.js';
import type { ValidatedFileInfo } from './file-validation.service.js';
import {
  assertIngestionClassificationValid,
  type IngestDocumentInput,
} from './ingestion-validation.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface PersistedIngestedVersionResult {
  versionNo: number;
  documentStatus: 'DRAFT' | 'ACTIVE';
}

/**
 * Thuật toán: Ghi nhận phiên bản tài liệu đã quét sạch mã độc trong giao dịch nguyên tử khóa kép (`Redlock` + `FOR UPDATE`),
 * trả về đồng thời `versionNo` và trạng thái thực tế của tài liệu (`DRAFT` hoặc `ACTIVE` khi tải lên v2+, BUG-110).
 */
export async function persistCleanIngestedVersionWithStatus(params: {
  database: PrismaClient;
  redlock?: RedlockService | undefined;
  authorization?: AuthorizationService | undefined;
  input: IngestDocumentInput;
  targetDocId: string;
  validatedInfo: ValidatedFileInfo;
  documentStorageKey: string;
  totalBytes: number;
  sha256Hash: string;
  dekReference: string;
}): Promise<PersistedIngestedVersionResult> {
  const {
    database,
    redlock,
    authorization,
    input,
    targetDocId,
    validatedInfo,
    documentStorageKey,
    totalBytes,
    sha256Hash,
    dekReference,
  } = params;

  let callerDeptId = (input.principal as { departmentId?: bigint }).departmentId;
  if (
    input.departmentId === undefined &&
    callerDeptId === undefined &&
    typeof database?.user?.findUnique === 'function'
  ) {
    const caller = await database.user.findUnique({
      where: { id: input.principal.userId },
      select: { department_id: true },
    });
    callerDeptId = caller?.department_id ?? undefined;
  }
  const deptId = input.departmentId ?? callerDeptId ?? 1n;
  const title = (input.title?.trim() || validatedInfo.sanitizedFilename).slice(0, 255);
  const docCode = input.documentCode ?? `DOC-${randomUUID().substring(0, 8).toUpperCase()}`;

  const retentionDate: Date | null =
    input.retentionUntil && input.retentionUntil !== ''
      ? parseIsoRetentionDate(input.retentionUntil)
      : null;

  let finalVersionNo = 1;
  let persistedStatus: 'DRAFT' | 'ACTIVE' = 'DRAFT';

  const persistVersionMetadata = async (): Promise<void> => {
    await database.$transaction(async (tx) => {
      if (
        typeof (tx as unknown as { $executeRawUnsafe?: unknown }).$executeRawUnsafe === 'function'
      ) {
        await (
          tx as unknown as {
            $executeRawUnsafe: (sql: string, ...args: unknown[]) => Promise<unknown>;
          }
        ).$executeRawUnsafe('SELECT id FROM documents WHERE id = $1::uuid FOR UPDATE', targetDocId);
      }

      const existingDoc = await tx.document.findUnique({
        where: { id: targetDocId },
        include: {
          versions: { select: { version_no: true } },
          classification_history: { where: { effective_to: null }, select: { id: true } },
        },
      });

      if (existingDoc && existingDoc.status === 'DELETED') {
        throw new NotFoundException({
          errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
          message: 'Document not found.',
        });
      }

      if (
        existingDoc &&
        existingDoc.owner_id !== undefined &&
        existingDoc.owner_id !== input.principal.userId
      ) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
          message: 'Only the document owner can upload a new version.',
        });
      }

      if (existingDoc && existingDoc.status === 'ARCHIVED') {
        throw new BadRequestException({
          errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
          message: 'Cannot upload new version to an archived or deleted document.',
        });
      }

      // CONFLICT-RESOLVED: Truy vấn qua client giao dịch tx thay vì pool gốc database bên trong $transaction để chống tự khóa chết Pool (Self-Deadlock).
      const txClient = tx as unknown as PrismaClient;
      let hasActiveClassification = Boolean(existingDoc?.classification_history?.length);

      if (!existingDoc) {
        if (authorization && typeof authorization.hasPermission === 'function') {
          const scope = { targetDepartmentId: deptId };
          const [canUpload, canClassify, canManage] = await Promise.all([
            authorization.hasPermission(input.principal, 'DOCUMENT', 'UPLOAD', scope),
            authorization.hasPermission(input.principal, 'DOCUMENT', 'CLASSIFY', scope),
            authorization.hasPermission(input.principal, 'DOCUMENT', 'MANAGE', scope),
          ]);
          if (!canUpload && !canClassify && !canManage) {
            throw new ForbiddenException({
              errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
              message: 'Caller is not authorized to upload documents into the target department.',
            });
          }
        }
        await assertIngestionClassificationValid({
          database: txClient,
          principal: input.principal,
          classificationLevelId: input.classificationLevelId,
          businessCategoryId: input.businessCategoryId,
        });
        await tx.document.create({
          data: {
            id: targetDocId,
            document_code: docCode,
            title,
            description: input.description ?? null,
            owner_id: input.principal.userId,
            department_id: deptId,
            status: 'DRAFT',
            discoverable: true,
            retention_until: retentionDate,
          },
        });
        finalVersionNo = 1;
        persistedStatus = 'DRAFT';
      } else {
        persistedStatus = existingDoc.status === 'ACTIVE' ? 'ACTIVE' : 'DRAFT';
        if (typeof txClient?.documentClassificationHistory?.findFirst === 'function') {
          const currentClass = await txClient.documentClassificationHistory.findFirst({
            where: { document_id: targetDocId, effective_to: null },
            include: { classification_levels: true },
          });
          if (currentClass) {
            hasActiveClassification = true;
          }
          const existingRank = currentClass?.classification_levels?.rank ?? 0;
          if (
            existingRank > 0 &&
            typeof txClient?.userAttributeAssignment?.findFirst === 'function'
          ) {
            const rank = await getUserClearanceRank(txClient, input.principal.userId, new Date());
            if (rank < existingRank) {
              throw new ForbiddenException({
                errorCode: AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
                message: `Insufficient clearance level (${rank}) to upload version to document at rank ${existingRank}.`,
              });
            }
          }
        }
        if (!hasActiveClassification) {
          await assertIngestionClassificationValid({
            database: txClient,
            principal: input.principal,
            classificationLevelId: input.classificationLevelId,
            businessCategoryId: input.businessCategoryId,
          });
        }
        const currentMaxVersion = existingDoc.versions.reduce(
          (max, v) => (v.version_no > max ? v.version_no : max),
          0,
        );
        finalVersionNo = currentMaxVersion + 1;
      }

      const newVersion = await tx.documentVersion.create({
        data: {
          document_id: targetDocId,
          version_no: finalVersionNo,
          original_filename: validatedInfo.sanitizedFilename,
          storage_key: documentStorageKey,
          mime_type: validatedInfo.mimeType,
          file_size_bytes: BigInt(totalBytes),
          sha256_hash: sha256Hash,
          encryption_key_ref: dekReference,
          scan_status: 'CLEAN',
          change_note:
            input.changeNote?.trim() ||
            (finalVersionNo === 1 ? 'Initial version' : `Version ${finalVersionNo}`),
          uploaded_by: input.principal.userId,
        },
      });

      if (
        typeof tx.document?.update === 'function' &&
        newVersion?.id &&
        (!existingDoc || !existingDoc.current_version_id)
      ) {
        await tx.document.update({
          where: { id: targetDocId },
          data: { current_version_id: newVersion.id },
        });
      }

      if (
        input.classificationLevelId &&
        typeof tx.documentClassificationHistory?.create === 'function' &&
        !hasActiveClassification
      ) {
        await tx.documentClassificationHistory.create({
          data: {
            document_id: targetDocId,
            classification_level_id: input.classificationLevelId,
            business_category_id: input.businessCategoryId ?? 1n,
            reason: input.changeNote ?? 'Initial upload classification',
            classified_by: input.principal.userId,
            effective_from: new Date(),
            effective_to: null,
          },
        });
      }
    });
  };

  if (redlock) {
    await redlock.withLock(`document:version:${targetDocId}`, 10_000, persistVersionMetadata);
  } else {
    await persistVersionMetadata();
  }

  return { versionNo: finalVersionNo, documentStatus: persistedStatus };
}

/**
 * Thuật toán: Tương thích ngược trả về số phiên bản `versionNo` cho các lời gọi trực tiếp `persistCleanIngestedVersion`.
 */
export async function persistCleanIngestedVersion(
  params: Parameters<typeof persistCleanIngestedVersionWithStatus>[0],
): Promise<number> {
  const persisted = await persistCleanIngestedVersionWithStatus(params);
  return persisted.versionNo;
}

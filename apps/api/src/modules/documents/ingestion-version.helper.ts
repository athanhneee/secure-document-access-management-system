/**
 * @module IngestionVersionHelper
 * Thuật toán: Lưu trữ nguyên tử siêu dữ liệu phiên bản tài liệu qua cơ chế khóa kép (`Redlock` phân tán + khóa dòng
 * PostgreSQL `SELECT ... FOR UPDATE`), cấp phát số phiên bản tuần tự `max(version_no) + 1`, kiểm định trần độ mật
 * Bell-LaPadula của người tải lên và thực thi toàn bộ truy vấn bên trong giao dịch qua `tx` chống tự khóa chết Pool.
 */
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { RedlockService } from '../concurrency/redlock.service.js';
import { getUserClearanceRank } from './document-access-guard.helper.js';
import { parseIsoRetentionDate } from './document-draft-validation.helper.js';
import type { ValidatedFileInfo } from './file-validation.service.js';
import type { IngestDocumentInput } from './ingestion-validation.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Ghi nhận phiên bản tài liệu đã quét sạch mã độc trong giao dịch nguyên tử khóa kép (`Redlock` + `FOR UPDATE`).
 * Sử dụng nhất quán `tx` cho mọi thao tác đọc/ghi trong `$transaction` để loại bỏ nguy cơ cạn kiệt kết nối tự khóa chết (Self-Deadlock).
 */
export async function persistCleanIngestedVersion(params: {
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
}): Promise<number> {
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
  const title = input.title ?? validatedInfo.sanitizedFilename;
  const docCode = input.documentCode ?? `DOC-${randomUUID().substring(0, 8).toUpperCase()}`;

  const retentionDate: Date | null =
    input.retentionUntil && input.retentionUntil !== ''
      ? parseIsoRetentionDate(input.retentionUntil)
      : null;

  let finalVersionNo = 1;

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

      if (existingDoc && (existingDoc.status === 'ARCHIVED' || existingDoc.status === 'DELETED')) {
        throw new BadRequestException({
          errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
          message: 'Cannot upload new version to an archived or deleted document.',
        });
      }

      if (
        existingDoc &&
        existingDoc.owner_id !== undefined &&
        existingDoc.owner_id !== input.principal.userId
      ) {
        const canCreateVersion = authorization
          ? (await authorization.hasPermission(input.principal, 'DOCUMENT_VERSION', 'CREATE', {
              targetDepartmentId: existingDoc.department_id,
            })) ||
            (await authorization.hasPermission(input.principal, 'DOCUMENT', 'CLASSIFY', {
              targetDepartmentId: existingDoc.department_id,
            }))
          : false;
        if (!canCreateVersion) {
          throw new ForbiddenException({
            errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
            message:
              'Only the document owner or authorized department administrator can upload a new version.',
          });
        }
      }

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
        // CONFLICT-RESOLVED: Truy vấn qua client giao dịch tx thay vì pool gốc database bên trong $transaction để chống tự khóa chết Pool (Self-Deadlock).
        const txClient = tx as unknown as PrismaClient;
        if (
          input.classificationLevelId &&
          typeof txClient?.classificationLevel?.findUnique === 'function'
        ) {
          const level = await txClient.classificationLevel.findUnique({
            where: { id: input.classificationLevelId },
          });
          if (!level || !level.is_active) {
            throw new BadRequestException({
              errorCode: AppErrorCode.VALIDATION_FAILED,
              message: 'Target classification level does not exist or is inactive.',
            });
          }
          if (typeof txClient?.userAttributeAssignment?.findFirst === 'function') {
            const rank = await getUserClearanceRank(txClient, input.principal.userId, new Date());
            if (rank < level.rank) {
              throw new ForbiddenException({
                errorCode: AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
                message: `Insufficient clearance level (${rank}) to upload document at rank ${level.rank}.`,
              });
            }
          }
        }
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
      } else {
        const txClient = tx as unknown as PrismaClient;
        if (
          typeof txClient?.documentClassificationHistory?.findFirst === 'function' &&
          typeof txClient?.userAttributeAssignment?.findFirst === 'function'
        ) {
          const currentClass = await txClient.documentClassificationHistory.findFirst({
            where: { document_id: targetDocId, effective_to: null },
            include: { classification_levels: true },
          });
          const existingRank = currentClass?.classification_levels?.rank ?? 0;
          if (existingRank > 0) {
            const rank = await getUserClearanceRank(txClient, input.principal.userId, new Date());
            if (rank < existingRank) {
              throw new ForbiddenException({
                errorCode: AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
                message: `Insufficient clearance level (${rank}) to upload version to document at rank ${existingRank}.`,
              });
            }
          }
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
          change_note: input.changeNote ?? 'Initial version',
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
        (!existingDoc || !existingDoc.classification_history?.length)
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

  return finalVersionNo;
}

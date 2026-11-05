/**
 * Module: Document Ingestion Transactional Version Persistence Helper
 * Algorithm: Serializes version numbering via distributed Redlock + PostgreSQL `SELECT ... FOR UPDATE`,
 *   atomically creating `DRAFT` documents, `CLEAN` versions, `current_version_id` pointers, and initial classifications.
 */
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { RedlockService } from '../concurrency/redlock.service.js';
import { getUserClearanceRank } from './document-access-guard.helper.js';
import type { ValidatedFileInfo } from './file-validation.service.js';
import type { IngestDocumentInput } from './ingestion-validation.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm: Dual-Lock Atomic Document Version Persistence
 * Acquires optional Redlock (`document:version:<id>`) and PostgreSQL `FOR UPDATE` row lock to compute `max(version_no) + 1`.
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

  let retentionDate: Date | null = null;
  if (input.retentionUntil) {
    retentionDate = new Date(`${input.retentionUntil}T00:00:00.000Z`);
    if (Number.isNaN(retentionDate.getTime())) {
      retentionDate = null;
    }
  }

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
        if (
          input.classificationLevelId &&
          typeof database?.classificationLevel?.findUnique === 'function'
        ) {
          const level = await database.classificationLevel.findUnique({
            where: { id: input.classificationLevelId },
          });
          if (!level || !level.is_active) {
            throw new BadRequestException({
              errorCode: AppErrorCode.VALIDATION_FAILED,
              message: 'Target classification level does not exist or is inactive.',
            });
          }
          if (typeof database?.userAttributeAssignment?.findFirst === 'function') {
            const rank = await getUserClearanceRank(database, input.principal.userId, new Date());
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

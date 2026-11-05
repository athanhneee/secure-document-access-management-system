/**
 * Module: Document Version Pointer & Version History Helper
 * Algorithm: Enforces cross-document foreign-key integrity and `CLEAN` scan-status invariants
 *   when switching `current_version_id`, and lists versions ordered descending after read-access checks.
 */
import { BadRequestException, NotFoundException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode, type SetCurrentVersionInput } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { DocumentAuditService } from './document-audit.service.js';
import {
  assertDocumentMutationPermission,
  assertDocumentReadAccess,
} from './document-access-guard.helper.js';
import type { DocumentVersionItem } from './documents.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm: Foreign-Key & Scan-Hygiene Verified Current Version Assignment
 * Resolves version by `versionId` or `(documentId, versionNo)`, enforces ownership of `documentId` and `CLEAN` status.
 */
export async function executeSetCurrentVersion(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  audit: DocumentAuditService;
  documentId: string;
  input: SetCurrentVersionInput;
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
      message: 'Cannot update version of an archived or deleted document.',
    });
  }

  await assertDocumentMutationPermission(authorization, doc, principal, 'VERSION');

  let version;
  if (input.versionId) {
    version = await database.documentVersion.findUnique({ where: { id: input.versionId } });
  } else if (input.versionNo) {
    version = await database.documentVersion.findUnique({
      where: {
        document_id_version_no: { document_id: documentId, version_no: input.versionNo },
      },
    });
  } else {
    throw new BadRequestException({
      errorCode: AppErrorCode.VALIDATION_FAILED,
      message: 'Must provide either versionId or versionNo.',
    });
  }

  if (!version) {
    throw new NotFoundException({
      errorCode: AppErrorCode.VERSION_NOT_FOUND,
      message: 'Document version not found.',
    });
  }
  if (version.document_id !== documentId) {
    throw new BadRequestException({
      errorCode: AppErrorCode.INVALID_VERSION_TARGET,
      message: 'Cannot point current_version to a version belonging to a different document.',
    });
  }
  if (version.scan_status !== 'CLEAN') {
    throw new BadRequestException({
      errorCode: AppErrorCode.VERSION_NOT_CLEAN,
      message: `Version cannot be assigned as current version because its scan status is ${version.scan_status}. Only CLEAN versions are allowed.`,
    });
  }

  await database.document.update({
    where: { id: documentId },
    data: { current_version_id: version.id, version: { increment: 1 } },
  });

  await audit.record(
    {
      action: 'DOCUMENT_CURRENT_VERSION_SET',
      outcome: 'SUCCESS',
      actorUserId: principal.userId,
      actorUsername: principal.username,
      documentId,
      versionNo: version.version_no,
      details: {
        versionId: version.id.toString(),
        versionNo: version.version_no,
        scanStatus: version.scan_status,
      },
    },
    context,
  );
}

/**
 * Algorithm: Authorization-Checked Document Version History Query
 * Enforces `assertDocumentReadAccess` when `principal` is supplied and returns versions ordered by `version_no DESC`.
 */
export async function queryDocumentVersions(
  database: PrismaClient,
  authorization: AuthorizationService,
  documentId: string,
  principal?: AuthPrincipal,
): Promise<DocumentVersionItem[]> {
  const doc = await database.document.findUnique({
    where: { id: documentId },
    include: {
      classification_history: {
        where: { effective_to: null },
        include: { classification_levels: true },
      },
    },
  });
  if (!doc) {
    throw new NotFoundException({
      errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
      message: 'Document not found.',
    });
  }
  await assertDocumentReadAccess(database, authorization, doc, principal, false);

  const versions = await database.documentVersion.findMany({
    where: { document_id: documentId },
    orderBy: { version_no: 'desc' },
  });

  return versions.map((v) => ({
    id: v.id.toString(),
    versionNo: v.version_no,
    originalFilename: v.original_filename,
    mimeType: v.mime_type,
    fileSizeBytes: v.file_size_bytes.toString(),
    sha256Hash: v.sha256_hash,
    scanStatus: v.scan_status,
    changeNote: v.change_note,
    uploadedBy: v.uploaded_by.toString(),
    createdAt: v.created_at.toISOString(),
  }));
}

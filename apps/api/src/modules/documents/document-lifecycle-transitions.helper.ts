/**
 * Module: Document Lifecycle State Machine Transitions (`DRAFT` -> `ACTIVE` -> `ARCHIVED`)
 * Algorithm: Enforces 5-invariant activation gate with automatic owner-grant provisioning, and executes
 *   atomic archival freeze suspending active grants and terminating all open sessions across versions.
 */
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode, type ArchiveDocumentInput } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationCache } from '../rbac/authorization-cache.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { DocumentAuditService } from './document-audit.service.js';
import { assertDocumentMutationPermission } from './document-access-guard.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm: 5-Invariant Document Activation State Transition (`DRAFT` -> `ACTIVE`)
 * Verifies active owner, active department, non-empty title, active classification/category, and `CLEAN` current version.
 */
export async function executeActivateDocument(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  audit: DocumentAuditService;
  documentId: string;
  principal: AuthPrincipal;
  context: RequestContext;
}): Promise<void> {
  const { database, authorization, audit, documentId, principal, context } = params;

  const doc = await database.document.findUnique({
    where: { id: documentId },
    include: {
      users: true,
      departments: true,
      current_version: true,
      classification_history: {
        where: { effective_to: null },
        include: { classification_levels: true, business_categories: true },
      },
    },
  });

  if (!doc) {
    throw new NotFoundException({
      errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
      message: 'Document not found.',
    });
  }
  if (doc.status === 'ACTIVE') {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ALREADY_ACTIVE,
      message: 'Document is already active.',
    });
  }
  if (doc.status === 'ARCHIVED' || doc.status === 'DELETED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
      message: 'Archived or deleted document cannot be activated.',
    });
  }

  await assertDocumentMutationPermission(authorization, doc, principal, 'ACTIVATE');

  if (!doc.owner_id || !doc.users || doc.users.status !== 'ACTIVE') {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ACTIVATION_FAILED,
      message: 'Document must have an active owner before activation.',
    });
  }
  if (!doc.department_id || !doc.departments || !doc.departments.is_active) {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ACTIVATION_FAILED,
      message: 'Document must belong to an active department before activation.',
    });
  }
  if (!doc.title || doc.title.trim().length === 0) {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ACTIVATION_FAILED,
      message: 'Document title cannot be empty before activation.',
    });
  }

  const activeClassification = doc.classification_history?.[0];
  if (
    !activeClassification ||
    !activeClassification.classification_level_id ||
    !activeClassification.business_category_id
  ) {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ACTIVATION_FAILED,
      message:
        'Document must have an active classification level and business category before activation.',
    });
  }

  if (!doc.current_version_id || !doc.current_version) {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ACTIVATION_FAILED,
      message: 'Document must have a current file version assigned before activation.',
    });
  }
  if (doc.current_version.scan_status !== 'CLEAN') {
    throw new BadRequestException({
      errorCode: AppErrorCode.VERSION_NOT_CLEAN,
      message: `Cannot activate document: current version has scan status ${doc.current_version.scan_status}. Only CLEAN versions can be activated.`,
    });
  }

  // CONFLICT-RESOLVED: Bọc kích hoạt tài liệu và khởi tạo/gia hạn owner grant trong giao dịch nguyên tử, tránh đụng chỉ mục duy nhất uq_access_grant_active_user khi grant cũ hết hạn.
  const now = new Date();
  const validUntil = new Date(now.getTime() + 365 * 86400000);
  const runInTx = async (
    work: (tx: Parameters<Parameters<PrismaClient['$transaction']>[0]>[0]) => Promise<void>,
  ) => {
    if (typeof database.$transaction === 'function') {
      await database.$transaction(work);
    } else {
      await work(database as unknown as Parameters<Parameters<PrismaClient['$transaction']>[0]>[0]);
    }
  };

  await runInTx(async (tx) => {
    await tx.document.update({
      where: { id: documentId },
      data: { status: 'ACTIVE', version: { increment: 1 } },
    });

    if (tx.accessGrant?.findFirst && tx.accessGrant?.create) {
      const existingOwnerGrant = await tx.accessGrant.findFirst({
        where: {
          document_id: documentId,
          principal_type: 'USER',
          principal_user_id: doc.owner_id,
          status: 'ACTIVE',
        },
      });

      if (!existingOwnerGrant) {
        const allowDownload = activeClassification.classification_levels.allow_download;
        await tx.accessGrant.create({
          data: {
            id: randomUUID(),
            document_id: documentId,
            principal_type: 'USER',
            principal_user_id: doc.owner_id,
            source: 'DIRECT',
            status: 'ACTIVE',
            valid_from: now,
            valid_until: validUntil,
            granted_by: doc.owner_id,
            access_grant_permissions: {
              createMany: {
                data: [
                  { permission: 'VIEW' },
                  ...(allowDownload ? [{ permission: 'DOWNLOAD' as const }] : []),
                ],
              },
            },
          },
        });
      } else if (
        existingOwnerGrant.valid_until <= now &&
        typeof tx.accessGrant.update === 'function'
      ) {
        await tx.accessGrant.update({
          where: { id: existingOwnerGrant.id },
          data: { valid_from: now, valid_until: validUntil, version: { increment: 1 } },
        });
      }
    }
  });

  await audit.record(
    {
      action: 'DOCUMENT_ACTIVATED',
      outcome: 'SUCCESS',
      actorUserId: principal.userId,
      actorUsername: principal.username,
      documentId,
      details: {
        currentVersionId: doc.current_version.id.toString(),
        classificationLevel: activeClassification.classification_levels.code,
        businessCategory: activeClassification.business_categories.code,
      },
    },
    context,
  );
}

/**
 * Algorithm: Atomic Document Archival Freeze (`ACTIVE/DRAFT` -> `ARCHIVED`)
 * Transitions status to `ARCHIVED`, suspends active grants, terminates open sessions across versions, and flushes cache.
 */
export async function executeArchiveDocument(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  cache: AuthorizationCache;
  audit: DocumentAuditService;
  documentId: string;
  input: ArchiveDocumentInput;
  principal: AuthPrincipal;
  context: RequestContext;
}): Promise<void> {
  const { database, authorization, cache, audit, documentId, input, principal, context } = params;

  const doc = await database.document.findUnique({ where: { id: documentId } });
  if (!doc) {
    throw new NotFoundException({
      errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
      message: 'Document not found.',
    });
  }
  if (doc.status === 'ARCHIVED') {
    return;
  }

  await assertDocumentMutationPermission(authorization, doc, principal, 'ARCHIVE');

  const now = new Date();
  let suspendedGrantsCount = 0;
  let terminatedSessionsCount = 0;

  await database.$transaction(async (tx) => {
    await tx.document.update({
      where: { id: documentId },
      data: { status: 'ARCHIVED', archived_at: now, version: { increment: 1 } },
    });

    const grantsResult = await tx.accessGrant.updateMany({
      where: { document_id: documentId, status: 'ACTIVE' },
      data: {
        status: 'SUSPENDED',
        revoke_reason: input.reason ?? 'Document archived',
      },
    });
    suspendedGrantsCount = grantsResult.count;

    const versions = await tx.documentVersion.findMany({
      where: { document_id: documentId },
      select: { id: true },
    });
    const versionIds = versions.map((v) => v.id);

    if (versionIds.length > 0) {
      const sessionsResult = await tx.accessSession.updateMany({
        where: { document_version_id: { in: versionIds }, status: 'ACTIVE' },
        data: { status: 'TERMINATED', ended_at: now, terminated_reason: 'Document archived' },
      });
      terminatedSessionsCount = sessionsResult.count;
    }
  });

  cache.invalidateAll();

  await audit.record(
    {
      action: 'DOCUMENT_ARCHIVED',
      outcome: 'SUCCESS',
      actorUserId: principal.userId,
      actorUsername: principal.username,
      documentId,
      details: {
        suspendedGrantsCount,
        terminatedSessionsCount,
        reason: input.reason ?? 'Document archived',
      },
    },
    context,
  );
}

/**
 * Module: Document Lifecycle State Machine Transitions (`DRAFT` -> `ACTIVE` -> `ARCHIVED`)
 * Thuật toán: Chuyển Trạng Thái Vòng Đời 5 Bất Biến Kèm Cấp Phát Quyền Chủ Sở Hữu & Phong Tỏa Lưu Trữ Nguyên Tử.
 */
import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode, type ArchiveDocumentInput } from '@sda/contracts';
import { resolveRetentionCeilingUtc } from '../access-grants/grant-retention-bounds.helper.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationCache } from '../rbac/authorization-cache.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { RealtimeEventsService } from '../realtime/realtime-events.service.js';
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

  if (!doc || doc.status === 'DELETED') {
    throw new NotFoundException({
      errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
      message: 'Document not found.',
    });
  }

  await assertDocumentMutationPermission(authorization, doc, principal, 'ACTIVATE', { database });

  if (doc.status === 'ACTIVE') {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ALREADY_ACTIVE,
      message: 'Document is already active.',
    });
  }
  if (doc.status === 'ARCHIVED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
      message: 'Archived or deleted document cannot be activated.',
    });
  }

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

  // CONFLICT-RESOLVED: Bọc kích hoạt tài liệu và khởi tạo/gia hạn owner grant trong giao dịch nguyên tử, đồng thời kẹp trần `retention_until` và từ chối kích hoạt khi hạn lưu trữ đã qua (MED-05).
  const now = new Date();
  const retentionCeiling = resolveRetentionCeilingUtc(doc.retention_until);
  if (retentionCeiling && retentionCeiling.getTime() <= now.getTime()) {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ACTIVATION_FAILED,
      message: 'Cannot activate document whose retention horizon has already expired.',
    });
  }
  const defaultValidUntil = new Date(now.getTime() + 365 * 86400000);
  const validUntil =
    retentionCeiling && retentionCeiling.getTime() < defaultValidUntil.getTime()
      ? retentionCeiling
      : defaultValidUntil;
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
    // Thuật toán: Kích hoạt nguyên tử Compare-And-Swap trên `(id, status = 'DRAFT', version = doc.version)` chống kích hoạt kép đồng thời (BUG-123).
    if (typeof tx.document.updateMany === 'function') {
      const activated = await tx.document.updateMany({
        where: { id: documentId, status: 'DRAFT', version: doc.version },
        data: { status: 'ACTIVE', version: { increment: 1 } },
      });
      if (activated.count === 0) {
        throw new ConflictException({
          errorCode: AppErrorCode.RESOURCE_CONFLICT,
          message: 'Document status or version was modified concurrently; activation aborted.',
        });
      }
    } else {
      await tx.document.update({
        where: { id: documentId },
        data: { status: 'ACTIVE', version: { increment: 1 } },
      });
    }

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
  realtime?: RealtimeEventsService | undefined;
  documentId: string;
  input: ArchiveDocumentInput;
  principal: AuthPrincipal;
  context: RequestContext;
}): Promise<void> {
  const { database, authorization, cache, audit, realtime, documentId, input, principal, context } =
    params;

  const doc = await database.document.findUnique({ where: { id: documentId } });
  if (!doc || doc.status === 'DELETED') {
    throw new NotFoundException({
      errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
      message: 'Document not found.',
    });
  }

  await assertDocumentMutationPermission(authorization, doc, principal, 'ARCHIVE', { database });

  if (doc.status === 'ARCHIVED') {
    return;
  }

  const now = new Date();
  let suspendedGrantsCount = 0;
  let terminatedSessionsCount = 0;
  const affectedUserIds = new Set<string>([principal.userId.toString(), doc.owner_id.toString()]);
  const sessionUserIds = new Set<string>();
  const terminatedSessionIds: string[] = [];
  const affectedRoleIds = new Set<bigint>();

  await database.$transaction(async (tx) => {
    if (typeof tx.accessGrant?.findMany === 'function') {
      const priorActiveGrants = await tx.accessGrant.findMany({
        where: { document_id: documentId, status: 'ACTIVE' },
        select: { principal_type: true, principal_user_id: true, principal_role_id: true },
      });
      for (const grant of priorActiveGrants) {
        if (grant.principal_user_id) affectedUserIds.add(grant.principal_user_id.toString());
        if (grant.principal_type === 'ROLE' && grant.principal_role_id) {
          affectedRoleIds.add(grant.principal_role_id);
        }
      }
    }

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
      if (typeof tx.accessSession?.findMany === 'function') {
        const openSessions = await tx.accessSession.findMany({
          where: { document_version_id: { in: versionIds }, status: 'ACTIVE' },
          select: { id: true, user_id: true },
        });
        for (const sess of openSessions) {
          terminatedSessionIds.push(sess.id);
          if (sess.user_id !== undefined && sess.user_id !== null) {
            const uid = sess.user_id.toString();
            sessionUserIds.add(uid);
            affectedUserIds.add(uid);
          }
        }
      }
      const sessionsResult = await tx.accessSession.updateMany({
        where: { document_version_id: { in: versionIds }, status: 'ACTIVE' },
        data: { status: 'TERMINATED', ended_at: now, terminated_reason: 'Document archived' },
      });
      terminatedSessionsCount = sessionsResult.count;
    }
  });

  await cache.invalidateAll();

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

  // Thuật toán: Sau khi giao dịch lưu trữ commit thành công, phát sự kiện SSE thời gian thực tới chủ sở hữu và người giữ quyền để làm mới ngay danh sách quyền/tài liệu (BUG-099).
  if (realtime) {
    if (affectedRoleIds.size > 0 && typeof database.userRole?.findMany === 'function') {
      const holders = await database.userRole
        .findMany({
          where: {
            role_id: { in: [...affectedRoleIds] },
            valid_from: { lte: now },
            OR: [{ valid_to: null }, { valid_to: { gt: now } }],
          },
          select: { user_id: true },
          take: 200,
        })
        .catch(() => []);
      for (const h of holders) affectedUserIds.add(h.user_id.toString());
    }
    const targetUserIds = [...affectedUserIds];
    const hasRoleGrant = affectedRoleIds.size > 0;
    realtime.publish({
      type: 'ACCESS_GRANT_UPDATED',
      targetUserIds,
      ...(hasRoleGrant ? { targetRoles: ['DOCUMENT_READER'] } : {}),
      payload: {
        documentId,
        status: 'SUSPENDED',
        action: 'REVOKED',
        reason: 'DOCUMENT_ARCHIVED',
        suspendedGrantsCount,
        terminatedSessionIds,
      },
    });
    realtime.publish({
      type: 'DOCUMENT_UPDATED',
      targetUserIds,
      ...(hasRoleGrant ? { targetRoles: ['DOCUMENT_READER'] } : {}),
      payload: {
        id: documentId,
        documentId,
        status: 'ARCHIVED',
        action: 'ARCHIVED',
      },
    });
    if (terminatedSessionsCount > 0) {
      realtime.publish({
        type: 'ACCESS_SESSION_UPDATED',
        targetRoles: ['SECURITY_OFFICER'],
        targetDepartmentId: doc.department_id?.toString() ?? null,
        ...(sessionUserIds.size > 0 ? { targetUserIds: [...sessionUserIds] } : {}),
        payload: {
          documentId,
          terminatedSessions: terminatedSessionsCount,
          terminatedSessionIds,
          status: 'TERMINATED',
          action: 'TERMINATED',
          reason: 'DOCUMENT_ARCHIVED',
        },
      });
    }
  }
}

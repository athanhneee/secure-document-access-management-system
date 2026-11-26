/**
 * Module: SCD Type 2 Document Classification & History Helper
 * Thuật toán: Khóa Dòng `SELECT ... FOR UPDATE`, Lịch Sử Phân Loại SCD Type 2 & Thu Hồi Dây Chuyền Khi Tăng Bậc Độ Mật.
 */
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode, type ReclassifyDocumentInput } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AuthorizationCache } from '../rbac/authorization-cache.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { RealtimeEventsService } from '../realtime/realtime-events.service.js';
import type { DocumentAuditService } from './document-audit.service.js';
import {
  assertDocumentMutationPermission,
  assertDocumentReadAccess,
  getUserClearanceRank,
} from './document-access-guard.helper.js';
import {
  cascadeRevokeOnRankIncrease,
  stripForbiddenDownloadPermissions,
} from './document-classification-cascade.helper.js';
import type { ClassificationHistoryItem } from './documents.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm: SCD Type 2 Reclassification Transaction
 */
export async function executeReclassifyDocument(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  cache: AuthorizationCache;
  audit: DocumentAuditService;
  realtime?: RealtimeEventsService | undefined;
  documentId: string;
  input: ReclassifyDocumentInput;
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

  await assertDocumentMutationPermission(authorization, doc, principal, 'CLASSIFY', { database });

  if (doc.status === 'ARCHIVED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
      message: 'Cannot reclassify an archived or deleted document.',
    });
  }

  const targetLevel = await database.classificationLevel.findUnique({
    where: { id: input.classificationLevelId },
  });
  if (!targetLevel || !targetLevel.is_active) {
    throw new BadRequestException({
      errorCode: AppErrorCode.VALIDATION_FAILED,
      message: 'Target classification level does not exist or is inactive.',
    });
  }

  const targetCategory = await database.businessCategory.findUnique({
    where: { id: input.businessCategoryId },
  });
  if (!targetCategory || !targetCategory.is_active) {
    throw new BadRequestException({
      errorCode: AppErrorCode.VALIDATION_FAILED,
      message: 'Target business category does not exist or is inactive.',
    });
  }

  const now = new Date();
  let oldRank = 0;
  const newRank = targetLevel.rank;
  let isLevelIncrease = false;
  let revokedGrantsCount = 0;
  let terminatedSessionsCount = 0;
  const affectedUserIds = new Set<string>([principal.userId.toString(), doc.owner_id.toString()]);
  const affectedRoleIds = new Set<bigint>();
  let usersToInvalidateAfterCommit: bigint[] = [];

  await database.$transaction(async (tx) => {
    if (typeof tx.accessGrant?.findMany === 'function') {
      const priorActiveGrants = await tx.accessGrant.findMany({
        where: { document_id: documentId, status: 'ACTIVE' },
      });
      for (const g of priorActiveGrants) {
        if (g.principal_user_id) affectedUserIds.add(g.principal_user_id.toString());
        if (g.principal_type === 'ROLE' && g.principal_role_id) {
          affectedRoleIds.add(g.principal_role_id);
        }
      }
    }
    if (
      typeof (tx as unknown as { $executeRawUnsafe?: unknown }).$executeRawUnsafe === 'function'
    ) {
      await (
        tx as unknown as {
          $executeRawUnsafe: (sql: string, ...args: unknown[]) => Promise<unknown>;
        }
      ).$executeRawUnsafe('SELECT id FROM documents WHERE id = $1::uuid FOR UPDATE', documentId);
    }

    const current = await tx.documentClassificationHistory.findFirst({
      where: { document_id: documentId, effective_to: null },
      include: { classification_levels: true },
    });

    if (current) {
      oldRank = current.classification_levels.rank;
      isLevelIncrease = newRank > oldRank;
    }

    // CONFLICT-RESOLVED: Cưỡng chế bất biến thống trị độ mật Bell-LaPadula (actorClearanceRank >= max(oldRank, newRank)) trước khi nâng/hạ phân loại tài liệu.
    const clearanceSource =
      typeof (tx as unknown as PrismaClient)?.userAttributeAssignment?.findFirst === 'function'
        ? (tx as unknown as PrismaClient)
        : database;
    const actorClearanceRank = await getUserClearanceRank(clearanceSource, principal.userId, now);
    const requiredClearanceRank = Math.max(oldRank, newRank);
    if (actorClearanceRank < requiredClearanceRank) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
        message: `Insufficient clearance level (${actorClearanceRank}) to reclassify document between rank ${oldRank} and rank ${newRank}.`,
      });
    }

    if (current) {
      await tx.documentClassificationHistory.update({
        where: { id: current.id },
        data: { effective_to: now },
      });
    }

    await tx.documentClassificationHistory.create({
      data: {
        document_id: documentId,
        classification_level_id: targetLevel.id,
        business_category_id: targetCategory.id,
        reason: input.reason,
        classified_by: principal.userId,
        effective_from: now,
        effective_to: null,
      },
    });

    if (isLevelIncrease) {
      const cascaded = await cascadeRevokeOnRankIncrease({
        tx,
        cache,
        documentId,
        newRank,
        actorUserId: principal.userId,
        now,
        deferCacheInvalidation: true,
      });
      revokedGrantsCount = cascaded.revokedGrantsCount;
      terminatedSessionsCount = cascaded.terminatedSessionsCount;
      usersToInvalidateAfterCommit = cascaded.affectedUserIdsToInvalidate;
    }

    if (targetLevel.allow_download === false) {
      const stripped = await stripForbiddenDownloadPermissions(
        tx,
        documentId,
        principal.userId,
        now,
      );
      revokedGrantsCount += stripped.revokedEmptyGrantsCount;
      terminatedSessionsCount += stripped.terminatedSessionsCount;
    }
  });

  if (usersToInvalidateAfterCommit.length > 0) {
    await Promise.all(usersToInvalidateAfterCommit.map((uid) => cache.invalidateUser(uid)));
  }

  await audit.record(
    {
      action: 'DOCUMENT_RECLASSIFIED',
      outcome: 'SUCCESS',
      actorUserId: principal.userId,
      actorUsername: principal.username,
      documentId,
      details: {
        oldRank,
        newRank,
        targetLevelCode: targetLevel.code,
        targetCategoryCode: targetCategory.code,
        isLevelIncrease,
        revokedGrantsCount,
        terminatedSessionsCount,
        reason: input.reason,
      },
    },
    context,
  );

  // Thuật toán: Phát sự kiện SSE thời gian thực sau khi giao dịch tái phân loại commit để cập nhật ngay danh sách quyền/tài liệu của Owner và Reader (BUG-099).
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
        status: revokedGrantsCount > 0 ? 'REVOKED' : 'ACTIVE',
        action: revokedGrantsCount > 0 ? 'REVOKED' : 'UPDATED',
        reason: 'DOCUMENT_RECLASSIFIED',
        classificationLevelCode: targetLevel.code,
        allowDownload: targetLevel.allow_download,
        revokedGrantsCount,
      },
    });
    realtime.publish({
      type: 'DOCUMENT_UPDATED',
      targetUserIds,
      ...(hasRoleGrant ? { targetRoles: ['DOCUMENT_READER'] } : {}),
      payload: {
        id: documentId,
        documentId,
        classificationLevelCode: targetLevel.code,
        allowDownload: targetLevel.allow_download,
        action: 'RECLASSIFIED',
      },
    });
    if (terminatedSessionsCount > 0) {
      realtime.publish({
        type: 'ACCESS_SESSION_UPDATED',
        targetRoles: ['SECURITY_OFFICER'],
        targetDepartmentId: doc.department_id?.toString() ?? null,
        targetUserIds,
        payload: {
          documentId,
          terminatedSessions: terminatedSessionsCount,
          status: 'TERMINATED',
          action: 'TERMINATED',
          reason: 'DOCUMENT_RECLASSIFIED',
        },
      });
    }
  }
}

/**
 * Algorithm: Chronological SCD Type 2 Classification History Query
 */
export async function queryClassificationHistory(
  database: PrismaClient,
  authorization: AuthorizationService,
  documentId: string,
  principal?: AuthPrincipal,
): Promise<ClassificationHistoryItem[]> {
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

  const history = await database.documentClassificationHistory.findMany({
    where: { document_id: documentId },
    include: { classification_levels: true, business_categories: true },
    orderBy: { effective_from: 'asc' },
  });

  return history.map((item) => ({
    id: item.id.toString(),
    classificationLevelId: item.classification_level_id.toString(),
    classificationLevelCode: item.classification_levels.code,
    classificationLevelName: item.classification_levels.name,
    rank: item.classification_levels.rank,
    businessCategoryId: item.business_category_id.toString(),
    businessCategoryCode: item.business_categories.code,
    businessCategoryName: item.business_categories.name,
    reason: item.reason,
    classifiedBy: item.classified_by.toString(),
    effectiveFrom: item.effective_from.toISOString(),
    effectiveTo: item.effective_to ? item.effective_to.toISOString() : null,
  }));
}

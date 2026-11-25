/**
 * Module: Document Ownership Handover Helper
 * Thuật toán: Chuyển Giao Quyền Sở Hữu Tài Liệu Kiểm Định SoD & Độ Mật Bell-LaPadula Kèm Thu Hồi Quyền/Phiên Chủ Cũ.
 */
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode, type TransferDocumentOwnerInput } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { NotificationsService } from '../notifications/notifications.service.js';
import type { AuthorizationCache } from '../rbac/authorization-cache.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import { PRIVILEGED_SEPARATION_ROLES } from '../rbac/permission-matrix.js';
import type { DocumentAuditService } from './document-audit.service.js';
import { assertDocumentMutationPermission } from './document-access-guard.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm: Clearance-Verified Document Ownership Handover
 * Validates active target user, SoD role exclusions, and `userRank >= documentRank`, then revokes former owner grants/sessions.
 */
export async function executeTransferDocumentOwner(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  cache: AuthorizationCache;
  audit: DocumentAuditService;
  notifications?: NotificationsService | undefined;
  documentId: string;
  input: TransferDocumentOwnerInput;
  principal: AuthPrincipal;
  context: RequestContext;
}): Promise<void> {
  const {
    database,
    authorization,
    cache,
    audit,
    notifications,
    documentId,
    input,
    principal,
    context,
  } = params;

  const doc = await database.document.findUnique({ where: { id: documentId } });
  if (!doc || doc.status === 'DELETED') {
    throw new NotFoundException({
      errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
      message: 'Document not found.',
    });
  }

  await assertDocumentMutationPermission(authorization, doc, principal, 'TRANSFER_OWNER', {
    database,
  });

  if (doc.status === 'ARCHIVED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
      message: 'Cannot transfer ownership of an archived or deleted document.',
    });
  }

  const targetUser = await database.user.findUnique({ where: { id: input.newOwnerId } });
  if (!targetUser || targetUser.status !== 'ACTIVE') {
    throw new BadRequestException({
      errorCode: AppErrorCode.VALIDATION_FAILED,
      message: 'Target user does not exist or is not active.',
    });
  }

  const currentClassification = await database.documentClassificationHistory.findFirst({
    where: { document_id: documentId, effective_to: null },
    include: { classification_levels: true },
  });
  const documentRank = currentClassification?.classification_levels?.rank ?? 0;

  const now = new Date();
  if (typeof database.userRole?.findMany === 'function') {
    const targetUserRoles = await database.userRole.findMany({
      where: {
        user_id: input.newOwnerId,
        valid_from: { lte: now },
        OR: [{ valid_to: null }, { valid_to: { gt: now } }],
        roles: { is_active: true },
      },
      include: { roles: { select: { code: true } } },
    });
    const roleCodes = targetUserRoles
      .map((r) => (r as { roles?: { code?: string } }).roles?.code)
      .filter((c): c is string => typeof c === 'string');
    // CONFLICT-RESOLVED: Unconditionally block ownership transfer to PRIVILEGED_SEPARATION_ROLES (including SECURITY_OFFICER) and enforce active CLEARANCE_LEVEL.
    if (roleCodes.some((code) => PRIVILEGED_SEPARATION_ROLES.has(code))) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.TECHNICAL_ADMIN_CANNOT_OWN,
        message:
          'Separation of duties: cannot transfer document ownership to privileged administrative, security, or auditor accounts.',
      });
    }
  }

  const clearanceAssignment = await database.userAttributeAssignment.findFirst({
    where: {
      user_id: input.newOwnerId,
      attribute_definitions: { code: 'CLEARANCE_LEVEL', is_active: true },
      attribute_options: { is_active: true },
      valid_from: { lte: now },
      OR: [{ valid_to: null }, { valid_to: { gt: now } }],
    },
    include: {
      attribute_definitions: { select: { is_active: true } },
      attribute_options: true,
    },
    orderBy: { attribute_options: { numeric_rank: 'desc' } },
  });
  const userRank =
    (clearanceAssignment as { attribute_definitions?: { is_active?: boolean } } | null)
      ?.attribute_definitions?.is_active === false ||
    clearanceAssignment?.attribute_options?.is_active === false
      ? 0
      : (clearanceAssignment?.attribute_options?.numeric_rank ?? 0);
  if (userRank < documentRank) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.GRANT_CLEARANCE_INSUFFICIENT,
      message: 'New owner clearance level is insufficient for this document classification.',
    });
  }

  const previousOwnerId = doc.owner_id;
  await database.document.update({
    where: { id: documentId },
    data: { owner_id: input.newOwnerId, version: { increment: 1 } },
  });

  if (
    previousOwnerId !== input.newOwnerId &&
    typeof database.accessGrant?.findMany === 'function' &&
    typeof database.accessGrant?.update === 'function'
  ) {
    const activeGrants = await database.accessGrant.findMany({
      where: { document_id: documentId, status: 'ACTIVE' },
    });
    for (const grant of activeGrants) {
      if (grant.principal_type === 'USER' && grant.principal_user_id === previousOwnerId) {
        await database.accessGrant.update({
          where: { id: grant.id },
          data: {
            status: 'REVOKED',
            revoked_by: principal.userId,
            revoked_at: now,
            revoke_reason: 'Document ownership transferred',
            version: { increment: 1 },
          },
        });
        if (typeof database.accessSession?.updateMany === 'function') {
          await database.accessSession.updateMany({
            where: { access_grant_id: grant.id, status: 'ACTIVE' },
            data: {
              status: 'TERMINATED',
              ended_at: now,
              terminated_reason: 'Document ownership transferred',
            },
          });
        }
      }
    }
  }

  await audit.record(
    {
      action: 'DOCUMENT_OWNER_TRANSFERRED',
      outcome: 'SUCCESS',
      actorUserId: principal.userId,
      actorUsername: principal.username,
      documentId,
      details: {
        previousOwnerId: previousOwnerId.toString(),
        newOwnerId: input.newOwnerId.toString(),
        reason: input.reason,
      },
    },
    context,
  );

  cache.invalidateUser(previousOwnerId);
  cache.invalidateUser(input.newOwnerId);

  if (notifications && previousOwnerId !== input.newOwnerId) {
    const docLabel = doc.title
      ? `"${doc.title}"${doc.document_code ? ` (${doc.document_code})` : ''}`
      : documentId;
    const reasonSuffix = input.reason?.trim() ? ` Lý do: ${input.reason.trim()}` : '';
    const nextVersion = (doc.version ?? 0) + 1;

    if (input.newOwnerId !== principal.userId) {
      try {
        await notifications.sendNotification({
          recipientId: input.newOwnerId,
          notificationType: 'DOCUMENT_OWNERSHIP_TRANSFERRED',
          title: 'Bạn vừa được chuyển giao quyền sở hữu tài liệu',
          body: `Tài liệu ${docLabel} đã được chuyển quyền sở hữu sang tài khoản của bạn.${reasonSuffix}`,
          relatedObjectType: 'DOCUMENT',
          relatedObjectId: documentId,
          deduplicationKey: `DOCUMENT_OWNERSHIP_TRANSFERRED:${input.newOwnerId.toString()}:${documentId}:v${nextVersion}`,
          payload: {
            documentId,
            documentCode: doc.document_code ?? null,
            previousOwnerId: previousOwnerId.toString(),
            newOwnerId: input.newOwnerId.toString(),
          },
        });
      } catch {
        // Non-fatal post-commit notification dispatch
      }
    }

    if (previousOwnerId !== principal.userId) {
      try {
        await notifications.sendNotification({
          recipientId: previousOwnerId,
          notificationType: 'DOCUMENT_OWNERSHIP_TRANSFERRED',
          title: 'Quyền sở hữu tài liệu của bạn đã được chuyển giao',
          body: `Quyền sở hữu đối với tài liệu ${docLabel} đã được chuyển sang chủ sở hữu mới.${reasonSuffix}`,
          relatedObjectType: 'DOCUMENT',
          relatedObjectId: documentId,
          deduplicationKey: `DOCUMENT_OWNERSHIP_TRANSFERRED:${previousOwnerId.toString()}:${documentId}:v${nextVersion}`,
          payload: {
            documentId,
            documentCode: doc.document_code ?? null,
            previousOwnerId: previousOwnerId.toString(),
            newOwnerId: input.newOwnerId.toString(),
          },
        });
      } catch {
        // Non-fatal post-commit notification dispatch
      }
    }
  }
}

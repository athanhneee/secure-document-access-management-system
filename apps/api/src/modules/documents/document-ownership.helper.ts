/**
 * Module: Document Ownership Handover Helper
 * Algorithm: Enforces Separation of Duties (SoD) and Bell-LaPadula clearance (`userRank >= documentRank`)
 *   on target owners while revoking prior owner grants/sessions and invalidating RBAC caches.
 */
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode, type TransferDocumentOwnerInput } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
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
  documentId: string;
  input: TransferDocumentOwnerInput;
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
  if (doc.status === 'ARCHIVED' || doc.status === 'DELETED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
      message: 'Cannot transfer ownership of an archived or deleted document.',
    });
  }

  await assertDocumentMutationPermission(authorization, doc, principal);

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
}

/**
 * Module: Cascading Bell-LaPadula Grant & Session Revocation Helper
 * Algorithm: Re-evaluates active `USER` and `ROLE` grants when confidentiality rank increases,
 *   revoking under-cleared grants, terminating active sessions, invalidating caches, and stripping `DOWNLOAD`.
 */
import type { getDatabaseClient } from '@sda/database';
import type { AuthorizationCache } from '../rbac/authorization-cache.js';

type PrismaTransaction = Parameters<
  Parameters<ReturnType<typeof getDatabaseClient>['$transaction']>[0]
>[0];

/**
 * Algorithm: Cascading Bell-LaPadula Clearance Re-Evaluation on Confidentiality Upgrade
 */
export async function cascadeRevokeOnRankIncrease(params: {
  tx: PrismaTransaction;
  cache: AuthorizationCache;
  documentId: string;
  newRank: number;
  actorUserId: bigint;
  now: Date;
}): Promise<{ revokedGrantsCount: number; terminatedSessionsCount: number }> {
  const { tx, cache, documentId, newRank, actorUserId, now } = params;
  let revokedGrantsCount = 0;
  let terminatedSessionsCount = 0;

  const activeGrants = await tx.accessGrant.findMany({
    where: { document_id: documentId, status: 'ACTIVE' },
  });

  for (const grant of activeGrants) {
    if (grant.principal_type === 'USER' && grant.principal_user_id) {
      const clearanceAssignment = await tx.userAttributeAssignment.findFirst({
        where: {
          user_id: grant.principal_user_id,
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

      if (userRank < newRank) {
        await tx.accessGrant.update({
          where: { id: grant.id },
          data: {
            status: 'REVOKED',
            revoked_by: actorUserId,
            revoked_at: now,
            revoke_reason:
              'Reclassification to higher confidentiality level: user clearance insufficient',
            version: { increment: 1 },
          },
        });
        revokedGrantsCount++;

        const terminatedSessions = await tx.accessSession.updateMany({
          where: { access_grant_id: grant.id, status: 'ACTIVE' },
          data: {
            status: 'TERMINATED',
            ended_at: now,
            terminated_reason:
              'Document reclassified to higher level: clearance no longer sufficient',
          },
        });
        terminatedSessionsCount += terminatedSessions.count;
        cache.invalidateUser(grant.principal_user_id);
      }
    } else if (grant.principal_type === 'ROLE') {
      const roleSessions = await tx.accessSession.findMany({
        where: { access_grant_id: grant.id, status: 'ACTIVE' },
      });

      for (const sess of roleSessions) {
        const sessionUserClearance = await tx.userAttributeAssignment.findFirst({
          where: {
            user_id: sess.user_id,
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
        const sessRank =
          (sessionUserClearance as { attribute_definitions?: { is_active?: boolean } } | null)
            ?.attribute_definitions?.is_active === false ||
          sessionUserClearance?.attribute_options?.is_active === false
            ? 0
            : (sessionUserClearance?.attribute_options?.numeric_rank ?? 0);
        if (sessRank < newRank) {
          await tx.accessSession.update({
            where: { id: sess.id },
            data: {
              status: 'TERMINATED',
              ended_at: now,
              terminated_reason:
                'Document reclassified to higher level: role member clearance insufficient',
            },
          });
          terminatedSessionsCount++;
          cache.invalidateUser(sess.user_id);
        }
      }
    }
  }

  return { revokedGrantsCount, terminatedSessionsCount };
}

/**
 * Algorithm: Classification Download Prohibition Stripper
 */
export async function stripForbiddenDownloadPermissions(
  tx: PrismaTransaction,
  documentId: string,
): Promise<void> {
  if (
    typeof (tx as { accessGrantPermission?: { deleteMany?: unknown } }).accessGrantPermission
      ?.deleteMany !== 'function'
  ) {
    return;
  }
  const remainingActiveGrants = await tx.accessGrant.findMany({
    where: { document_id: documentId, status: 'ACTIVE' },
  });
  const grantIds = remainingActiveGrants.map((g) => g.id);
  if (grantIds.length > 0) {
    await tx.accessGrantPermission.deleteMany({
      where: { access_grant_id: { in: grantIds }, permission: 'DOWNLOAD' },
    });
  }
}

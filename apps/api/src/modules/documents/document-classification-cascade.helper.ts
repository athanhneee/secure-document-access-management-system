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
 * Thuật toán: Tước quyền `DOWNLOAD` bị cấm bởi cấp độ mật và thu hồi dây chuyền grant rỗng quyền.
 * Cơ chế hoạt động:
 *   1. Xóa mọi bản ghi `DOWNLOAD` trên các grant `ACTIVE` của tài liệu khi `allow_download === false`.
 *   2. Kiểm tra lại các grant vừa bị tác động: nếu số quyền còn lại bằng `0` (`access_grant_permissions`),
 *      chuyển grant sang `REVOKED` và đóng toàn bộ phiên `ACTIVE` (`TERMINATED`) để không tồn tại grant rỗng.
 */
export async function stripForbiddenDownloadPermissions(
  tx: PrismaTransaction,
  documentId: string,
  actorUserId?: bigint,
  now: Date = new Date(),
): Promise<{ revokedEmptyGrantsCount: number; terminatedSessionsCount: number }> {
  if (
    typeof (tx as { accessGrantPermission?: { deleteMany?: unknown } }).accessGrantPermission
      ?.deleteMany !== 'function'
  ) {
    return { revokedEmptyGrantsCount: 0, terminatedSessionsCount: 0 };
  }
  const remainingActiveGrants = await tx.accessGrant.findMany({
    where: { document_id: documentId, status: 'ACTIVE' },
  });
  const grantIds = remainingActiveGrants.map((g) => g.id);
  if (grantIds.length === 0) {
    return { revokedEmptyGrantsCount: 0, terminatedSessionsCount: 0 };
  }

  let affectedGrantIds: string[] = [];
  const hasPermFindMany =
    typeof (tx as { accessGrantPermission?: { findMany?: unknown } }).accessGrantPermission
      ?.findMany === 'function';
  if (hasPermFindMany) {
    const downloadRows = await tx.accessGrantPermission.findMany({
      where: { access_grant_id: { in: grantIds }, permission: 'DOWNLOAD' },
      select: { access_grant_id: true },
    });
    affectedGrantIds = [...new Set(downloadRows.map((r) => r.access_grant_id))];
  }

  await tx.accessGrantPermission.deleteMany({
    where: { access_grant_id: { in: grantIds }, permission: 'DOWNLOAD' },
  });

  let revokedEmptyGrantsCount = 0;
  let terminatedSessionsCount = 0;
  if (hasPermFindMany && affectedGrantIds.length > 0) {
    // CONFLICT-RESOLVED: Thu hồi ngay các grant ACTIVE chỉ có quyền DOWNLOAD sau khi bị tước quyền để tránh bản ghi mồ côi 0 quyền.
    const survivingPerms = await tx.accessGrantPermission.findMany({
      where: { access_grant_id: { in: affectedGrantIds } },
      select: { access_grant_id: true },
    });
    const survivingGrantSet = new Set(survivingPerms.map((p) => p.access_grant_id));
    for (const emptyGrantId of affectedGrantIds) {
      if (survivingGrantSet.has(emptyGrantId)) continue;
      if (typeof tx.accessGrant.update === 'function') {
        await tx.accessGrant.update({
          where: { id: emptyGrantId },
          data: {
            status: 'REVOKED',
            ...(actorUserId !== undefined ? { revoked_by: actorUserId } : {}),
            revoked_at: now,
            revoke_reason:
              'Reclassification forbids download and grant has no remaining permissions',
            version: { increment: 1 },
          },
        });
        revokedEmptyGrantsCount += 1;
      }
      if (typeof tx.accessSession?.updateMany === 'function') {
        const terminated = await tx.accessSession.updateMany({
          where: { access_grant_id: emptyGrantId, status: 'ACTIVE' },
          data: {
            status: 'TERMINATED',
            ended_at: now,
            terminated_reason: 'Grant revoked because classification forbids download',
          },
        });
        terminatedSessionsCount += terminated.count;
      }
    }
  }

  return { revokedEmptyGrantsCount, terminatedSessionsCount };
}

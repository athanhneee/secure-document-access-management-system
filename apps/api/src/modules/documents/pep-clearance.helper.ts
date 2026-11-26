/**
 * Module: PEP Bell-LaPadula Clearance & Three-Tier Grant Resolution Helper
 * Thuật toán: Kiểm Định Trần Độ Mật Bell-LaPadula Chỉ Đọc & Cấp Phát Hậu-PERMIT Ba Tầng (`USER`, `ROLE`, `OWNER`) (`BUG-054`).
 *   1. Kiểm tra bất biến "No Read Up" (`userClearanceRank >= documentRank`) trên mọi đường dẫn mở phiên (bao gồm cả `grantId` tường minh và chủ sở hữu).
 *   2. Tách bước thẩm định điều kiện đủ của Owner thành bước chỉ đọc trước khi đánh giá ABAC PDP + nghĩa vụ, tránh ghi rác CSDL khi bị PDP từ chối.
 *   3. Chỉ khi ABAC PERMIT mới cấp phát/cập nhật grant tự động cho Owner (`source: 'SYSTEM'`, kẹp trần `retention_until`, điền đủ `revoked_by`/`revoked_at`/`revoke_reason` thỏa `CHECK 23514`, khóa tư vấn `(documentId, userId)` + `skipDuplicates` chống `P2002`).
 */
import { ForbiddenException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AccessGrantsService } from '../access-grants/access-grants.service.js';
import {
  isDocumentDepartmentWithinRoleScope,
  loadActiveUserRoleScopes,
} from '../access-grants/grant-role-visibility.helper.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Truy vấn thứ bậc độ mật `CLEARANCE_LEVEL` còn hiệu lực cao nhất của người dùng và đối chiếu `rank >= documentRank`.
 */
export async function checkUserClearance(
  database: PrismaClient,
  userId: bigint,
  documentRank: number,
  now: Date,
): Promise<boolean> {
  if (documentRank <= 0) return true;
  if (typeof database?.userAttributeAssignment?.findFirst !== 'function') return false;
  const clearance = await database.userAttributeAssignment.findFirst({
    where: {
      user_id: userId,
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

  const rank =
    (clearance as { attribute_definitions?: { is_active?: boolean } } | null)?.attribute_definitions
      ?.is_active === false || clearance?.attribute_options?.is_active === false
      ? 0
      : (clearance?.attribute_options?.numeric_rank ?? 0);
  return rank >= documentRank;
}

interface ReadOnlyGrantResolution {
  grantId: string | null;
  grantPermissions: string[];
  pendingOwnerGrantProvision: boolean;
}

/**
 * Thuật toán: Phân giải chỉ đọc quyền cấp phát ba tầng (`USER` -> `ROLE` -> `OWNER` precheck) không ghi CSDL trước khi chạy PDP (`BUG-054`).
 */
async function resolveEligibleGrantReadOnly(params: {
  database: PrismaClient;
  authorization?: AuthorizationService | undefined;
  documentId: string;
  documentDepartmentId?: bigint | null | undefined;
  userId: bigint;
  action: 'VIEW' | 'DOWNLOAD';
  now: Date;
  documentRank: number;
  isOwner?: boolean;
  classAllowDownload?: boolean;
  documentRetentionUntil?: Date | null | undefined;
}): Promise<ReadOnlyGrantResolution | null> {
  const {
    database,
    authorization,
    documentId,
    documentDepartmentId,
    userId,
    action,
    now,
    documentRank,
    isOwner = false,
    classAllowDownload = true,
    documentRetentionUntil,
  } = params;

  const directGrant = await database.accessGrant.findFirst({
    where: {
      document_id: documentId,
      principal_type: 'USER',
      principal_user_id: userId,
      status: 'ACTIVE',
      valid_from: { lte: now },
      valid_until: { gt: now },
      access_grant_permissions: { some: { permission: action } },
    },
    include: { access_grant_permissions: true },
  });

  if (directGrant && (await checkUserClearance(database, userId, documentRank, now))) {
    const grantPermissions = Array.isArray(directGrant.access_grant_permissions)
      ? directGrant.access_grant_permissions.map((p) => p.permission)
      : action === 'DOWNLOAD'
        ? ['VIEW', 'DOWNLOAD']
        : ['VIEW'];
    return {
      grantId: directGrant.id,
      grantPermissions,
      pendingOwnerGrantProvision: false,
    };
  }

  const activeRoleScopes = await loadActiveUserRoleScopes(database, userId, now);
  const eligibleRoleIds: bigint[] = [];
  const checkedRoleIds = new Set<bigint>();
  for (const assignment of activeRoleScopes) {
    if (checkedRoleIds.has(assignment.roleId)) continue;
    if (
      await isDocumentDepartmentWithinRoleScope(
        database,
        authorization,
        documentDepartmentId,
        assignment.scopeDepartmentId,
      )
    ) {
      checkedRoleIds.add(assignment.roleId);
      eligibleRoleIds.push(assignment.roleId);
    }
  }

  if (eligibleRoleIds.length > 0) {
    const roleGrant = await database.accessGrant.findFirst({
      where: {
        document_id: documentId,
        principal_type: 'ROLE',
        principal_role_id: { in: eligibleRoleIds },
        status: 'ACTIVE',
        valid_from: { lte: now },
        valid_until: { gt: now },
        access_grant_permissions: { some: { permission: action } },
      },
      include: { access_grant_permissions: true },
    });
    if (roleGrant && (await checkUserClearance(database, userId, documentRank, now))) {
      const grantPermissions = Array.isArray(roleGrant.access_grant_permissions)
        ? roleGrant.access_grant_permissions.map((p) => p.permission)
        : action === 'DOWNLOAD'
          ? ['VIEW', 'DOWNLOAD']
          : ['VIEW'];
      return {
        grantId: roleGrant.id,
        grantPermissions,
        pendingOwnerGrantProvision: false,
      };
    }
  }

  if (isOwner) {
    if (!(await checkUserClearance(database, userId, documentRank, now))) return null;
    if (action === 'DOWNLOAD' && !classAllowDownload) return null;
    if (documentRetentionUntil && documentRetentionUntil <= now) return null;

    const existingOwnerGrant = await database.accessGrant.findFirst({
      where: {
        document_id: documentId,
        principal_type: 'USER',
        principal_user_id: userId,
        status: 'ACTIVE',
        valid_from: { lte: now },
        valid_until: { gt: now },
      },
      include: { access_grant_permissions: true },
    });

    const targetPerms = classAllowDownload ? ['VIEW', 'DOWNLOAD'] : ['VIEW'];
    if (existingOwnerGrant) {
      const perms = Array.isArray(existingOwnerGrant.access_grant_permissions)
        ? existingOwnerGrant.access_grant_permissions.map((p) => p.permission)
        : [];
      if (perms.includes(action)) {
        return {
          grantId: existingOwnerGrant.id,
          grantPermissions: targetPerms,
          pendingOwnerGrantProvision: false,
        };
      }
      return {
        grantId: existingOwnerGrant.id,
        grantPermissions: targetPerms,
        pendingOwnerGrantProvision: true,
      };
    }

    return {
      grantId: null,
      grantPermissions: targetPerms,
      pendingOwnerGrantProvision: true,
    };
  }

  return null;
}

/**
 * Thuật toán: Cấp phát hoặc nâng cấp nguyên tử `access_grants` tự động (`source: 'SYSTEM'`) cho chủ sở hữu sau khi ABAC PERMIT (`BUG-054`),
 * có khóa tư vấn `(documentId, userId)` + `skipDuplicates` chống `P2002`, kẹp trần `retention_until`, và điền đủ 3 cột thu hồi thỏa `CHECK 23514`.
 */
export async function ensurePermittedOwnerSystemGrant(params: {
  database: PrismaClient;
  documentId: string;
  userId: bigint;
  action: 'VIEW' | 'DOWNLOAD';
  now: Date;
  classAllowDownload: boolean;
  documentRetentionUntil?: Date | null | undefined;
}): Promise<string> {
  const { database, documentId, userId, action, now, classAllowDownload, documentRetentionUntil } =
    params;

  const runInScope = async (tx: PrismaClient): Promise<string> => {
    if (typeof tx.$executeRawUnsafe === 'function') {
      await tx.$executeRawUnsafe(
        'SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))',
        documentId,
        `owner-grant:${userId.toString()}`,
      );
    }

    const existingOwnerGrant = await tx.accessGrant.findFirst({
      where: {
        document_id: documentId,
        principal_type: 'USER',
        principal_user_id: userId,
        status: 'ACTIVE',
        valid_from: { lte: now },
        valid_until: { gt: now },
      },
      include: { access_grant_permissions: true },
    });

    if (existingOwnerGrant) {
      const perms = Array.isArray(existingOwnerGrant.access_grant_permissions)
        ? existingOwnerGrant.access_grant_permissions.map((p) => p.permission)
        : [];
      if (!perms.includes(action)) {
        if (typeof tx.accessGrantPermission?.createMany === 'function') {
          await tx.accessGrantPermission.createMany({
            data: [{ access_grant_id: existingOwnerGrant.id, permission: action }],
            skipDuplicates: true,
          });
        } else if (typeof tx.accessGrantPermission?.create === 'function') {
          try {
            await tx.accessGrantPermission.create({
              data: { access_grant_id: existingOwnerGrant.id, permission: action },
            });
          } catch (err: unknown) {
            const code = (err as { code?: string } | null)?.code;
            if (code !== 'P2002' && code !== '23505') throw err;
          }
        }
      }
      return existingOwnerGrant.id;
    }

    if (typeof tx.accessGrant?.findMany === 'function') {
      const staleGrants = await tx.accessGrant.findMany({
        where: {
          document_id: documentId,
          principal_type: 'USER',
          principal_user_id: userId,
          status: 'ACTIVE',
        },
        select: { id: true, valid_until: true },
      });
      for (const stale of staleGrants) {
        if (stale.valid_until <= now) {
          await tx.accessGrant.update({
            where: { id: stale.id },
            data: { status: 'EXPIRED', version: { increment: 1 } },
          });
        } else {
          await tx.accessGrant.update({
            where: { id: stale.id },
            data: {
              status: 'REVOKED',
              revoked_by: userId,
              revoked_at: now,
              revoke_reason: 'Superseded by active owner system grant',
              version: { increment: 1 },
            },
          });
        }
      }
    } else if (typeof tx.accessGrant?.update === 'function') {
      const staleOwnerGrant = await tx.accessGrant.findFirst({
        where: {
          document_id: documentId,
          principal_type: 'USER',
          principal_user_id: userId,
          status: 'ACTIVE',
        },
        select: { id: true, valid_until: true },
      });
      if (staleOwnerGrant) {
        await tx.accessGrant.update({
          where: { id: staleOwnerGrant.id },
          data:
            staleOwnerGrant.valid_until <= now
              ? { status: 'EXPIRED', version: { increment: 1 } }
              : {
                  status: 'REVOKED',
                  revoked_by: userId,
                  revoked_at: now,
                  revoke_reason: 'Superseded by active owner system grant',
                  version: { increment: 1 },
                },
        });
      }
    }

    const defaultValidUntil = new Date(now.getTime() + 365 * 86_400_000);
    let resolvedRetentionUntil = documentRetentionUntil;
    if (resolvedRetentionUntil === undefined && typeof tx.document?.findUnique === 'function') {
      const docRow = await tx.document.findUnique({
        where: { id: documentId },
        select: { retention_until: true },
      });
      resolvedRetentionUntil = docRow?.retention_until ?? null;
    }

    const clampedValidUntil =
      resolvedRetentionUntil && resolvedRetentionUntil < defaultValidUntil
        ? resolvedRetentionUntil
        : defaultValidUntil;
    if (clampedValidUntil <= now) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Document retention horizon has expired; cannot provision owner access session.',
      });
    }

    const grantId = randomUUID();
    const permissions: ('VIEW' | 'DOWNLOAD')[] = classAllowDownload
      ? ['VIEW', 'DOWNLOAD']
      : ['VIEW'];
    await tx.accessGrant.create({
      data: {
        id: grantId,
        document_id: documentId,
        principal_type: 'USER',
        principal_user_id: userId,
        source: 'SYSTEM',
        status: 'ACTIVE',
        valid_from: now,
        valid_until: clampedValidUntil,
        granted_by: userId,
        access_grant_permissions: {
          createMany: {
            data: permissions.map((p) => ({ permission: p })),
            skipDuplicates: true,
          },
        },
      },
    });
    return grantId;
  };

  if (typeof database?.$transaction === 'function') {
    return database.$transaction(async (tx) => runInScope(tx as unknown as PrismaClient));
  }
  return runInScope(database);
}

/**
 * Thuật toán: Phân giải quyền cấp phát hoạt động ba tầng (`USER` -> `ROLE` -> `OWNER`) có kiểm định độ mật Bell-LaPadula tại mọi tầng.
 */
export async function resolveEligibleGrant(params: {
  database: PrismaClient;
  authorization?: AuthorizationService | undefined;
  documentId: string;
  documentDepartmentId?: bigint | null | undefined;
  userId: bigint;
  action: 'VIEW' | 'DOWNLOAD';
  now: Date;
  documentRank: number;
  isOwner?: boolean;
  classAllowDownload?: boolean;
  documentRetentionUntil?: Date | null | undefined;
}): Promise<string | null> {
  const resolved = await resolveEligibleGrantReadOnly(params);
  if (!resolved) return null;
  if (resolved.pendingOwnerGrantProvision || !resolved.grantId) {
    return ensurePermittedOwnerSystemGrant({
      database: params.database,
      documentId: params.documentId,
      userId: params.userId,
      action: params.action,
      now: params.now,
      classAllowDownload: params.classAllowDownload ?? true,
      documentRetentionUntil: params.documentRetentionUntil,
    });
  }
  return resolved.grantId;
}

/**
 * Thuật toán: Cổng thẩm định chỉ đọc `grantId` tường minh hoặc tự động phân giải kèm kiểm tra độ mật và quyền tải xuống thực tế của grant (`BUG-054`).
 */
export async function verifyAndResolveEffectiveGrant(params: {
  database: PrismaClient;
  authorization?: AuthorizationService | undefined;
  grantsService: AccessGrantsService;
  documentId: string;
  documentDepartmentId?: bigint | null | undefined;
  requestedGrantId: string | undefined;
  userId: bigint;
  action: 'VIEW' | 'DOWNLOAD';
  now: Date;
  documentRank: number;
  isOwner: boolean;
  classAllowDownload: boolean;
  documentRetentionUntil?: Date | null | undefined;
  deny: (grantId: string | null, reasonCode: string, reasonMessage: string) => Promise<void>;
}): Promise<{
  effectiveGrantId: string | null;
  grantPermitsDownload: boolean;
  pendingOwnerGrantProvision: boolean;
}> {
  const {
    database,
    authorization,
    grantsService,
    documentId,
    documentDepartmentId,
    requestedGrantId,
    userId,
    action,
    now,
    documentRank,
    isOwner,
    classAllowDownload,
    documentRetentionUntil,
    deny,
  } = params;

  let effectiveGrantId: string | null = requestedGrantId ?? null;
  let grantPermissions: string[] = [];
  let pendingOwnerGrantProvision = false;

  if (effectiveGrantId) {
    const validated = await grantsService.assertGrantValidForAccess(
      effectiveGrantId,
      userId,
      action,
      now,
      documentId,
    );
    if (validated && validated.grant.document_id !== documentId) {
      await deny(
        effectiveGrantId,
        AppErrorCode.DOCUMENT_ACCESS_DENIED,
        'Provided grantId belongs to a different document.',
      );
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'Access grant does not belong to the requested document.',
      });
    }
    if (
      documentRank > 0 &&
      typeof database?.userAttributeAssignment?.findFirst === 'function' &&
      !(await checkUserClearance(database, userId, documentRank, now))
    ) {
      await deny(
        effectiveGrantId,
        AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
        'Caller clearance is lower than document rank.',
      );
      throw new ForbiddenException({
        errorCode: AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
        message: 'Caller security clearance is insufficient for this document classification.',
      });
    }
    if (Array.isArray((validated as { permissions?: string[] } | undefined)?.permissions)) {
      grantPermissions = (validated as { permissions: string[] }).permissions;
    } else if (!isOwner && typeof database?.accessGrant?.findUnique === 'function') {
      const grantRow = await database.accessGrant.findUnique({
        where: { id: effectiveGrantId },
        include: { access_grant_permissions: true },
      });
      if (Array.isArray(grantRow?.access_grant_permissions)) {
        grantPermissions = grantRow.access_grant_permissions.map((p) => p.permission);
      } else if (action === 'DOWNLOAD') {
        grantPermissions = ['VIEW', 'DOWNLOAD'];
      }
    } else if (action === 'DOWNLOAD') {
      grantPermissions = ['VIEW', 'DOWNLOAD'];
    }
  } else {
    const resolved = await resolveEligibleGrantReadOnly({
      database,
      authorization,
      documentId,
      documentDepartmentId,
      userId,
      action,
      now,
      documentRank,
      isOwner,
      classAllowDownload,
      documentRetentionUntil,
    });
    if (!resolved) {
      await deny(
        null,
        AppErrorCode.DOCUMENT_ACCESS_DENIED,
        'No valid active grant found for this user and action.',
      );
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: `No active grant found providing ${action} permission for this document.`,
      });
    }
    effectiveGrantId = resolved.grantId;
    grantPermissions = resolved.grantPermissions;
    pendingOwnerGrantProvision = resolved.pendingOwnerGrantProvision;
  }

  if (action === 'DOWNLOAD' && !classAllowDownload) {
    await deny(
      effectiveGrantId,
      AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
      'Classification level forbids download.',
    );
    throw new ForbiddenException({
      errorCode: AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
      message: 'This document classification level does not allow downloads.',
    });
  }

  const grantPermitsDownload = isOwner ? classAllowDownload : grantPermissions.includes('DOWNLOAD');

  return { effectiveGrantId, grantPermitsDownload, pendingOwnerGrantProvision };
}

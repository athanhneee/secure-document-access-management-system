/**
 * Module: PEP Bell-LaPadula Clearance & Three-Tier Grant Resolution Helper
 * Thuật toán: Kiểm Định Trần Độ Mật Bell-LaPadula & Phân Giải Quyền Cấp Phát Ba Tầng (`USER`, `ROLE`, `OWNER`).
 *   1. Kiểm tra bất biến "No Read Up" (`userClearanceRank >= documentRank`) trên mọi đường dẫn mở phiên (bao gồm cả `grantId` tường minh và chủ sở hữu).
 *   2. Phân giải quyền cấp phát hợp lệ qua Tầng 1 (`USER` grant), Tầng 2 (`ROLE` grant), hoặc Tầng 3 (khởi tạo/gia hạn cho chủ sở hữu khi đủ độ mật).
 */
import { ForbiddenException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AccessGrantsService } from '../access-grants/access-grants.service.js';

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

/**
 * Thuật toán: Phân giải quyền cấp phát hoạt động ba tầng (`USER` -> `ROLE` -> `OWNER`) có kiểm định độ mật Bell-LaPadula tại mọi tầng.
 */
export async function resolveEligibleGrant(params: {
  database: PrismaClient;
  documentId: string;
  userId: bigint;
  action: 'VIEW' | 'DOWNLOAD';
  now: Date;
  documentRank: number;
  isOwner?: boolean;
  classAllowDownload?: boolean;
}): Promise<string | null> {
  const {
    database,
    documentId,
    userId,
    action,
    now,
    documentRank,
    isOwner = false,
    classAllowDownload = true,
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
    select: { id: true },
  });

  if (directGrant && (await checkUserClearance(database, userId, documentRank, now))) {
    return directGrant.id;
  }

  const userRoles = await database.userRole.findMany({
    where: {
      user_id: userId,
      valid_from: { lte: now },
      OR: [{ valid_to: null }, { valid_to: { gt: now } }],
      roles: { is_active: true },
    },
    select: { role_id: true },
  });

  if (userRoles.length > 0) {
    const roleGrant = await database.accessGrant.findFirst({
      where: {
        document_id: documentId,
        principal_type: 'ROLE',
        principal_role_id: { in: userRoles.map((r) => r.role_id) },
        status: 'ACTIVE',
        valid_from: { lte: now },
        valid_until: { gt: now },
        access_grant_permissions: { some: { permission: action } },
      },
      select: { id: true },
    });
    if (roleGrant && (await checkUserClearance(database, userId, documentRank, now))) {
      return roleGrant.id;
    }
  }

  if (isOwner) {
    if (!(await checkUserClearance(database, userId, documentRank, now))) return null;
    if (action === 'DOWNLOAD' && !classAllowDownload) return null;

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

    if (existingOwnerGrant) {
      const perms = existingOwnerGrant.access_grant_permissions.map((p) => p.permission);
      if (!perms.includes(action)) {
        await database.accessGrantPermission.create({
          data: { access_grant_id: existingOwnerGrant.id, permission: action },
        });
      }
      return existingOwnerGrant.id;
    }

    if (typeof database.accessGrant.update === 'function') {
      const staleOwnerGrant = await database.accessGrant.findFirst({
        where: {
          document_id: documentId,
          principal_type: 'USER',
          principal_user_id: userId,
          status: 'ACTIVE',
        },
        select: { id: true, valid_until: true },
      });
      if (staleOwnerGrant) {
        await database.accessGrant.update({
          where: { id: staleOwnerGrant.id },
          data: {
            status: staleOwnerGrant.valid_until <= now ? 'EXPIRED' : 'REVOKED',
            version: { increment: 1 },
          },
        });
      }
    }

    const grantId = randomUUID();
    const permissions: ('VIEW' | 'DOWNLOAD')[] = classAllowDownload
      ? ['VIEW', 'DOWNLOAD']
      : ['VIEW'];
    await database.accessGrant.create({
      data: {
        id: grantId,
        document_id: documentId,
        principal_type: 'USER',
        principal_user_id: userId,
        source: 'DIRECT',
        status: 'ACTIVE',
        valid_from: now,
        valid_until: new Date(now.getTime() + 365 * 86400000),
        granted_by: userId,
        access_grant_permissions: {
          createMany: { data: permissions.map((p) => ({ permission: p })) },
        },
      },
    });
    return grantId;
  }

  return null;
}

/**
 * Thuật toán: Cổng thẩm định `grantId` tường minh hoặc tự động phân giải kèm kiểm tra độ mật và quyền tải xuống.
 */
export async function verifyAndResolveEffectiveGrant(params: {
  database: PrismaClient;
  grantsService: AccessGrantsService;
  documentId: string;
  requestedGrantId: string | undefined;
  userId: bigint;
  action: 'VIEW' | 'DOWNLOAD';
  now: Date;
  documentRank: number;
  isOwner: boolean;
  classAllowDownload: boolean;
  deny: (grantId: string | null, reasonCode: string, reasonMessage: string) => Promise<void>;
}): Promise<string> {
  const {
    database,
    grantsService,
    documentId,
    requestedGrantId,
    userId,
    action,
    now,
    documentRank,
    isOwner,
    classAllowDownload,
    deny,
  } = params;

  let effectiveGrantId: string | null = requestedGrantId ?? null;
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
  } else {
    effectiveGrantId = await resolveEligibleGrant({
      database,
      documentId,
      userId,
      action,
      now,
      documentRank,
      isOwner,
      classAllowDownload,
    });
    if (!effectiveGrantId) {
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

  return effectiveGrantId;
}

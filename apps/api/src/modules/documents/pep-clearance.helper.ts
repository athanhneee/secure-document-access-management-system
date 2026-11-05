/**
 * Module: PEP Bell-LaPadula Clearance & Three-Tier Grant Resolution Helper
 * Algorithm: Enforces "No Read Up" simple security dominance (`userRank >= documentRank`) and resolves
 *   an active grant across explicit `grantId` validation, direct `USER` grants, active `ROLE` grants, or owner self-provisioning.
 */
import { ForbiddenException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AccessGrantsService } from '../access-grants/access-grants.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm: Bell-LaPadula Simple Security Dominance Check
 * Queries the highest active `CLEARANCE_LEVEL` numeric rank for `userId` and verifies `rank >= documentRank`.
 */
export async function checkUserClearance(
  database: PrismaClient,
  userId: bigint,
  documentRank: number,
  now: Date,
): Promise<boolean> {
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
 * Algorithm: Three-Tier Active Access Grant Resolution
 * Evaluates Tier 1 (Direct `USER` grant), Tier 2 (Active `ROLE` grant), and Tier 3 (Document Owner grant)
 * while enforcing individual Bell-LaPadula clearance at every tier.
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
 * Algorithm: Explicit or Auto-Resolved Grant Verification Gate
 * Validates caller-supplied `grantId` binding or resolves an eligible grant, enforcing classification download rules.
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

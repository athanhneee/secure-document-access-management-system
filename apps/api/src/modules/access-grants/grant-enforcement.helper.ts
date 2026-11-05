/**
 * @module GrantEnforcementHelper
 * Algorithm: Real-Time Reference Monitor Grant Validation (Half-Open `[valid_from, valid_until)`, Bell-LaPadula & IDOR Guard).
 */
import { ForbiddenException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import { fetchUserClearanceRank } from './grant-pip.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm / Thuật toán: Thẩm định hiệu lực quyền truy cập thời gian thực (Real-Time Reference Monitor Grant Validation).
 *   1. Kiểm tra liên kết tài liệu (`expectedDocumentId`), trạng thái `ACTIVE` của tài liệu, grant và tài khoản người dùng.
 *   2. Kiểm tra khoảng nửa mở `[valid_from, valid_until)`: từ chối nếu `now < valid_from` hoặc `now >= valid_until`.
 *   3. Kiểm tra quyền tường minh (`VIEW` không suy diễn sang `DOWNLOAD`) và cờ `allow_download` của mức phân loại.
 *   4. Thực thi bất biến độ mật Bell-LaPadula (`userRank >= documentRank`) cho từng cá nhân (kể cả qua `ROLE` grant),
 *      xác minh tư cách thành viên role đang hoạt động hoặc khớp người nhận trực tiếp chống IDOR.
 */
export async function verifyGrantValidForAccess(
  database: PrismaClient,
  grantId: string,
  userId: bigint,
  requestedAction: 'VIEW' | 'DOWNLOAD',
  now: Date = new Date(),
  expectedDocumentId?: string,
): Promise<{
  grant: { id: string; document_id: string; principal_type: string };
  documentRank: number;
}> {
  const grant = await database.accessGrant.findUnique({
    where: { id: grantId },
    include: {
      access_grant_permissions: true,
      documents: {
        include: {
          classification_history: {
            where: { effective_to: null },
            include: { classification_levels: true },
          },
        },
      },
    },
  });

  if (!grant) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.GRANT_NOT_FOUND,
      message: 'Access grant was not found.',
    });
  }

  if (expectedDocumentId && grant.document_id !== expectedDocumentId) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Access grant does not belong to the requested document.',
    });
  }

  if (grant.documents.status !== 'ACTIVE') {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Document is not in active state.',
    });
  }

  if (grant.status === 'REVOKED') {
    throw new ForbiddenException({
      errorCode: AppErrorCode.GRANT_REVOKED,
      message: 'Access grant has been revoked.',
    });
  }

  if (grant.status !== 'ACTIVE') {
    throw new ForbiddenException({
      errorCode: AppErrorCode.GRANT_EXPIRED,
      message: `Access grant status is ${grant.status}.`,
    });
  }

  if (now < grant.valid_from) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.GRANT_EXPIRED,
      message: 'Access grant is not yet valid.',
    });
  }

  if (now >= grant.valid_until) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.GRANT_EXPIRED,
      message: 'Access grant has expired.',
    });
  }

  const user = await database.user.findUnique({
    where: { id: userId },
    select: { status: true },
  });

  if (!user || user.status !== 'ACTIVE') {
    throw new ForbiddenException({
      errorCode: AppErrorCode.USER_NOT_ACTIVE,
      message: 'User account is not active.',
    });
  }

  const grantedPerms = grant.access_grant_permissions.map((p) => p.permission);
  if (!grantedPerms.includes(requestedAction)) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: `Grant does not include ${requestedAction} permission.`,
    });
  }

  const currentClassification = grant.documents.classification_history[0];
  const documentRank = currentClassification?.classification_levels?.rank ?? 0;
  const userRank = (await fetchUserClearanceRank(database, userId, now)) ?? 0;

  if (userRank < documentRank) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.CLEARANCE_INSUFFICIENT,
      message: 'User clearance level is insufficient for this document.',
    });
  }

  if (grant.principal_type === 'ROLE' && grant.principal_role_id) {
    const hasRole = await database.userRole.findFirst({
      where: {
        user_id: userId,
        role_id: grant.principal_role_id,
        valid_from: { lte: now },
        OR: [{ valid_to: null }, { valid_to: { gt: now } }],
        roles: { is_active: true },
      },
    });
    if (!hasRole) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message: 'User does not currently hold the required role for this grant.',
      });
    }
  }

  if (grant.principal_type === 'USER' && grant.principal_user_id !== userId) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
      message: 'Grant was not issued to this user.',
    });
  }

  if (
    requestedAction === 'DOWNLOAD' &&
    currentClassification &&
    !currentClassification.classification_levels.allow_download
  ) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
      message: 'Document classification does not allow download.',
    });
  }

  return {
    grant: {
      id: grant.id,
      document_id: grant.document_id,
      principal_type: grant.principal_type,
    },
    documentRank,
  };
}

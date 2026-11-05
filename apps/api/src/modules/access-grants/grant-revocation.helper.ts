/**
 * @module GrantRevocationHelper
 * Algorithm: Idempotent Serializable Double-Checked Grant Revocation, Cascading Session Termination & Cache Purge.
 */
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode, type RevokeAccessGrantInput } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { NotificationsService } from '../notifications/notifications.service.js';
import type { AuthorizationCache } from '../rbac/authorization-cache.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import type { AccessGrantAuditService } from './access-grant-audit.service.js';
import { toGrantDetail, type GrantDetail } from './access-grants.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface ExecuteRevokeGrantParams {
  grantId: string;
  input: RevokeAccessGrantInput;
  principal: AuthPrincipal;
  context: RequestContext;
  database: PrismaClient;
  authorization: AuthorizationService;
  cache: AuthorizationCache;
  audit: AccessGrantAuditService;
  notifications?: NotificationsService | undefined;
}

/**
 * Algorithm / Thuật toán: Thu hồi quyền truy cập bất biến lịch sử kèm đóng phiên liên đới (Cascading Grant Revocation).
 *   1. Kiểm tra tính lũy đẳng sớm (`REVOKED` -> trả ngay), thẩm định quyền chủ sở hữu/RBAC và khóa lạc quan `expectedVersion`.
 *   2. Giao dịch `Serializable` kèm `SELECT ... FOR UPDATE` trên `access_grants` và kiểm tra lại trạng thái (Double-Checked Locking).
 *   3. Chuyển grant sang `REVOKED` (tăng `version`), chấm dứt mọi phiên `ACTIVE` sang `TERMINATED` và ghi kiểm toán nguyên tử.
 *   4. Xóa bộ nhớ đệm phân quyền của các người dùng bị ảnh hưởng, phát thông báo thu hồi và ghi nhận độ trễ vào `MetricsService`.
 */
export async function executeRevokeGrantWorkflow(
  params: ExecuteRevokeGrantParams,
): Promise<GrantDetail> {
  const {
    grantId,
    input,
    principal,
    context,
    database,
    authorization,
    cache,
    audit,
    notifications,
  } = params;
  const start = performance.now();
  const now = new Date();

  const grant = await database.accessGrant.findUnique({
    where: { id: grantId },
    include: {
      access_grant_permissions: true,
      documents: { select: { owner_id: true, department_id: true } },
    },
  });

  if (!grant) {
    throw new NotFoundException({
      errorCode: AppErrorCode.GRANT_NOT_FOUND,
      message: 'Access grant was not found.',
    });
  }

  if (grant.status === 'REVOKED') {
    return toGrantDetail(grant);
  }

  if (grant.status !== 'ACTIVE' && grant.status !== 'SUSPENDED') {
    throw new BadRequestException({
      errorCode: AppErrorCode.GRANT_ALREADY_REVOKED,
      message: `Cannot revoke a grant with status ${grant.status}.`,
    });
  }

  if (grant.documents.owner_id !== principal.userId) {
    const hasPermission = await authorization.hasPermission(principal, 'ACCESS_GRANT', 'REVOKE', {
      targetDepartmentId: grant.documents.department_id,
    });
    if (!hasPermission) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.FORBIDDEN,
        message: 'Only the document owner or authorized administrator can revoke grants.',
      });
    }
  }

  if (input.expectedVersion !== undefined && input.expectedVersion !== grant.version) {
    throw new ConflictException({
      errorCode: AppErrorCode.GRANT_CONCURRENCY_CONFLICT,
      message: 'Grant was modified by another request. Please retry.',
    });
  }

  let terminatedSessionCount = 0;
  let didTransitionToRevoked = false;
  const affectedUserIds = new Set<bigint>();

  await database.$transaction(
    async (tx) => {
      await tx.$executeRawUnsafe(
        'SELECT id FROM access_grants WHERE id = $1::uuid FOR UPDATE',
        grantId,
      );

      const locked = await tx.accessGrant.findUnique({
        where: { id: grantId },
        select: { status: true, version: true },
      });

      if (!locked || locked.status === 'REVOKED') return;

      if (locked.status !== 'ACTIVE' && locked.status !== 'SUSPENDED') {
        throw new BadRequestException({
          errorCode: AppErrorCode.GRANT_ALREADY_REVOKED,
          message: `Cannot revoke a grant with status ${locked.status}.`,
        });
      }

      await tx.accessGrant.update({
        where: { id: grantId },
        data: {
          status: 'REVOKED',
          revoked_by: principal.userId,
          revoked_at: now,
          revoke_reason: input.reason,
          version: { increment: 1 },
        },
      });
      didTransitionToRevoked = true;

      const activeSessions = await tx.accessSession.findMany({
        where: { access_grant_id: grantId, status: 'ACTIVE' },
        select: { id: true, user_id: true },
      });

      for (const session of activeSessions) {
        affectedUserIds.add(session.user_id);
      }

      if (activeSessions.length > 0) {
        const result = await tx.accessSession.updateMany({
          where: { access_grant_id: grantId, status: 'ACTIVE' },
          data: {
            status: 'TERMINATED',
            ended_at: now,
            terminated_reason: `Grant revoked: ${input.reason}`,
          },
        });
        terminatedSessionCount = result.count;
      }

      await audit.record(
        {
          action: 'GRANT_REVOKED',
          outcome: 'SUCCESS',
          objectId: grantId,
          documentId: grant.document_id,
          details: {
            reason: input.reason,
            terminatedSessions: terminatedSessionCount,
            principalType: grant.principal_type,
            principalUserId: grant.principal_user_id?.toString() ?? null,
            principalRoleId: grant.principal_role_id?.toString() ?? null,
          },
        },
        principal,
        context,
        tx,
      );
    },
    { isolationLevel: 'Serializable' },
  );

  for (const userId of affectedUserIds) {
    cache.invalidateUser(userId);
  }
  if (grant.principal_user_id) {
    cache.invalidateUser(grant.principal_user_id);
  }

  const updated = await database.accessGrant.findUnique({
    where: { id: grantId },
    include: { access_grant_permissions: true },
  });

  if (didTransitionToRevoked && notifications) {
    const recipients = new Set<bigint>(affectedUserIds);
    if (grant.principal_user_id) {
      recipients.add(grant.principal_user_id);
    }
    for (const recipientId of recipients) {
      try {
        await notifications.sendNotification({
          recipientId,
          notificationType: 'ACCESS_GRANT_REVOKED',
          title: 'Quyền truy cập tài liệu đã bị thu hồi',
          body: `Quyền truy cập đối với tài liệu ${grant.document_id} đã bị thu hồi. Lý do: ${input.reason}`,
          relatedObjectType: 'ACCESS_GRANT',
          relatedObjectId: grantId,
          deduplicationKey: `ACCESS_GRANT_REVOKED:${recipientId}:${grantId}:v${updated?.version ?? grant.version + 1}`,
          payload: {
            grantId,
            documentId: grant.document_id,
            reason: input.reason,
            terminatedSessions: terminatedSessionCount,
          },
        });
      } catch {
        // Non-fatal post-commit notification dispatch
      }
    }
  }

  const durationSeconds = (performance.now() - start) / 1000;
  try {
    const { MetricsService } = await import('../system-health/metrics.service.js');
    MetricsService.getInstance().recordGrantRevocation(durationSeconds, true);
  } catch {
    // Metrics optional in isolated unit tests
  }

  return toGrantDetail(updated!);
}

/**
 * Module: Document Ownership Handover Helper
 * Thuật toán: Chuyển Giao Quyền Sở Hữu Tài Liệu Nguyên Tử Có Khóa Dòng `FOR UPDATE`, Kiểm Định SoD (Cả Custom Role Đặc Quyền),
 *   Quyền `DOCUMENT:MANAGE`, Phòng Ban Hoạt Động, Trần Độ Mật Bell-LaPadula & Dọn Dẹp Dây Chuyền (`BUG-052`).
 */
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import type { getDatabaseClient, Prisma } from '@sda/database';
import { AppErrorCode, type TransferDocumentOwnerInput } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { NotificationsService } from '../notifications/notifications.service.js';
import type { AuthorizationCache } from '../rbac/authorization-cache.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';
import {
  isPrivilegedSeparationRoleOrCapability,
  systemRoleAllows,
} from '../rbac/permission-matrix.js';
import type { RealtimeEventsService } from '../realtime/realtime-events.service.js';
import type { DocumentAuditService } from './document-audit.service.js';
import { assertDocumentMutationPermission } from './document-access-guard.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Bàn giao quyền sở hữu tài liệu nguyên tử trong một giao dịch `$transaction` có `FOR UPDATE`,
 * chặn tự chuyển cho chính mình (`400`), kiểm tra `targetUser` `ACTIVE` + phòng ban `ACTIVE` + không vướng Custom/System Role đặc quyền SoD
 * + có quyền `DOCUMENT:MANAGE` hiệu lực + đủ `clearanceRank >= documentRank`, thu hồi grant dư thừa, đóng `AccessSession` chủ cũ,
 * hủy `AccessRequest PENDING` của chủ mới, `await` xóa cache và phát SSE (`BUG-052`).
 */
export async function executeTransferDocumentOwner(params: {
  database: PrismaClient;
  authorization: AuthorizationService;
  cache: AuthorizationCache;
  audit: DocumentAuditService;
  notifications?: NotificationsService | undefined;
  realtime?: RealtimeEventsService | undefined;
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
    realtime,
    documentId,
    input,
    principal,
    context,
  } = params;

  const runTransfer = async (tx: PrismaClient) => {
    if (typeof tx.$queryRawUnsafe === 'function') {
      await tx.$queryRawUnsafe(
        'SELECT id FROM documents WHERE id = $1::uuid FOR UPDATE',
        documentId,
      );
    }

    const doc = await tx.document.findUnique({ where: { id: documentId } });
    if (!doc || doc.status === 'DELETED') {
      throw new NotFoundException({
        errorCode: AppErrorCode.DOCUMENT_NOT_FOUND,
        message: 'Document not found.',
      });
    }

    await assertDocumentMutationPermission(authorization, doc, principal, 'TRANSFER_OWNER', {
      database: tx,
    });

    if (doc.status === 'ARCHIVED') {
      throw new BadRequestException({
        errorCode: AppErrorCode.DOCUMENT_ARCHIVED,
        message: 'Cannot transfer ownership of an archived or deleted document.',
      });
    }

    if (doc.owner_id === input.newOwnerId) {
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message: 'Cannot transfer document ownership to the current owner.',
      });
    }

    const now = new Date();
    const targetUser = await tx.user.findUnique({ where: { id: input.newOwnerId } });
    const targetLocked =
      (targetUser as { locked_until?: Date | null } | null)?.locked_until &&
      new Date((targetUser as { locked_until: Date }).locked_until) > now;
    if (!targetUser || targetUser.status !== 'ACTIVE' || targetLocked) {
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message: 'Target user does not exist or is not active.',
      });
    }

    if ('department_id' in targetUser) {
      if (targetUser.department_id === null || targetUser.department_id === undefined) {
        throw new BadRequestException({
          errorCode: AppErrorCode.VALIDATION_FAILED,
          message: 'Target user must belong to an active department to own business documents.',
        });
      }
      if (typeof tx.department?.findFirst === 'function') {
        const activeDepartment = await tx.department.findFirst({
          where: { id: targetUser.department_id, is_active: true },
          select: { id: true },
        });
        if (!activeDepartment) {
          throw new BadRequestException({
            errorCode: AppErrorCode.VALIDATION_FAILED,
            message: 'Target user department is inactive or does not exist.',
          });
        }
      }
    }

    const targetRoleCodes: string[] = [];
    let hasRoleBasedManage = false;
    let inspectedRolePermissions = false;

    if (typeof tx.userRole?.findMany === 'function') {
      const targetUserRoles = await tx.userRole.findMany({
        where: {
          user_id: input.newOwnerId,
          valid_from: { lte: now },
          OR: [{ valid_to: null }, { valid_to: { gt: now } }],
          roles: { is_active: true },
        },
        include: {
          roles: {
            include: {
              role_permissions: {
                include: { permissions: true },
              },
            },
          },
        },
      });

      for (const rawRole of targetUserRoles) {
        const roleObj = (
          rawRole as {
            roles?: {
              code?: string;
              role_permissions?: Array<{
                permissions?: { code: string; resource_type?: string; action?: string } | null;
              }>;
            } | null;
          }
        ).roles;
        if (!roleObj?.code) continue;
        targetRoleCodes.push(roleObj.code);
        const perms = Array.isArray(roleObj.role_permissions)
          ? roleObj.role_permissions
              .map((rp) => rp.permissions)
              .filter((p): p is NonNullable<typeof p> => Boolean(p))
          : [];
        if (Array.isArray(roleObj.role_permissions)) {
          inspectedRolePermissions = true;
        }
        if (isPrivilegedSeparationRoleOrCapability(roleObj.code, perms)) {
          throw new ForbiddenException({
            errorCode: AppErrorCode.TECHNICAL_ADMIN_CANNOT_OWN,
            message:
              'Separation of duties: cannot transfer document ownership to privileged administrative, security, or auditor accounts.',
          });
        }
        if (
          perms.some(
            (p) =>
              p.code === 'DOCUMENT_MANAGE' ||
              (p.resource_type === 'DOCUMENT' && p.action === 'MANAGE'),
          )
        ) {
          hasRoleBasedManage = true;
        }
      }
    }

    // BUG-052: Khớp 100% với @RequirePermission('DOCUMENT', 'MANAGE') trên DocumentsController để không khóa chết tài liệu khi chuyển sang DOCUMENT_READER.
    const newOwnerPrincipal: AuthPrincipal = {
      userId: input.newOwnerId,
      sessionId: 'ownership-transfer-check',
      username:
        (targetUser as { username?: string }).username ?? `user-${input.newOwnerId.toString()}`,
      roles: targetRoleCodes,
      mfa: true,
      ...(targetUser.department_id ? { departmentId: targetUser.department_id } : {}),
    };

    let targetCanManageDocuments = false;
    if (typeof authorization?.effectiveGrants === 'function') {
      const effectiveGrants = await authorization.effectiveGrants(
        input.newOwnerId,
        tx as unknown as Prisma.TransactionClient,
      );
      const allGrantCapabilities = effectiveGrants.map((g) => ({
        code: g.code,
        resource_type: g.resource,
        action: g.action,
      }));
      if (isPrivilegedSeparationRoleOrCapability(undefined, allGrantCapabilities)) {
        throw new ForbiddenException({
          errorCode: AppErrorCode.TECHNICAL_ADMIN_CANNOT_OWN,
          message:
            'Separation of duties: cannot transfer document ownership to privileged administrative, security, or auditor accounts.',
        });
      }
      for (const grant of effectiveGrants) {
        if (
          grant.code === 'DOCUMENT_MANAGE' ||
          (grant.resource === 'DOCUMENT' && grant.action === 'MANAGE')
        ) {
          if (grant.scopeDepartmentId === null) {
            targetCanManageDocuments = true;
            break;
          }
          if (
            typeof authorization.departmentWithinScope === 'function' &&
            (await authorization.departmentWithinScope(
              doc.department_id,
              grant.scopeDepartmentId,
              tx as unknown as Prisma.TransactionClient,
            ))
          ) {
            targetCanManageDocuments = true;
            break;
          }
        }
      }
    } else if (typeof tx.userRole?.findMany === 'function') {
      targetCanManageDocuments =
        targetRoleCodes.length > 0 &&
        (hasRoleBasedManage ||
          (!inspectedRolePermissions &&
            targetRoleCodes.some((code) => systemRoleAllows(code, ['DOCUMENT_MANAGE']))));
    } else if (typeof authorization?.hasPermission === 'function') {
      targetCanManageDocuments = await authorization.hasPermission(
        newOwnerPrincipal,
        'DOCUMENT',
        'MANAGE',
        { targetDepartmentId: doc.department_id },
        tx as unknown as Prisma.TransactionClient,
      );
    }

    if (!targetCanManageDocuments) {
      throw new ForbiddenException({
        errorCode: AppErrorCode.DOCUMENT_ACCESS_DENIED,
        message:
          'Target user does not hold effective DOCUMENT:MANAGE permission required to manage owned documents.',
      });
    }

    const currentClassification = await tx.documentClassificationHistory.findFirst({
      where: { document_id: documentId, effective_to: null },
      include: { classification_levels: true },
    });
    const documentRank = currentClassification?.classification_levels?.rank ?? 0;

    const clearanceAssignment = await tx.userAttributeAssignment.findFirst({
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
    await tx.document.update({
      where: { id: documentId },
      data: { owner_id: input.newOwnerId, version: { increment: 1 } },
    });

    const revokedPreviousGrantIds: string[] = [];
    if (typeof tx.accessGrant?.findMany === 'function') {
      const activeGrants = await tx.accessGrant.findMany({
        where: { document_id: documentId, status: 'ACTIVE' },
      });
      for (const grant of activeGrants) {
        const isFormerOwnerGrant =
          grant.principal_type === 'USER' && grant.principal_user_id === previousOwnerId;
        const isRedundantNewOwnerGrant =
          grant.principal_type === 'USER' && grant.principal_user_id === input.newOwnerId;
        if (
          (isFormerOwnerGrant || isRedundantNewOwnerGrant) &&
          typeof tx.accessGrant?.update === 'function'
        ) {
          await tx.accessGrant.update({
            where: { id: grant.id },
            data: {
              status: 'REVOKED',
              revoked_by: principal.userId,
              revoked_at: now,
              revoke_reason: isFormerOwnerGrant
                ? 'Document ownership transferred'
                : 'Superseded by document ownership transfer',
              version: { increment: 1 },
            },
          });
          if (isFormerOwnerGrant) {
            revokedPreviousGrantIds.push(grant.id);
          }
        }
      }
    }

    let terminatedSessionsCount = 0;
    if (typeof tx.accessSession?.updateMany === 'function') {
      for (const grantId of revokedPreviousGrantIds) {
        const res = await tx.accessSession.updateMany({
          where: { access_grant_id: grantId, status: 'ACTIVE' },
          data: {
            status: 'TERMINATED',
            ended_at: now,
            terminated_reason: 'Document ownership transferred',
          },
        });
        terminatedSessionsCount += res?.count ?? 0;
      }
      const directSessionRes = await tx.accessSession
        .updateMany({
          where: {
            user_id: previousOwnerId,
            status: 'ACTIVE',
            document_versions: { document_id: documentId },
          },
          data: {
            status: 'TERMINATED',
            ended_at: now,
            terminated_reason: 'Document ownership transferred',
          },
        })
        .catch(() => ({ count: 0 }));
      terminatedSessionsCount += directSessionRes?.count ?? 0;
    }

    if (typeof tx.accessRequest?.updateMany === 'function') {
      await tx.accessRequest.updateMany({
        where: {
          document_id: documentId,
          requester_id: input.newOwnerId,
          status: 'PENDING',
        },
        data: {
          status: 'CANCELLED',
          cancelled_at: now,
        },
      });
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
      tx as unknown as Prisma.TransactionClient,
    );

    return { doc, previousOwnerId, terminatedSessionsCount };
  };

  const { doc, previousOwnerId, terminatedSessionsCount } =
    typeof database.$transaction === 'function'
      ? await database.$transaction(async (tx) => runTransfer(tx as unknown as PrismaClient))
      : await runTransfer(database);

  await Promise.all([
    cache.invalidateUser(previousOwnerId),
    cache.invalidateUser(input.newOwnerId),
  ]);

  realtime?.publish({
    type: 'DOCUMENT_UPDATED',
    targetUserIds: [previousOwnerId.toString(), input.newOwnerId.toString()],
    payload: {
      id: documentId,
      action: 'OWNER_TRANSFERRED',
      previousOwnerId: previousOwnerId.toString(),
      newOwnerId: input.newOwnerId.toString(),
    },
  });
  if (terminatedSessionsCount > 0) {
    realtime?.publish({
      type: 'ACCESS_SESSION_UPDATED',
      targetUserIds: [previousOwnerId.toString()],
      targetRoles: ['SECURITY_OFFICER'],
      targetDepartmentId: doc.department_id?.toString() ?? null,
      payload: {
        documentId,
        status: 'TERMINATED',
        action: 'OWNER_TRANSFERRED',
      },
    });
  }

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

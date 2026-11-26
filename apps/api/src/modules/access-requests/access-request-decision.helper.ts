/**
 * @module AccessRequestDecisionHelper
 * Algorithm: One-Way Access Request Decision State Machine (`PENDING` -> `APPROVED` | `REJECTED`).
 * Xử lý chuyển trạng thái phê duyệt/từ chối nguyên tử và tự động khởi tạo quyền truy cập khi chấp thuận.
 */
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode, type DecideAccessRequestInput } from '@sda/contracts';
import type { AccessGrantAuditService } from '../access-grants/access-grant-audit.service.js';
import type { AccessGrantsService } from '../access-grants/access-grants.service.js';
import { assertWithinDocumentRetention } from '../access-grants/grant-retention-bounds.helper.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { NotificationsService } from '../notifications/notifications.service.js';
import type { RealtimeEventsService } from '../realtime/realtime-events.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface ExecuteDecisionParams {
  id: string;
  input: DecideAccessRequestInput;
  principal: AuthPrincipal;
  context: RequestContext;
  database: PrismaClient;
  audit: AccessGrantAuditService;
  grantsService: AccessGrantsService;
  realtime?: RealtimeEventsService | undefined;
  notifications?: NotificationsService | undefined;
}

/**
 * Algorithm / Thuật toán: Thực thi quyết định phê duyệt hoặc từ chối yêu cầu truy cập (`PENDING` -> `APPROVED` | `REJECTED`).
 * Cơ chế hoạt động:
 *   1. Xác minh sự tồn tại của yêu cầu, quyền sở hữu tài liệu (`owner_id === principal.userId`) và trạng thái `PENDING`.
 *   2. Nhánh `REJECTED`: Cập nhật trạng thái, ghi `AccessRequestDecision` và nhật ký kiểm toán trong một giao dịch.
 *   3. Nhánh `APPROVED`: Tính mốc `validUntil = now + validDays`, ủy quyền cho `grantsService.createGrant` cấp quyền
 *      kèm `accessRequestId` và ghi nhận sự kiện kiểm toán `ACCESS_REQUEST_APPROVED`.
 */
export async function executeAccessRequestDecision(
  params: ExecuteDecisionParams,
): Promise<{ id: string; status: string; grantId?: string }> {
  const { id, input, principal, context, database, audit, grantsService, realtime, notifications } =
    params;
  const now = new Date();

  const request = await database.accessRequest.findUnique({
    where: { id },
    include: {
      documents: true,
      access_request_permissions: true,
    },
  });

  if (!request) {
    throw new NotFoundException({
      errorCode: AppErrorCode.ACCESS_REQUEST_NOT_FOUND,
      message: 'Access request was not found.',
    });
  }

  if (request.documents.owner_id !== principal.userId) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.FORBIDDEN,
      message: 'Only the document owner can decide access requests.',
    });
  }

  if (request.status !== 'PENDING') {
    throw new BadRequestException({
      errorCode: AppErrorCode.ACCESS_REQUEST_ALREADY_DECIDED,
      message: `Cannot decide request in ${request.status} status.`,
    });
  }

  if (input.decision === 'REJECTED') {
    await database.$transaction(async (tx) => {
      if (typeof tx.accessRequest.updateMany === 'function') {
        const updated = await tx.accessRequest.updateMany({
          where: { id, status: 'PENDING' },
          data: {
            status: 'REJECTED',
            updated_at: now,
            version: { increment: 1 },
          },
        });
        if (updated.count === 0) {
          throw new BadRequestException({
            errorCode: AppErrorCode.ACCESS_REQUEST_ALREADY_DECIDED,
            message: 'Access request is no longer in PENDING status.',
          });
        }
      } else {
        await tx.accessRequest.update({
          where: { id },
          data: {
            status: 'REJECTED',
            updated_at: now,
            version: { increment: 1 },
          },
        });
      }

      await tx.accessRequestDecision.create({
        data: {
          access_request_id: id,
          decision: 'REJECTED',
          decided_by: principal.userId,
          decision_note: input.decisionNote?.trim() ?? null,
          decided_at: now,
        },
      });

      await audit.record(
        {
          action: 'ACCESS_REQUEST_REJECTED',
          outcome: 'SUCCESS',
          objectId: id,
          documentId: request.document_id,
          details: {
            decidedBy: principal.userId.toString(),
            decisionNote: input.decisionNote?.trim() ?? null,
          },
        },
        principal,
        context,
        tx,
      );
    });

    const trimmedNote = input.decisionNote?.trim() ?? null;
    if (notifications) {
      const docTitle = request.documents?.title;
      const docCode = request.documents?.document_code;
      const docLabel = docTitle ? `"${docTitle}"${docCode ? ` (${docCode})` : ''}` : 'đã yêu cầu';
      const noteSuffix = trimmedNote ? ` Lý do: ${trimmedNote}` : '';
      try {
        await notifications.sendNotification({
          recipientId: request.requester_id,
          notificationType: 'ACCESS_REQUEST_REJECTED',
          title: 'Yêu cầu quyền truy cập tài liệu bị từ chối',
          body: `Yêu cầu truy cập đối với tài liệu ${docLabel} không được phê duyệt.${noteSuffix}`,
          relatedObjectType: 'ACCESS_REQUEST',
          relatedObjectId: id,
          deduplicationKey: `ACCESS_REQUEST_REJECTED:${request.requester_id.toString()}:${id}`,
          payload: {
            requestId: id,
            documentId: request.document_id,
            decisionNote: trimmedNote,
          },
        });
      } catch {
        // Non-fatal post-commit notification dispatch
      }
    }

    realtime?.publish({
      type: 'ACCESS_REQUEST_UPDATED',
      targetUserIds: [principal.userId.toString(), request.requester_id.toString()],
      payload: {
        id,
        status: 'REJECTED',
        documentId: request.document_id,
        decisionNote: trimmedNote,
      },
    });
    return { id, status: 'REJECTED' };
  }

  // Thuật toán: Ưu tiên mốc `validUntil` tường minh hoặc `validDays` của chủ sở hữu; ngược lại tôn trọng khung đề xuất của người xem và cưỡng chế không vượt `retention_until`.
  let validFrom = now;
  let validUntil: Date;
  if (input.validUntil) {
    const parsedUntil = new Date(input.validUntil);
    if (Number.isNaN(parsedUntil.getTime()) || parsedUntil.getTime() <= now.getTime()) {
      throw new BadRequestException({
        errorCode: AppErrorCode.GRANT_TIME_RANGE_INVALID,
        message: 'validUntil must be a valid future ISO timestamp.',
      });
    }
    validUntil = parsedUntil;
  } else if (
    typeof input.validDays === 'number' &&
    Number.isFinite(input.validDays) &&
    input.validDays > 0
  ) {
    validUntil = new Date(now.getTime() + input.validDays * 86400000);
  } else {
    const reqFrom =
      request.requested_from instanceof Date
        ? request.requested_from
        : request.requested_from
          ? new Date(request.requested_from)
          : null;
    if (reqFrom && !Number.isNaN(reqFrom.getTime()) && reqFrom > now) {
      validFrom = reqFrom;
    }

    if (request.requested_until !== null && request.requested_until !== undefined) {
      const reqUntil =
        request.requested_until instanceof Date
          ? request.requested_until
          : new Date(request.requested_until);
      if (
        Number.isNaN(reqUntil.getTime()) ||
        reqUntil.getTime() <= now.getTime() ||
        reqUntil.getTime() <= validFrom.getTime()
      ) {
        throw new BadRequestException({
          errorCode: AppErrorCode.GRANT_TIME_RANGE_INVALID,
          message:
            'Requested access window has already expired; provide an explicit future validUntil or validDays override, or reject the request.',
        });
      }
      validUntil = reqUntil;
    } else {
      validUntil = new Date(validFrom.getTime() + 7 * 86400000);
    }
  }

  assertWithinDocumentRetention({
    retentionUntil: request.documents?.retention_until,
    targetUntil: validUntil,
    now,
    context: 'GRANT',
  });

  const trimmedApprovalNote = input.decisionNote?.trim() || null;
  const effectiveValidDays =
    typeof input.validDays === 'number'
      ? input.validDays
      : Math.max(1, Math.round((validUntil.getTime() - validFrom.getTime()) / 86400000));
  const rawPermissions =
    input.permissions && input.permissions.length > 0
      ? input.permissions
      : request.access_request_permissions.length > 0
        ? request.access_request_permissions.map((p) => p.permission)
        : ['VIEW'];
  // CONFLICT-RESOLVED: Phòng thủ chiều sâu — khi phê duyệt DOWNLOAD bắt buộc bao gồm cả quyền VIEW (HIGH-06)
  const permissions =
    rawPermissions.includes('DOWNLOAD') && !rawPermissions.includes('VIEW')
      ? ['VIEW', ...rawPermissions]
      : [...new Set(rawPermissions)];

  const grant = await grantsService.createGrant(
    {
      documentId: request.document_id,
      principalType: 'USER',
      principalUserId: request.requester_id,
      permissions: permissions as ('VIEW' | 'DOWNLOAD')[],
      validFrom: validFrom.toISOString(),
      validUntil: validUntil.toISOString(),
      accessRequestId: id,
    },
    principal,
    context,
    { decisionNote: trimmedApprovalNote },
  );

  await audit.record(
    {
      action: 'ACCESS_REQUEST_APPROVED',
      outcome: 'SUCCESS',
      objectId: id,
      documentId: request.document_id,
      details: {
        decidedBy: principal.userId.toString(),
        grantId: grant.id,
        validDays: effectiveValidDays,
        permissions: permissions.join(','),
        decisionNote: trimmedApprovalNote,
      },
    },
    principal,
    context,
  );

  realtime?.publish({
    type: 'ACCESS_REQUEST_UPDATED',
    targetUserIds: [principal.userId.toString(), request.requester_id.toString()],
    payload: {
      id,
      status: 'APPROVED',
      documentId: request.document_id,
      grantId: grant.id,
      decisionNote: trimmedApprovalNote,
    },
  });
  return { id, status: 'APPROVED', grantId: grant.id };
}

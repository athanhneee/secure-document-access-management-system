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
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface ExecuteDecisionParams {
  id: string;
  input: DecideAccessRequestInput;
  principal: AuthPrincipal;
  context: RequestContext;
  database: PrismaClient;
  audit: AccessGrantAuditService;
  grantsService: AccessGrantsService;
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
  const { id, input, principal, context, database, audit, grantsService } = params;
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

    return { id, status: 'REJECTED' };
  }

  const validUntil = new Date(now.getTime() + input.validDays * 86400000);
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
      validFrom: now.toISOString(),
      validUntil: validUntil.toISOString(),
      accessRequestId: id,
    },
    principal,
    context,
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
        validDays: input.validDays,
        permissions: permissions.join(','),
      },
    },
    principal,
    context,
  );

  return { id, status: 'APPROVED', grantId: grant.id };
}

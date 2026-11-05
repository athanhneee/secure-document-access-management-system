/**
 * @module GrantTransactionHelper
 * Algorithm: Serializable Pessimistic Row-Locked Grant Creation & Interval Coalescing (`[min(from), max(until)]`).
 */
import { BadRequestException, ConflictException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { withSerializableTransaction, type getDatabaseClient } from '@sda/database';
import { AppErrorCode, type CreateAccessGrantInput } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AccessGrantAuditService } from './access-grant-audit.service.js';
import { toGrantDetail, type GrantDetail } from './access-grants.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface ExecuteCreateGrantTxParams {
  input: CreateAccessGrantInput;
  principal: AuthPrincipal;
  context: RequestContext;
  now: Date;
  validFrom: Date;
  validUntil: Date;
  maxMs: number;
  maxDurationDays: number;
  database: PrismaClient;
  audit: AccessGrantAuditService;
}

/**
 * Algorithm / Thuật toán: Giao dịch cô lập `Serializable` kèm `SELECT ... FOR UPDATE` và Hợp nhất khoảng hiệu lực (Interval Coalescing).
 *   - Nếu đã tồn tại grant `ACTIVE` cùng tập quyền: hợp nhất khoảng thời gian `[min(validFrom, existing.valid_from), max(validUntil, existing.valid_until)]`.
 *   - Nếu tồn tại grant `ACTIVE` khác tập quyền: từ chối `409 GRANT_OVERLAP_EXISTS`.
 *   - Nếu chưa tồn tại: khởi tạo grant mới, ghi chuỗi kiểm toán HMAC và cập nhật yêu cầu `accessRequestId` sang `APPROVED`.
 */
export async function executeCreateOrExtendGrantTx(
  params: ExecuteCreateGrantTxParams,
): Promise<GrantDetail> {
  const {
    input,
    principal,
    context,
    now,
    validFrom,
    validUntil,
    maxMs,
    maxDurationDays,
    database,
    audit,
  } = params;
  let resultGrant!: GrantDetail;

  // CONFLICT-RESOLVED: Dùng withSerializableTransaction có vòng lặp thử lại chống lỗi 40001/40P01/P2034 (MED-02)
  await withSerializableTransaction(
    async (tx) => {
      const grantId = randomUUID();
      await tx.$executeRawUnsafe(
        'SELECT id FROM documents WHERE id = $1::uuid FOR UPDATE',
        input.documentId,
      );

      const existingGrant = await tx.accessGrant.findFirst({
        where: {
          document_id: input.documentId,
          principal_type: input.principalType,
          principal_user_id:
            input.principalType === 'USER' ? (input.principalUserId ?? null) : null,
          principal_role_id:
            input.principalType === 'ROLE' ? (input.principalRoleId ?? null) : null,
          status: 'ACTIVE',
        },
        include: { access_grant_permissions: true },
      });

      if (existingGrant) {
        const existingPerms = existingGrant.access_grant_permissions.map((p) => p.permission);
        const requestedPerms = [...new Set(input.permissions)].sort();
        const samePerms = existingPerms.sort().join(',') === requestedPerms.join(',');

        if (!samePerms) {
          throw new ConflictException({
            errorCode: AppErrorCode.GRANT_OVERLAP_EXISTS,
            message:
              'An active grant with different permissions already exists for this document and principal. Revoke the existing grant first.',
          });
        }

        const newValidUntil =
          validUntil > existingGrant.valid_until ? validUntil : existingGrant.valid_until;
        const newValidFrom =
          validFrom < existingGrant.valid_from ? validFrom : existingGrant.valid_from;

        if (newValidUntil.getTime() - now.getTime() > maxMs) {
          throw new BadRequestException({
            errorCode: AppErrorCode.GRANT_DURATION_EXCEEDED,
            message: `Extended grant duration cannot exceed ${maxDurationDays} days from now.`,
          });
        }

        await tx.accessGrant.update({
          where: { id: existingGrant.id },
          data: {
            valid_from: newValidFrom,
            valid_until: newValidUntil,
            version: { increment: 1 },
          },
        });

        await audit.record(
          {
            action: 'GRANT_EXTENDED',
            outcome: 'SUCCESS',
            objectId: existingGrant.id,
            documentId: input.documentId,
            details: {
              principalType: input.principalType,
              principalId: (input.principalUserId ?? input.principalRoleId)?.toString() ?? null,
              previousValidUntil: existingGrant.valid_until.toISOString(),
              newValidUntil: newValidUntil.toISOString(),
              previousValidFrom: existingGrant.valid_from.toISOString(),
              newValidFrom: newValidFrom.toISOString(),
            },
          },
          principal,
          context,
          tx,
        );

        await markLinkedAccessRequestApproved(
          tx,
          input.accessRequestId,
          principal.userId,
          newValidFrom,
          newValidUntil,
          now,
        );

        const updated = await tx.accessGrant.findUnique({
          where: { id: existingGrant.id },
          include: { access_grant_permissions: true },
        });
        resultGrant = toGrantDetail(updated!);
        return;
      }

      const created = await tx.accessGrant.create({
        data: {
          id: grantId,
          document_id: input.documentId,
          principal_type: input.principalType,
          principal_user_id: input.principalUserId ?? null,
          principal_role_id: input.principalRoleId ?? null,
          source: input.accessRequestId ? 'ACCESS_REQUEST' : 'DIRECT',
          access_request_id: input.accessRequestId ?? null,
          valid_from: validFrom,
          valid_until: validUntil,
          status: 'ACTIVE',
          granted_by: principal.userId,
          granted_at: now,
          version: 0,
          access_grant_permissions: {
            createMany: {
              data: [...new Set(input.permissions)].map((p) => ({ permission: p })),
            },
          },
        },
        include: { access_grant_permissions: true },
      });

      await audit.record(
        {
          action: 'GRANT_CREATED',
          outcome: 'SUCCESS',
          objectId: grantId,
          documentId: input.documentId,
          details: {
            principalType: input.principalType,
            principalId: (input.principalUserId ?? input.principalRoleId)?.toString() ?? null,
            permissions: input.permissions.join(','),
            validFrom: validFrom.toISOString(),
            validUntil: validUntil.toISOString(),
            source: input.accessRequestId ? 'ACCESS_REQUEST' : 'DIRECT',
            accessRequestId: input.accessRequestId ?? null,
          },
        },
        principal,
        context,
        tx,
      );

      await markLinkedAccessRequestApproved(
        tx,
        input.accessRequestId,
        principal.userId,
        validFrom,
        validUntil,
        now,
      );

      resultGrant = toGrantDetail(created);
    },
    { client: database },
  );

  return resultGrant;
}

/**
 * Algorithm / Thuật toán: Cập nhật yêu cầu xin quyền liên kết sang trạng thái `APPROVED` trong cùng giao dịch.
 */
async function markLinkedAccessRequestApproved(
  tx: Parameters<Parameters<PrismaClient['$transaction']>[0]>[0],
  accessRequestId: string | undefined,
  decidedBy: bigint,
  approvedFrom: Date,
  approvedUntil: Date,
  now: Date,
): Promise<void> {
  // CONFLICT-RESOLVED: Cưỡng chế CAS nguyên tử `status = 'PENDING'` khi chuyển `accessRequestId` sang `APPROVED` để tự động rollback grant nếu yêu cầu đã bị hủy đồng thời (HIGH-11).
  if (!accessRequestId) return;
  if (typeof tx.accessRequest.updateMany === 'function') {
    const updated = await tx.accessRequest.updateMany({
      where: { id: accessRequestId, status: 'PENDING' },
      data: { status: 'APPROVED', updated_at: now, version: { increment: 1 } },
    });
    if (updated.count === 0) {
      throw new ConflictException({
        errorCode: AppErrorCode.ACCESS_REQUEST_ALREADY_DECIDED,
        message: 'Linked access request is no longer in PENDING status.',
      });
    }
  } else {
    await tx.accessRequest.update({
      where: { id: accessRequestId },
      data: { status: 'APPROVED', updated_at: now, version: { increment: 1 } },
    });
  }
  await tx.accessRequestDecision.create({
    data: {
      access_request_id: accessRequestId,
      decision: 'APPROVED',
      decided_by: decidedBy,
      approved_from: approvedFrom,
      approved_until: approvedUntil,
      decided_at: now,
    },
  });
}

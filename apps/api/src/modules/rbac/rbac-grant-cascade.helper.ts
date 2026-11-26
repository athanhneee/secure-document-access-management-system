/**
 * @module RbacGrantCascadeHelper
 * Thuật toán: Cưỡng Chế Phân Tách Nhiệm Vụ (SoD) & Bất Biến Lưới Độ Mật Bell-LaPadula Dây Chuyền Trên Vòng Đời Vai Trò (`BUG-047`).
 *   1. Chặn `409 Conflict` nếu người giữ/nhận vai trò đặc quyền đang sở hữu tài liệu nghiệp vụ chưa bàn giao (`documents.owner_id`, `status <> 'DELETED'`).
 *   2. Thu hồi dây chuyền mọi `USER`/`ROLE` `AccessGrant` đang `ACTIVE` (ghi đủ `revoked_by`, `revoked_at`, `revoke_reason` thỏa `CHECK 23514`),
 *      đóng mọi `AccessSession` đang `ACTIVE` (`ended_at = now`) và hủy mọi `AccessRequest` đang `PENDING` (`cancelled_at = now`) khi nâng cấp vai trò đặc quyền.
 *   3. Khi gán người dùng vào vai trò thường đang nắm `ROLE` `AccessGrant`, kiểm chứng `userClearanceRank >= maxRoleGrantDocumentRank` (chặn `409` yêu cầu nâng clearance trước, bảo toàn quyền cho các thành viên khác của vai trò).
 *   4. Khi gỡ vai trò khỏi người dùng và người đó không còn phép gán hiệu lực nào khác của cùng `role_id`, chấm dứt tức thì các `AccessSession` `ACTIVE` mở qua `ROLE` grant của vai trò đó.
 */
import { ConflictException } from '@nestjs/common';
import type { Prisma, withSerializableTransaction } from '@sda/database';
import { fetchActiveUserClearance } from '../users/users-clearance-assignment.helper.js';

type SerializableTransaction = Parameters<Parameters<typeof withSerializableTransaction>[0]>[0];

/**
 * Thuật toán: Chặn nâng cấp/gán vai trò đặc quyền nếu bất kỳ người dùng mục tiêu nào đang đứng tên sở hữu tài liệu nghiệp vụ chưa xóa (`owner_id`).
 */
export async function assertUsersOwnNoBusinessDocuments(
  transaction: SerializableTransaction,
  userIds: readonly bigint[],
): Promise<void> {
  if (userIds.length === 0 || typeof transaction.document?.count !== 'function') {
    return;
  }
  const ownedCount = await transaction.document.count({
    where: {
      owner_id: { in: [...userIds] },
      status: { not: 'DELETED' },
    },
  });
  if (ownedCount > 0) {
    throw new ConflictException(
      'Separation of duties violation: target user owns active or unarchived business documents that must be transferred before receiving privileged roles.',
    );
  }
}

/**
 * Thuật toán: Thu hồi dây chuyền nguyên tử `AccessGrant` (`USER`/`ROLE`), đóng `AccessSession` (`ACTIVE`) và hủy `AccessRequest` (`PENDING`)
 * khi vai trò được chuyển thành vai trò đặc quyền hoặc khi người dùng được gán vai trò đặc quyền (`BUG-047`).
 * Luôn điền đầy đủ bộ ba `(revoked_by, revoked_at, revoke_reason)` cho `access_grants`, `ended_at` cho `access_sessions` và `cancelled_at` cho `access_requests` để thỏa mãn tuyệt đối `CHECK 23514`.
 */
export async function cascadeCleanupOnPrivilegedRoleEscalation(params: {
  transaction: SerializableTransaction;
  userIds: readonly bigint[];
  roleIds: readonly bigint[];
  actorUserId: bigint;
  reason: string;
  now: Date;
}): Promise<{
  revokedGrantsCount: number;
  terminatedSessionsCount: number;
  cancelledRequestsCount: number;
}> {
  const { transaction, userIds, roleIds, actorUserId, reason, now } = params;
  const uniqueUserIds = [...new Set(userIds)];
  const uniqueRoleIds = [...new Set(roleIds)];
  let revokedGrantsCount = 0;
  let terminatedSessionsCount = 0;
  let cancelledRequestsCount = 0;
  const revokedGrantIds: string[] = [];

  const grantOrClauses: Prisma.AccessGrantWhereInput[] = [];
  if (uniqueUserIds.length > 0) {
    grantOrClauses.push({
      principal_type: 'USER',
      principal_user_id: { in: uniqueUserIds },
      status: 'ACTIVE',
    });
  }
  if (uniqueRoleIds.length > 0) {
    grantOrClauses.push({
      principal_type: 'ROLE',
      principal_role_id: { in: uniqueRoleIds },
      status: 'ACTIVE',
    });
  }

  if (grantOrClauses.length > 0) {
    const revokeData = {
      status: 'REVOKED' as const,
      revoked_by: actorUserId,
      revoked_at: now,
      revoke_reason: reason,
      version: { increment: 1 },
    };

    if (typeof transaction.accessGrant?.findMany === 'function') {
      const grantsToRevoke = await transaction.accessGrant.findMany({
        where: { OR: grantOrClauses },
        select: { id: true },
      });
      for (const g of grantsToRevoke) {
        revokedGrantIds.push(g.id);
      }
      if (revokedGrantIds.length > 0) {
        if (typeof transaction.accessGrant.updateMany === 'function') {
          const updated = await transaction.accessGrant.updateMany({
            where: { id: { in: revokedGrantIds }, status: 'ACTIVE' },
            data: revokeData,
          });
          revokedGrantsCount += updated.count;
        } else if (typeof transaction.accessGrant.update === 'function') {
          for (const gid of revokedGrantIds) {
            await transaction.accessGrant.update({
              where: { id: gid },
              data: revokeData,
            });
            revokedGrantsCount += 1;
          }
        }
      }
    } else if (typeof transaction.accessGrant?.updateMany === 'function') {
      const updated = await transaction.accessGrant.updateMany({
        where: { OR: grantOrClauses },
        data: revokeData,
      });
      revokedGrantsCount += updated.count;
    }
  }

  if (typeof transaction.accessSession?.updateMany === 'function') {
    const sessionOrClauses: Prisma.AccessSessionWhereInput[] = [];
    if (uniqueUserIds.length > 0) {
      sessionOrClauses.push({ user_id: { in: uniqueUserIds } });
    }
    if (revokedGrantIds.length > 0) {
      sessionOrClauses.push({ access_grant_id: { in: revokedGrantIds } });
    }
    if (sessionOrClauses.length > 0) {
      const terminated = await transaction.accessSession.updateMany({
        where: {
          status: 'ACTIVE',
          OR: sessionOrClauses,
        },
        data: {
          status: 'TERMINATED',
          ended_at: now,
          terminated_reason: reason,
        },
      });
      terminatedSessionsCount += terminated.count;
    }
  }

  if (uniqueUserIds.length > 0 && typeof transaction.accessRequest?.updateMany === 'function') {
    const cancelled = await transaction.accessRequest.updateMany({
      where: {
        requester_id: { in: uniqueUserIds },
        status: 'PENDING',
      },
      data: {
        status: 'CANCELLED',
        cancelled_at: now,
        updated_at: now,
        version: { increment: 1 },
      },
    });
    cancelledRequestsCount += cancelled.count;
  }

  return { revokedGrantsCount, terminatedSessionsCount, cancelledRequestsCount };
}

/**
 * Thuật toán: Kiểm chứng bất biến Bell-LaPadula trước khi thêm thành viên mới vào vai trò đang giữ `ROLE` `AccessGrant` hiệu lực (`BUG-047`).
 * Ngăn người dùng bậc thẩm tra thấp làm suy yếu Lattice Meet của vai trò hoặc đọc vượt bậc phân loại mật, đồng thời bảo vệ quyền của các thành viên khác trong vai trò.
 */
export async function assertUserClearanceMeetsActiveRoleGrants(params: {
  transaction: SerializableTransaction;
  userId: bigint;
  roleId: bigint;
  roleCode: string;
  now: Date;
}): Promise<void> {
  const { transaction, userId, roleId, roleCode, now } = params;
  if (typeof transaction.accessGrant?.findMany !== 'function') {
    return;
  }
  const activeRoleGrants = await transaction.accessGrant.findMany({
    where: {
      principal_type: 'ROLE',
      principal_role_id: roleId,
      status: 'ACTIVE',
      valid_until: { gt: now },
    },
    include: {
      documents: {
        select: {
          classification_history: {
            where: { effective_to: null },
            include: { classification_levels: { select: { rank: true } } },
            take: 1,
          },
        },
      },
    },
  });
  if (activeRoleGrants.length === 0) {
    return;
  }

  let maxRequiredRank = 0;
  for (const grant of activeRoleGrants) {
    const docRank = grant.documents?.classification_history?.[0]?.classification_levels?.rank ?? 0;
    if (docRank > maxRequiredRank) {
      maxRequiredRank = docRank;
    }
  }
  if (maxRequiredRank <= 0) {
    return;
  }

  const userClearance = await fetchActiveUserClearance(transaction, userId, now);
  if (userClearance.clearanceRank < maxRequiredRank) {
    throw new ConflictException(
      `User security clearance rank (${userClearance.clearanceRank}) is insufficient for active document access grants held by role "${roleCode}" (requires rank >= ${maxRequiredRank}). Upgrade user clearance before assigning this role.`,
    );
  }
}

/**
 * Thuật toán: Khi gỡ phép gán vai trò khỏi người dùng và không còn bản ghi gán hiệu lực nào khác cho cùng `roleId`,
 * đóng tức thì toàn bộ `AccessSession` đang `ACTIVE` mà người dùng đó đã mở thông qua `ROLE` `AccessGrant` của vai trò vừa gỡ (`BUG-047`).
 */
export async function terminateUserSessionsOpenedViaRevokedRole(params: {
  transaction: SerializableTransaction;
  userId: bigint;
  roleId: bigint;
  roleCode?: string | undefined;
  now: Date;
}): Promise<number> {
  const { transaction, userId, roleId, roleCode, now } = params;
  if (typeof transaction.accessSession?.updateMany !== 'function') {
    return 0;
  }

  if (typeof transaction.userRole?.count === 'function') {
    const stillHoldsSameRole = await transaction.userRole.count({
      where: {
        user_id: userId,
        role_id: roleId,
        valid_from: { lte: now },
        AND: [
          { OR: [{ valid_to: null }, { valid_to: { gt: now } }] },
          { OR: [{ scope_department_id: null }, { departments: { is: { is_active: true } } }] },
        ],
        roles: { is_active: true },
      },
    });
    if (stillHoldsSameRole > 0) {
      return 0;
    }
  }

  const reason = `Role assignment ${roleCode ?? roleId.toString()} revoked from user`;
  if (typeof transaction.accessGrant?.findMany === 'function') {
    const roleGrants = await transaction.accessGrant.findMany({
      where: {
        principal_type: 'ROLE',
        principal_role_id: roleId,
      },
      select: { id: true },
    });
    const roleGrantIds = roleGrants.map((g) => g.id);
    if (roleGrantIds.length === 0) {
      return 0;
    }
    const terminated = await transaction.accessSession.updateMany({
      where: {
        user_id: userId,
        status: 'ACTIVE',
        access_grant_id: { in: roleGrantIds },
      },
      data: {
        status: 'TERMINATED',
        ended_at: now,
        terminated_reason: reason,
      },
    });
    return terminated.count;
  }

  return 0;
}

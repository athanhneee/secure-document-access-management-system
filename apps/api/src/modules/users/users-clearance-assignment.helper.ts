/**
 * Module: UsersClearanceAssignmentHelper — Quản Lý Cấp Độ Thẩm Tra Bell-LaPadula (`CLEARANCE_LEVEL`) Cho Tài Khoản
 * Thuật toán:
 *   1. Truy vấn danh mục tùy chọn `CLEARANCE_LEVEL` đang hoạt động theo thứ tự `numeric_rank` tăng dần và nạp hàng loạt cấp thẩm quyền hiện hành trong `O(1)` truy vấn SQL.
 *   2. Đồng bộ lịch sử SCD Type 2 trên bảng `user_attribute_assignments` trong giao dịch `SERIALIZABLE`:
 *      cắt hiệu lực bản ghi cũ (`valid_from < now` -> `valid_to = now`), loại bỏ bản ghi chưa hiệu lực/trùng mili-giây (`valid_from >= now`) để luôn thỏa `CHECK (valid_to IS NULL OR valid_to > valid_from)`.
 *   3. Cưỡng chế thu hồi dây chuyền Bell-LaPadula khi hạ bậc thẩm quyền (`newRank < previousRank`):
 *      thu hồi toàn bộ `AccessGrant` (`USER`, `ACTIVE`) và đóng toàn bộ `AccessSession` (`ACTIVE`) trên các tài liệu có bậc phân loại lớn hơn `newRank`.
 */
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import type { getDatabaseClient, withSerializableTransaction } from '@sda/database';
import {
  EMPTY_CLEARANCE_SUMMARY,
  type ClearanceOptionItem,
  type ClearanceSummary,
} from './users-clearance.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;
type SerializableTransaction = Parameters<Parameters<typeof withSerializableTransaction>[0]>[0];
type ClearanceQueryClient = Pick<PrismaClient, 'userAttributeAssignment'>;

export interface SyncUserClearanceResult {
  before: ClearanceSummary;
  after: ClearanceSummary;
  changed: boolean;
  revokedGrantsCount: number;
  terminatedSessionsCount: number;
}

/**
 * Thuật toán: Truy vấn danh sách tùy chọn cấp độ thẩm tra `CLEARANCE_LEVEL` đang kích hoạt sắp xếp đơn điệu theo `numeric_rank`.
 */
export async function listClearanceOptions(
  database: PrismaClient,
): Promise<{ data: ClearanceOptionItem[] }> {
  if (typeof database?.attributeDefinition?.findUnique !== 'function') {
    return { data: [] };
  }
  const definition = await database.attributeDefinition.findUnique({
    where: { code: 'CLEARANCE_LEVEL' },
    include: {
      attribute_options: {
        where: { is_active: true },
        orderBy: [{ numeric_rank: 'asc' }, { sort_order: 'asc' }, { id: 'asc' }],
      },
    },
  });
  if (!definition || !definition.is_active) {
    return { data: [] };
  }
  return {
    data: definition.attribute_options.map((opt) => ({
      id: opt.id.toString(),
      code: opt.value_code,
      name: opt.display_name,
      rank: opt.numeric_rank ?? 0,
    })),
  };
}

/**
 * Thuật toán: Truy vấn cấp thẩm tra `CLEARANCE_LEVEL` cao nhất còn hiệu lực tại thời điểm `now` cho một người dùng (Fail-Closed về bậc `0`).
 */
export async function fetchActiveUserClearance(
  database: Partial<ClearanceQueryClient> | undefined,
  userId: bigint,
  now: Date = new Date(),
): Promise<ClearanceSummary> {
  if (typeof database?.userAttributeAssignment?.findFirst !== 'function') {
    return { ...EMPTY_CLEARANCE_SUMMARY };
  }
  const row = await database.userAttributeAssignment.findFirst({
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
    orderBy: [{ attribute_options: { numeric_rank: 'desc' } }, { id: 'desc' }],
  });
  if (
    !row ||
    (row as { attribute_definitions?: { is_active?: boolean } }).attribute_definitions
      ?.is_active === false ||
    !row.attribute_options ||
    row.attribute_options.is_active === false
  ) {
    return { ...EMPTY_CLEARANCE_SUMMARY };
  }
  return {
    clearanceOptionId: row.attribute_options.id.toString(),
    clearanceCode: row.attribute_options.value_code,
    clearanceName: row.attribute_options.display_name,
    clearanceRank: row.attribute_options.numeric_rank ?? 0,
  };
}

/**
 * Thuật toán: Nạp đồng loạt cấp thẩm tra `CLEARANCE_LEVEL` cao nhất còn hiệu lực cho tập người dùng trong `O(1)` truy vấn SQL (tránh N+1).
 */
export async function fetchActiveClearancesByUserIds(
  database: Partial<ClearanceQueryClient> | undefined,
  userIds: readonly bigint[],
  now: Date = new Date(),
): Promise<Map<string, ClearanceSummary>> {
  const result = new Map<string, ClearanceSummary>();
  if (userIds.length === 0 || typeof database?.userAttributeAssignment?.findMany !== 'function') {
    return result;
  }

  const rows = await database.userAttributeAssignment.findMany({
    where: {
      user_id: { in: [...userIds] },
      attribute_definitions: { code: 'CLEARANCE_LEVEL', is_active: true },
      attribute_options: { is_active: true },
      valid_from: { lte: now },
      OR: [{ valid_to: null }, { valid_to: { gt: now } }],
    },
    include: {
      attribute_definitions: { select: { is_active: true } },
      attribute_options: true,
    },
    orderBy: [{ attribute_options: { numeric_rank: 'desc' } }, { id: 'desc' }],
  });

  for (const row of rows) {
    if (
      (row as { attribute_definitions?: { is_active?: boolean } }).attribute_definitions
        ?.is_active === false ||
      !row.attribute_options ||
      row.attribute_options.is_active === false
    ) {
      continue;
    }
    const key = row.user_id.toString();
    const rank = row.attribute_options.numeric_rank ?? 0;
    const existing = result.get(key);
    if (!existing || rank > existing.clearanceRank) {
      result.set(key, {
        clearanceOptionId: row.attribute_options.id.toString(),
        clearanceCode: row.attribute_options.value_code,
        clearanceName: row.attribute_options.display_name,
        clearanceRank: rank,
      });
    }
  }

  return result;
}

/**
 * Thuật toán: Thu hồi dây chuyền giấy phép truy cập (`USER` + `ROLE` Lattice Meet), phiên đọc tài liệu và yêu cầu truy cập `PENDING` vượt bậc
 * khi hạ bậc thẩm tra Bell-LaPadula của người dùng (`BUG-047`).
 */
async function cascadeRevokeOnUserClearanceDowngrade(params: {
  transaction: SerializableTransaction;
  userId: bigint;
  newRank: number;
  actorUserId: bigint;
  now: Date;
}): Promise<{ revokedGrantsCount: number; terminatedSessionsCount: number }> {
  const { transaction, userId, newRank, actorUserId, now } = params;
  let revokedGrantsCount = 0;
  let terminatedSessionsCount = 0;
  const revokedRoleGrantIds: string[] = [];

  if (typeof transaction?.accessGrant?.findMany === 'function') {
    const activeGrants = await transaction.accessGrant.findMany({
      where: {
        principal_type: 'USER',
        principal_user_id: userId,
        status: 'ACTIVE',
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

    for (const grant of activeGrants) {
      const docRank =
        grant.documents?.classification_history?.[0]?.classification_levels?.rank ?? 0;
      if (docRank > newRank) {
        await transaction.accessGrant.update({
          where: { id: grant.id },
          data: {
            status: 'REVOKED',
            revoked_by: actorUserId,
            revoked_at: now,
            revoke_reason: 'User clearance downgraded below document classification rank',
            version: { increment: 1 },
          },
        });
        revokedGrantsCount += 1;
      }
    }

    // BUG-047 & HIGH-06: Quét thu hồi cả các ROLE AccessGrant đang ACTIVE trên cả vai trò hiện hành lẫn vai trò đặt lịch tương lai (`valid_to IS NULL OR valid_to > now`) mà người dùng tham gia nếu `docRank > newRank`.
    if (typeof transaction?.userRole?.findMany === 'function') {
      const activeRoleLinks = await transaction.userRole.findMany({
        where: {
          user_id: userId,
          OR: [{ valid_to: null }, { valid_to: { gt: now } }],
          roles: { is_active: true },
        },
        select: { role_id: true },
      });
      const memberRoleIds = [
        ...new Set(
          activeRoleLinks
            .map((r) => r.role_id)
            .filter((rid): rid is bigint => typeof rid === 'bigint'),
        ),
      ];
      if (memberRoleIds.length > 0) {
        const activeRoleGrants = await transaction.accessGrant.findMany({
          where: {
            principal_type: 'ROLE',
            principal_role_id: { in: memberRoleIds },
            status: 'ACTIVE',
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
        for (const roleGrant of activeRoleGrants) {
          const docRank =
            roleGrant.documents?.classification_history?.[0]?.classification_levels?.rank ?? 0;
          if (docRank > newRank) {
            await transaction.accessGrant.update({
              where: { id: roleGrant.id },
              data: {
                status: 'REVOKED',
                revoked_by: actorUserId,
                revoked_at: now,
                revoke_reason:
                  'Role member clearance downgraded below document classification rank',
                version: { increment: 1 },
              },
            });
            revokedGrantsCount += 1;
            revokedRoleGrantIds.push(roleGrant.id);
          }
        }
      }
    }
  }

  if (typeof transaction?.accessSession?.findMany === 'function') {
    const activeSessions = await transaction.accessSession.findMany({
      where: { user_id: userId, status: 'ACTIVE' },
      include: {
        document_versions: {
          select: {
            document: {
              select: {
                classification_history: {
                  where: { effective_to: null },
                  include: { classification_levels: { select: { rank: true } } },
                  take: 1,
                },
              },
            },
          },
        },
      },
    });

    const sessionIdsToTerminate: string[] = [];
    for (const session of activeSessions) {
      const docRank =
        session.document_versions?.document?.classification_history?.[0]?.classification_levels
          ?.rank ?? 0;
      if (docRank > newRank) {
        sessionIdsToTerminate.push(session.id);
      }
    }

    if (
      sessionIdsToTerminate.length > 0 &&
      typeof transaction?.accessSession?.updateMany === 'function'
    ) {
      const terminated = await transaction.accessSession.updateMany({
        where: { id: { in: sessionIdsToTerminate }, status: 'ACTIVE' },
        data: {
          status: 'TERMINATED',
          ended_at: now,
          terminated_reason: 'User clearance downgraded below document classification rank',
        },
      });
      terminatedSessionsCount += terminated.count;
    }

    if (
      revokedRoleGrantIds.length > 0 &&
      typeof transaction?.accessSession?.updateMany === 'function'
    ) {
      const terminatedRoleSessions = await transaction.accessSession.updateMany({
        where: {
          access_grant_id: { in: revokedRoleGrantIds },
          status: 'ACTIVE',
        },
        data: {
          status: 'TERMINATED',
          ended_at: now,
          terminated_reason: 'Role grant revoked because member clearance was downgraded',
        },
      });
      terminatedSessionsCount += terminatedRoleSessions.count;
    }
  }

  // BUG-047: Hủy mọi yêu cầu truy cập PENDING vượt bậc thẩm tra mới của người dùng (`cancelled_at = now` thỏa CHECK 23514).
  if (typeof transaction?.accessRequest?.findMany === 'function') {
    const pendingRequests = await transaction.accessRequest.findMany({
      where: { requester_id: userId, status: 'PENDING' },
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
    const requestIdsToCancel: string[] = [];
    for (const req of pendingRequests) {
      const docRank = req.documents?.classification_history?.[0]?.classification_levels?.rank ?? 0;
      if (docRank > newRank) {
        requestIdsToCancel.push(req.id);
      }
    }
    if (requestIdsToCancel.length > 0) {
      if (typeof transaction.accessRequest.updateMany === 'function') {
        await transaction.accessRequest.updateMany({
          where: { id: { in: requestIdsToCancel }, status: 'PENDING' },
          data: {
            status: 'CANCELLED',
            cancelled_at: now,
            updated_at: now,
            version: { increment: 1 },
          },
        });
      } else if (typeof transaction.accessRequest.update === 'function') {
        for (const reqId of requestIdsToCancel) {
          await transaction.accessRequest.update({
            where: { id: reqId },
            data: {
              status: 'CANCELLED',
              cancelled_at: now,
              updated_at: now,
              version: { increment: 1 },
            },
          });
        }
      }
    }
  }

  return { revokedGrantsCount, terminatedSessionsCount };
}

/**
 * Thuật toán: Cập nhật nguyên tử thuộc tính `CLEARANCE_LEVEL` theo chuẩn SCD Type 2 kèm thu hồi dây chuyền Bell-LaPadula khi hạ bậc.
 */
export async function syncUserClearanceAssignment(params: {
  transaction: SerializableTransaction;
  userId: bigint;
  clearanceOptionId: bigint | null;
  actorUserId: bigint;
  now: Date;
}): Promise<SyncUserClearanceResult> {
  const { transaction, userId, clearanceOptionId, actorUserId, now } = params;
  // BUG-007: Phòng thủ chiều sâu — tuyệt đối cấm tự sửa thuộc tính CLEARANCE_LEVEL cho chính tài khoản đang thao tác.
  if (userId === actorUserId) {
    throw new ForbiddenException('Administrators cannot modify their own security clearance.');
  }

  const clearanceDef = await transaction.attributeDefinition.findUnique({
    where: { code: 'CLEARANCE_LEVEL' },
    select: { id: true, is_active: true },
  });
  if (!clearanceDef || !clearanceDef.is_active) {
    throw new BadRequestException('CLEARANCE_LEVEL attribute definition is unavailable.');
  }

  let targetOption: {
    id: bigint;
    value_code: string;
    display_name: string;
    numeric_rank: number | null;
  } | null = null;

  if (clearanceOptionId !== null) {
    targetOption = await transaction.attributeOption.findFirst({
      where: {
        id: clearanceOptionId,
        attribute_definition_id: clearanceDef.id,
        is_active: true,
      },
      select: {
        id: true,
        value_code: true,
        display_name: true,
        numeric_rank: true,
      },
    });
    if (!targetOption) {
      throw new BadRequestException('Invalid or inactive security clearance level.');
    }
  }

  const openAssignments = await transaction.userAttributeAssignment.findMany({
    where: {
      user_id: userId,
      attribute_definition_id: clearanceDef.id,
      OR: [{ valid_to: null }, { valid_to: { gt: now } }],
    },
    include: {
      attribute_options: {
        select: {
          id: true,
          value_code: true,
          display_name: true,
          numeric_rank: true,
          is_active: true,
        },
      },
    },
    orderBy: [{ attribute_options: { numeric_rank: 'desc' } }, { id: 'desc' }],
  });

  const activeNow = openAssignments.filter(
    (row) => row.valid_from <= now && row.attribute_options?.is_active !== false,
  );
  const highestActive = activeNow[0];
  const before: ClearanceSummary = highestActive?.attribute_options
    ? {
        clearanceOptionId: highestActive.attribute_options.id.toString(),
        clearanceCode: highestActive.attribute_options.value_code,
        clearanceName: highestActive.attribute_options.display_name,
        clearanceRank: highestActive.attribute_options.numeric_rank ?? 0,
      }
    : { ...EMPTY_CLEARANCE_SUMMARY };

  const after: ClearanceSummary = targetOption
    ? {
        clearanceOptionId: targetOption.id.toString(),
        clearanceCode: targetOption.value_code,
        clearanceName: targetOption.display_name,
        clearanceRank: targetOption.numeric_rank ?? 0,
      }
    : { ...EMPTY_CLEARANCE_SUMMARY };

  const alreadyExact =
    (targetOption === null && openAssignments.length === 0) ||
    (targetOption !== null &&
      openAssignments.length === 1 &&
      activeNow.length === 1 &&
      openAssignments[0]?.option_id === targetOption.id &&
      openAssignments[0]?.valid_to === null);

  if (alreadyExact) {
    return {
      before,
      after,
      changed: false,
      revokedGrantsCount: 0,
      terminatedSessionsCount: 0,
    };
  }

  const pastStartedIds = openAssignments.filter((row) => row.valid_from < now).map((row) => row.id);
  const sameOrFutureIds = openAssignments
    .filter((row) => row.valid_from >= now)
    .map((row) => row.id);

  if (pastStartedIds.length > 0) {
    await transaction.userAttributeAssignment.updateMany({
      where: { id: { in: pastStartedIds } },
      data: { valid_to: now },
    });
  }
  if (sameOrFutureIds.length > 0) {
    await transaction.userAttributeAssignment.deleteMany({
      where: { id: { in: sameOrFutureIds } },
    });
  }

  if (targetOption !== null) {
    await transaction.userAttributeAssignment.create({
      data: {
        user_id: userId,
        attribute_definition_id: clearanceDef.id,
        option_id: targetOption.id,
        valid_from: now,
        valid_to: null,
        assigned_by: actorUserId,
      },
    });
  }

  let revokedGrantsCount = 0;
  let terminatedSessionsCount = 0;
  if (after.clearanceRank < before.clearanceRank) {
    const cascade = await cascadeRevokeOnUserClearanceDowngrade({
      transaction,
      userId,
      newRank: after.clearanceRank,
      actorUserId,
      now,
    });
    revokedGrantsCount = cascade.revokedGrantsCount;
    terminatedSessionsCount = cascade.terminatedSessionsCount;
  }

  return {
    before,
    after,
    changed: true,
    revokedGrantsCount,
    terminatedSessionsCount,
  };
}

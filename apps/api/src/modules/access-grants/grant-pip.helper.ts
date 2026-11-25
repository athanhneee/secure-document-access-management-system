/**
 * @module GrantPipHelper
 * Thuật toán: Tổng hợp thuộc tính Điểm Thông tin Chính sách (PIP) cho chủ thể cá nhân và chủ thể vai trò
 * theo phép giao bảo thủ (`Lattice Meet`) dùng 3 truy vấn lô `in: holderIds` (loại bỏ hoàn toàn lỗi `3 * N` N+1),
 * đồng bộ `EMPLOYMENT_STATUS` từ từ điển ABAC kèm fallback `user.status`.
 */
import type { getDatabaseClient } from '@sda/database';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

type SubjectProfile = {
  clearanceRank: number | null;
  departmentId: string | null;
  employmentStatus: string | null;
  projects: string[];
};

type RawAttrRow = {
  user_id?: bigint;
  value_text?: string | null;
  attribute_definitions?: { code?: string; is_active?: boolean } | null;
  attribute_options?: {
    value_code?: string;
    numeric_rank?: number | null;
    is_active?: boolean;
  } | null;
};

/**
 * Thuật toán: Truy vấn thứ bậc độ mật `CLEARANCE_LEVEL` cao nhất còn hiệu lực và đang kích hoạt (`is_active: true`) tại mốc `now`.
 */
export async function fetchUserClearanceRank(
  database: PrismaClient,
  userId: bigint,
  now: Date,
): Promise<number | null> {
  // CONFLICT-RESOLVED: Enforce `is_active: true` on both `attribute_definitions` and `attribute_options` across grant creation, PIP, and runtime enforcement.
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
  if (
    (clearance as { attribute_definitions?: { is_active?: boolean } } | null)?.attribute_definitions
      ?.is_active === false ||
    clearance?.attribute_options?.is_active === false
  ) {
    return null;
  }
  return clearance?.attribute_options?.numeric_rank ?? null;
}

/**
 * Thuật toán: Tổng hợp vector thuộc tính chủ thể cho động cơ đánh giá ABAC (`PIP Subject Attribute Builder`).
 * Truy vấn đồng thời `PROJECT` và `EMPLOYMENT_STATUS` đang hiệu lực (`is_active: true`), ưu tiên `EMPLOYMENT_STATUS`
 * từ từ điển ABAC (`value_code ?? value_text`) và giữ fallback `user?.status ?? null`.
 */
export async function buildGrantSubjectAttributes(
  database: PrismaClient,
  userId: bigint,
  now: Date = new Date(),
): Promise<SubjectProfile> {
  const user = await database.user.findUnique({
    where: { id: userId },
    select: { department_id: true, status: true },
  });
  const clearanceRank = await fetchUserClearanceRank(database, userId, now);
  let projects: string[] = [];
  let explicitEmploymentStatus: string | null = null;
  if (typeof database.userAttributeAssignment?.findMany === 'function') {
    const rows = (await database.userAttributeAssignment.findMany({
      where: {
        user_id: userId,
        attribute_definitions: { code: { in: ['PROJECT', 'EMPLOYMENT_STATUS'] }, is_active: true },
        valid_from: { lte: now },
        AND: [
          { OR: [{ valid_to: null }, { valid_to: { gt: now } }] },
          { OR: [{ option_id: null }, { attribute_options: { is_active: true } }] },
        ],
      },
      include: {
        attribute_definitions: { select: { code: true, is_active: true } },
        attribute_options: true,
      },
    })) as RawAttrRow[];
    const projectValues: string[] = [];
    for (const row of rows) {
      if (
        row.attribute_definitions?.is_active === false ||
        row.attribute_options?.is_active === false
      ) {
        continue;
      }
      const val = row.attribute_options?.value_code ?? row.value_text;
      if (typeof val !== 'string' || val.length === 0) continue;
      if (row.attribute_definitions?.code === 'EMPLOYMENT_STATUS') {
        explicitEmploymentStatus = val;
      } else {
        projectValues.push(val);
      }
    }
    projects = projectValues.sort();
  }
  return {
    clearanceRank,
    departmentId: user?.department_id?.toString() ?? null,
    // CONFLICT-RESOLVED: Đồng bộ subject.employmentStatus giữa PIP cấp phát quyền và Từ điển ABAC, giữ fallback user.status.
    employmentStatus: explicitEmploymentStatus ?? user?.status ?? null,
    projects,
  };
}

/**
 * Thuật toán: Tổng hợp thuộc tính chủ thể bảo thủ (`Lattice Meet`) cho cấp quyền theo vai trò `ROLE` bằng 3 truy vấn lô (`in: holderIds`).
 * Nạp đồng loạt người dùng, vai trò hiệu lực và thuộc tính `CLEARANCE_LEVEL` / `PROJECT` / `EMPLOYMENT_STATUS` trong `O(1)` lượt truy vấn SQL.
 */
export async function buildRoleGrantSubjectAttributes(
  database: PrismaClient,
  roleId: bigint,
  now: Date = new Date(),
): Promise<SubjectProfile & { holderCount: number }> {
  if (typeof database?.userRole?.findMany !== 'function') {
    return {
      clearanceRank: 0,
      departmentId: null,
      employmentStatus: 'ACTIVE',
      projects: [],
      holderCount: 0,
    };
  }
  const assignments = await database.userRole.findMany({
    where: {
      role_id: roleId,
      OR: [{ valid_to: null }, { valid_to: { gt: now } }],
      users_user_roles_user_idTousers: { status: { not: 'DISABLED' } },
    },
    select: { user_id: true },
  });
  const holderIds = [...new Set(assignments.map((a) => a.user_id))];
  if (holderIds.length === 0) {
    return {
      clearanceRank: 0,
      departmentId: null,
      employmentStatus: null,
      projects: [],
      holderCount: 0,
    };
  }

  let holderProfiles: SubjectProfile[];
  if (
    typeof database.user?.findMany === 'function' &&
    typeof database.userAttributeAssignment?.findMany === 'function'
  ) {
    const [users, activeRoleRows, attrRows] = await Promise.all([
      database.user.findMany({
        where: { id: { in: holderIds } },
        select: { id: true, department_id: true, status: true },
      }),
      database.userRole.findMany({
        where: {
          user_id: { in: holderIds },
          role_id: roleId,
          OR: [{ valid_to: null }, { valid_to: { gt: now } }],
        },
        select: { user_id: true },
      }),
      database.userAttributeAssignment.findMany({
        where: {
          user_id: { in: holderIds },
          valid_from: { lte: now },
          OR: [{ valid_to: null }, { valid_to: { gt: now } }],
          attribute_definitions: {
            code: { in: ['CLEARANCE_LEVEL', 'PROJECT', 'EMPLOYMENT_STATUS'] },
            is_active: true,
          },
        },
        include: {
          attribute_definitions: { select: { code: true, is_active: true } },
          attribute_options: true,
        },
      }),
    ]);

    const confirmedHolderKeys = new Set(activeRoleRows.map((r) => r.user_id.toString()));
    const userById = new Map(users.map((u) => [u.id.toString(), u]));
    const clearanceByUser = new Map<string, number>();
    const employmentStatusByUser = new Map<string, string>();
    const projectsByUser = new Map<string, Set<string>>();

    for (const row of attrRows as RawAttrRow[]) {
      const uid = row.user_id!.toString();
      const def = row.attribute_definitions;
      const opt = row.attribute_options;
      if (def?.is_active === false || opt?.is_active === false) continue;
      if (def?.code === 'CLEARANCE_LEVEL' && typeof opt?.numeric_rank === 'number') {
        const prev = clearanceByUser.get(uid);
        if (prev === undefined || opt.numeric_rank > prev)
          clearanceByUser.set(uid, opt.numeric_rank);
      } else if (def?.code === 'EMPLOYMENT_STATUS') {
        const statusVal = opt?.value_code ?? row.value_text;
        if (typeof statusVal === 'string' && statusVal.length > 0) {
          employmentStatusByUser.set(uid, statusVal);
        }
      } else if (def?.code === 'PROJECT') {
        const code = opt?.value_code ?? row.value_text;
        if (typeof code === 'string' && code.length > 0) {
          const set = projectsByUser.get(uid) ?? new Set<string>();
          set.add(code);
          projectsByUser.set(uid, set);
        }
      }
    }

    const effectiveHolderIds = holderIds.filter(
      (id) => confirmedHolderKeys.size === 0 || confirmedHolderKeys.has(id.toString()),
    );
    holderProfiles = effectiveHolderIds.map((id) => {
      const key = id.toString();
      const user = userById.get(key);
      return {
        clearanceRank: clearanceByUser.get(key) ?? null,
        departmentId: user?.department_id?.toString() ?? null,
        employmentStatus: employmentStatusByUser.get(key) ?? user?.status ?? null,
        projects: [...(projectsByUser.get(key) ?? [])].sort(),
      };
    });
  } else {
    holderProfiles = await Promise.all(
      holderIds.map((uid) => buildGrantSubjectAttributes(database, uid, now)),
    );
  }

  const minClearance = holderProfiles.reduce(
    (min, p) => Math.min(min, p.clearanceRank ?? 0),
    Number.POSITIVE_INFINITY,
  );
  const firstDept = holderProfiles[0]?.departmentId ?? null;
  const sharedDept = holderProfiles.every((p) => p.departmentId === firstDept) ? firstDept : null;
  const firstEmploymentStatus = holderProfiles[0]?.employmentStatus ?? null;
  const sharedEmploymentStatus =
    firstEmploymentStatus !== null &&
    holderProfiles.every((p) => p.employmentStatus === firstEmploymentStatus)
      ? firstEmploymentStatus
      : holderProfiles.every(
            (p) => p.employmentStatus === 'ACTIVE' || p.employmentStatus === 'ACTIVE_STAFF',
          )
        ? 'ACTIVE'
        : null;
  const sharedProjects = holderProfiles
    .slice(1)
    .reduce(
      (acc, p) => acc.filter((proj) => p.projects.includes(proj)),
      [...(holderProfiles[0]?.projects ?? [])],
    );

  return {
    clearanceRank: Number.isFinite(minClearance) ? minClearance : 0,
    departmentId: sharedDept,
    employmentStatus: sharedEmploymentStatus,
    projects: sharedProjects,
    holderCount: holderIds.length,
  };
}

/**
 * Thuật toán: Trích xuất vector thuộc tính tài nguyên tài liệu cho động cơ đánh giá ABAC.
 */
export function buildGrantResourceAttributes(
  document: {
    owner_id: bigint;
    department_id: bigint;
    status: string;
  },
  classification:
    | {
        classification_levels: { rank: number };
        business_categories?: { code: string };
      }
    | null
    | undefined,
) {
  return {
    classificationRank: classification?.classification_levels?.rank ?? null,
    ownerId: document.owner_id.toString(),
    departmentId: document.department_id.toString(),
    category: classification?.business_categories?.code ?? null,
    status: document.status,
  };
}

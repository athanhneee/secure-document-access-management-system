/**
 * @module GrantPipHelper
 * Algorithm: Policy Information Point (PIP) Attribute Aggregation & Trusted CIDR Network Detection.
 * Tổng hợp vector thuộc tính chủ thể, tài nguyên và mạng tin cậy CIDR cho động cơ ABAC.
 */
import type { getDatabaseClient } from '@sda/database';
import type { AppConfigService } from '../../config/config.service.js';
import { cidrMatch } from '../abac/policy-engine.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Algorithm / Thuật toán: Truy vấn thứ bậc độ mật `CLEARANCE_LEVEL` cao nhất còn hiệu lực và đang kích hoạt (`is_active: true` trên cả định nghĩa lẫn tùy chọn) của người dùng tại mốc `now`.
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
 * Algorithm / Thuật toán: Tổng hợp vector thuộc tính chủ thể cho động cơ đánh giá ABAC (PIP Subject Attribute Builder).
 * Thu thập độ mật cao nhất còn hiệu lực, phòng ban, trạng thái công tác và danh sách dự án đang kích hoạt đã sắp xếp từ điển tất định.
 */
export async function buildGrantSubjectAttributes(
  database: PrismaClient,
  userId: bigint,
  now: Date = new Date(),
): Promise<{
  clearanceRank: number | null;
  departmentId: string | null;
  employmentStatus: string | null;
  projects: string[];
}> {
  const user = await database.user.findUnique({
    where: { id: userId },
    select: { department_id: true, status: true },
  });

  const clearanceRank = await fetchUserClearanceRank(database, userId, now);

  let projects: string[] = [];
  if (typeof database.userAttributeAssignment?.findMany === 'function') {
    const projectAssignments = await database.userAttributeAssignment.findMany({
      where: {
        user_id: userId,
        attribute_definitions: { code: 'PROJECT', is_active: true },
        valid_from: { lte: now },
        AND: [
          { OR: [{ valid_to: null }, { valid_to: { gt: now } }] },
          { OR: [{ option_id: null }, { attribute_options: { is_active: true } }] },
        ],
      },
      include: { attribute_options: true },
    });
    projects = projectAssignments
      .filter(
        (a) =>
          (a as { attribute_options?: { is_active?: boolean } | null }).attribute_options
            ?.is_active !== false,
      )
      .map(
        (a) =>
          (
            a as {
              attribute_options?: { value_code?: string } | null;
              value_text?: string | null;
            }
          ).attribute_options?.value_code ?? (a as { value_text?: string | null }).value_text,
      )
      .filter((v): v is string => typeof v === 'string' && v.length > 0)
      .sort();
  }

  return {
    clearanceRank,
    departmentId: user?.department_id?.toString() ?? null,
    employmentStatus: user?.status ?? null,
    projects,
  };
}

/**
 * Algorithm / Thuật toán: Tổng hợp thuộc tính chủ thể bảo thủ (Lattice Meet) cho cấp quyền theo vai trò `ROLE` (HIGH-11).
 * Tuyệt đối không dùng độ mật/phòng ban của người cấp (`granter`); thay vào đó tính giá trị giao bảo thủ trên tập người giữ vai trò đang hoạt động.
 */
export async function buildRoleGrantSubjectAttributes(
  database: PrismaClient,
  roleId: bigint,
  now: Date = new Date(),
): Promise<{
  clearanceRank: number | null;
  departmentId: string | null;
  employmentStatus: string | null;
  projects: string[];
  holderCount: number;
}> {
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
      users: { status: { not: 'DISABLED' } },
    },
    select: { user_id: true },
  });

  const uniqueUserIds = [...new Set(assignments.map((a) => a.user_id))];
  if (uniqueUserIds.length === 0) {
    return {
      clearanceRank: 0,
      departmentId: null,
      employmentStatus: null,
      projects: [],
      holderCount: 0,
    };
  }

  const holderProfiles = await Promise.all(
    uniqueUserIds.map((uid) => buildGrantSubjectAttributes(database, uid, now)),
  );
  const minClearance = holderProfiles.reduce(
    (min, p) => Math.min(min, p.clearanceRank ?? 0),
    Number.POSITIVE_INFINITY,
  );
  const firstDept = holderProfiles[0]?.departmentId ?? null;
  const sharedDept = holderProfiles.every((p) => p.departmentId === firstDept) ? firstDept : null;
  const allActive = holderProfiles.every((p) => p.employmentStatus === 'ACTIVE');
  const sharedProjects = holderProfiles
    .slice(1)
    .reduce(
      (acc, p) => acc.filter((proj) => p.projects.includes(proj)),
      [...(holderProfiles[0]?.projects ?? [])],
    );

  return {
    clearanceRank: Number.isFinite(minClearance) ? minClearance : 0,
    departmentId: sharedDept,
    employmentStatus: allActive ? 'ACTIVE' : null,
    projects: sharedProjects,
    holderCount: uniqueUserIds.length,
  };
}

/**
 * Algorithm / Thuật toán: Trích xuất vector thuộc tính tài nguyên tài liệu cho động cơ đánh giá ABAC.
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
): {
  classificationRank: number | null;
  ownerId: string | null;
  departmentId: string | null;
  category: string | null;
  status: string | null;
} {
  return {
    classificationRank: classification?.classification_levels?.rank ?? null,
    ownerId: document.owner_id.toString(),
    departmentId: document.department_id.toString(),
    category: classification?.business_categories?.code ?? null,
    status: document.status,
  };
}

/**
 * Algorithm / Thuật toán: Kiểm tra IP nguồn của yêu cầu có thuộc danh sách dải mạng nội bộ tin cậy `ABAC_TRUSTED_NETWORK_CIDRS`.
 */
export function isTrustedClientNetwork(
  config: AppConfigService | undefined,
  clientIp: string,
): boolean {
  const rawTrustedCidrs =
    typeof config?.get === 'function' ? config.get('ABAC_TRUSTED_NETWORK_CIDRS') : undefined;
  if (typeof rawTrustedCidrs !== 'string' || rawTrustedCidrs.length === 0) return false;
  return rawTrustedCidrs
    .split(',')
    .map((c) => c.trim())
    .filter(Boolean)
    .some((cidr) => cidrMatch(clientIp, cidr));
}

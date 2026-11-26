import type {
  DepartmentRow,
  HealthDashboardResponse,
  HealthReadyResponse,
  HealthStatusLabel,
  PermissionRow,
  RoleRow,
  SystemHealthData,
  UserRow,
} from './types';

export {
  normalizeAbacPolicyRow,
  normalizeAttributeDefinitionRow,
  normalizeVisualObligations,
  resolveVisualRuleForPolicy,
} from './abac-helpers';

export {
  buildDepartmentNameMap,
  computeUserFilterFacets,
  DEFAULT_USER_LIST_QUERY,
  filterAndSortUsers,
  formatUserSortOption,
  hasActiveUserFilters,
  isNonDefaultUserQuery,
  matchesUserActionFilter,
  parseUserSortOption,
  resolveUserDepartmentName,
  toggleUserSort,
  UNASSIGNED_DEPARTMENT_LABEL,
  USER_SORT_OPTIONS,
} from './users-query';
export type {
  DepartmentFacetOption,
  SortDirection,
  UserActionFilter,
  UserDepartmentFilter,
  UserFilterFacets,
  UserListQueryState,
  UserSortField,
  UserSortOption,
  UserSortOptionKey,
  UserStatusFilter,
} from './users-query';

/**
 * Thuật toán: Tìm kiếm Định danh Người dùng Đa Trường Không Phân biệt Hoa Thường (`filterUsersByQuery`)
 * Mục đích: Lọc tức thời danh sách tài khoản theo chuỗi con khớp trên họ tên, tên đăng nhập, thư điện tử hoặc mã nhân viên (`O(N)`).
 */
export function filterUsersByQuery(users: UserRow[], searchQuery: string): UserRow[] {
  const query = searchQuery.trim().toLowerCase();
  if (!query) return [...users];
  return users.filter(
    (u) =>
      u.fullName.toLowerCase().includes(query) ||
      u.username.toLowerCase().includes(query) ||
      u.email.toLowerCase().includes(query) ||
      (u.employeeCode ?? '').toLowerCase().includes(query),
  );
}

/**
 * Thuật toán: Tra Cứu Nhãn Đơn Vị Cấp Cha Trên Cây Tổ Chức (`resolveParentDepartmentLabel`)
 */
export function resolveParentDepartmentLabel(
  departments: DepartmentRow[],
  parentId: string | null,
): string {
  if (!parentId) return 'Trụ sở chính';
  return departments.find((d) => d.id === parentId)?.name || parentId;
}

/**
 * Thuật toán: Duyệt Chiều Rộng BFS Bao Đóng Cây Con Phòng Ban Chống Chu Trình (`collectDepartmentSubtreeIds`, BUG-120)
 * Mục đích: Thu thập tập hợp định danh gồm chính nút `rootId` và toàn bộ các phòng ban con cháu trực tiếp/gián tiếp
 * trong thời gian tuyến tính `O(V)` với tập `visited` chống lặp vô hạn để loại trừ khỏi danh sách phòng ban cấp trên.
 */
export function collectDepartmentSubtreeIds(
  departments: ReadonlyArray<Pick<DepartmentRow, 'id' | 'parentId'>>,
  rootId: string,
): Set<string> {
  const childrenByParent = new Map<string, string[]>();
  for (const dept of departments) {
    if (dept.parentId !== null && dept.parentId !== undefined && dept.parentId !== '') {
      const parentKey = String(dept.parentId);
      const bucket = childrenByParent.get(parentKey);
      if (bucket) {
        bucket.push(String(dept.id));
      } else {
        childrenByParent.set(parentKey, [String(dept.id)]);
      }
    }
  }

  const visited = new Set<string>();
  const queue: string[] = [String(rootId)];
  let head = 0;
  while (head < queue.length) {
    const current = queue[head++]!;
    if (visited.has(current)) continue;
    visited.add(current);
    const children = childrenByParent.get(current);
    if (children) {
      for (const childId of children) {
        if (!visited.has(childId)) {
          queue.push(childId);
        }
      }
    }
  }
  return visited;
}

/** Khoảng dung sai lệch đồng hồ 5 phút khớp máy chủ khi gán vai trò (`BUG-093`). */
export const CLIENT_PAST_TOLERANCE_MS = 5 * 60_000;

/**
 * Thuật toán: Định Dạng Mốc Thời Gian Cục Bộ ISO-8601 & Khung Hiệu Lực Vai Trò 30 Ngày (`getDefaultRoleAssignmentWindow`)
 */
export function formatLocalDateTimeInput(d: Date): string {
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function getDefaultRoleAssignmentWindow(): { validFrom: string; validTo: string } {
  const now = new Date();
  const nextMonth = new Date(Date.now() + 30 * 86400000);
  return {
    validFrom: formatLocalDateTimeInput(now),
    validTo: formatLocalDateTimeInput(nextMonth),
  };
}

/**
 * Thuật toán: Nhận Diện Phản Hồi Sức Khỏe Hạ Tầng Suy Giảm Thực Sự (`503`) Khác Biệt Với Lỗi Kết Nối Mạng (`isGenuineHealthPayload`, BUG-091)
 * Mục đích: Chỉ coi phản hồi lỗi là dữ liệu sức khỏe hợp lệ khi có cấu trúc `dependencies` hoặc `checks` từ điểm cuối `/health/*`,
 * tuyệt đối không bịa đặt trạng thái `OFFLINE` giả cho toàn bộ dịch vụ khi trình duyệt rớt mạng tạm thời.
 */
export function isGenuineHealthPayload(raw: unknown): raw is Record<string, unknown> {
  if (!raw || typeof raw !== 'object') return false;
  const obj = raw as Record<string, unknown>;
  const hasDependencies =
    'dependencies' in obj &&
    typeof obj['dependencies'] === 'object' &&
    obj['dependencies'] !== null;
  const hasChecks = 'checks' in obj && typeof obj['checks'] === 'object' && obj['checks'] !== null;
  return hasDependencies || hasChecks;
}

/**
 * Thuật toán: Chuẩn Hóa Trạng Thái Thăm Dò Sức Khỏe Hạ Tầng Không Phân Biệt Hoa Thường (`mapHealthReadyResponse`)
 * Mục đích: Ánh xạ trung thực phản hồi `/health/ready` (kể cả mã 503 chữ thường `'ready'`/`'up'`/`'degraded'`/`'down'`) và `/health/dashboard` (bao gồm `checks.storage` và bộ nhớ tiến trình `Heap / RSS`) sang miền trạng thái giao diện `ONLINE | DEGRADED | OFFLINE`.
 */
function normalizeProbeStatus(
  raw: string | undefined,
  fallback: HealthStatusLabel = 'OFFLINE',
): HealthStatusLabel {
  const upper = raw?.trim().toUpperCase();
  if (
    upper === 'READY' ||
    upper === 'UP' ||
    upper === 'ONLINE' ||
    upper === 'OK' ||
    upper === 'HEALTHY'
  ) {
    return 'ONLINE';
  }
  if (upper === 'DEGRADED') return 'DEGRADED';
  if (upper === 'DOWN' || upper === 'OFFLINE' || upper === 'ERROR' || upper === 'UNHEALTHY') {
    return 'OFFLINE';
  }
  return fallback;
}

export function mapHealthReadyResponse(
  ready?: HealthReadyResponse | null,
  dashboard?: HealthDashboardResponse | null,
): SystemHealthData {
  const checks = ready?.checks ?? dashboard?.dependencies?.checks;
  const overallStatus: HealthStatusLabel = ready?.status
    ? normalizeProbeStatus(ready.status, 'OFFLINE')
    : dashboard?.dependencies?.isReady !== undefined
      ? dashboard.dependencies.isReady
        ? 'ONLINE'
        : 'DEGRADED'
      : 'OFFLINE';

  return {
    status: overallStatus,
    database: {
      status: normalizeProbeStatus(checks?.database?.status, 'OFFLINE'),
      ...(checks?.database?.latencyMs !== undefined
        ? { latencyMs: checks.database.latencyMs }
        : {}),
    },
    cache: {
      status: normalizeProbeStatus(checks?.redis?.status, 'OFFLINE'),
      ...(checks?.redis?.latencyMs !== undefined ? { latencyMs: checks.redis.latencyMs } : {}),
    },
    storage: {
      status: normalizeProbeStatus(checks?.storage?.status, 'OFFLINE'),
      ...(checks?.storage?.latencyMs !== undefined ? { latencyMs: checks.storage.latencyMs } : {}),
    },
    uptimeSeconds: dashboard?.process?.uptimeSeconds ?? ready?.uptimeSeconds ?? 0,
    ...(dashboard?.process
      ? {
          memory: {
            heapUsedMb: dashboard.process.heapUsedMb,
            heapTotalMb: dashboard.process.heapTotalMb,
            rssMb: dashboard.process.rssMb,
          },
        }
      : {}),
  };
}

/**
 * Thuật toán: Giao Tập Mã Quyền Vai Trò Sang Danh Sách Định Danh Danh Mục (`resolveRolePermissionIds`)
 */
export function resolveRolePermissionIds(role: RoleRow, permissions: PermissionRow[]): string[] {
  const currentPermCodes = role.permissions.map((p) => p.code);
  return permissions.filter((p) => currentPermCodes.includes(p.code)).map((p) => p.id);
}

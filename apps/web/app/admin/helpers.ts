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
  resolveVisualRuleForPolicy,
} from './abac-helpers';

/**
 * Thuật toán: Tìm kiếm Định danh Người dùng Đa Trường Không Phân biệt Hoa Thường (`filterUsersByQuery`)
 * Mục đích: Lọc tức thời danh sách tài khoản theo chuỗi con khớp trên họ tên, tên đăng nhập hoặc thư điện tử (`O(N)`).
 */
export function filterUsersByQuery(users: UserRow[], searchQuery: string): UserRow[] {
  const query = searchQuery.toLowerCase();
  return users.filter(
    (u) =>
      u.fullName.toLowerCase().includes(query) ||
      u.username.toLowerCase().includes(query) ||
      u.email.toLowerCase().includes(query),
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
 * Thuật toán: Định Dạng Mốc Thời Gian Cục Bộ ISO-8601 & Khung Hiệu Lực Vai Trò 30 Ngày (`formatLocalDateTimeInput`)
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
 * Thuật toán: Chuẩn Hóa Trạng Thái Thăm Dò Sức Khỏe Hạ Tầng Không Phân Biệt Hoa Thường (`normalizeProbeStatus` & `mapHealthReadyResponse`)
 * Mục đích: Ánh xạ trung thực phản hồi `/health/ready` (kể cả mã 503 chữ thường `'ready'`/`'up'`/`'degraded'`/`'down'`) và `/health/dashboard` sang miền trạng thái giao diện `ONLINE | DEGRADED | OFFLINE`.
 */
export function normalizeProbeStatus(
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
    },
    uptimeSeconds: dashboard?.process?.uptimeSeconds ?? ready?.uptimeSeconds ?? 0,
  };
}

/**
 * Thuật toán: Giao Tập Mã Quyền Vai Trò Sang Danh Sách Định Danh Danh Mục (`resolveRolePermissionIds`)
 */
export function resolveRolePermissionIds(role: RoleRow, permissions: PermissionRow[]): string[] {
  const currentPermCodes = role.permissions.map((p) => p.code);
  return permissions.filter((p) => currentPermCodes.includes(p.code)).map((p) => p.id);
}

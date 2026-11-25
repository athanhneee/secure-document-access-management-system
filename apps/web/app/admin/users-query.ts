/**
 * Thuật toán: Lọc Đa Chiều & Sắp Xếp Định Danh Nhân Sự Theo Bảng Chữ Cái Tiếng Việt (`users-query`)
 * Mục đích:
 *   - Hỗ trợ lọc kết hợp (tìm kiếm đa trường, trạng thái vòng đời, phòng ban bao gồm "Chưa gán", và thao tác khả dụng như "Vô hiệu", "Khóa", "Mở khóa", "Kích hoạt") trong `O(N)`.
 *   - Hỗ trợ sắp xếp bất biến, ổn định và xác định theo `Trạng thái`, `Phòng ban`, `Thao tác`, `Tài khoản` hoặc `Email` với `Intl.Collator('vi')` trong `O(N log N)`.
 */

export interface UserQueryRecord {
  id: string;
  username: string;
  fullName: string;
  email: string;
  employeeCode?: string | null | undefined;
  status: string;
  departmentId: string | null;
  clearanceCode?: string | null | undefined;
  clearanceName?: string | null | undefined;
  clearanceRank?: number | undefined;
}

export interface DepartmentQueryRecord {
  id: string;
  name: string;
}

export type UserStatusFilter = 'ALL' | 'ACTIVE' | 'LOCKED' | 'DISABLED' | 'PENDING';
export type UserDepartmentFilter = 'ALL' | 'UNASSIGNED' | (string & {});
export type UserActionFilter = 'ALL' | 'DISABLE' | 'LOCK' | 'UNLOCK' | 'REACTIVATE';
export type UserSortField = 'status' | 'department' | 'clearance' | 'action' | 'fullName' | 'email';
export type SortDirection = 'asc' | 'desc';
export type UserSortOptionKey = `${UserSortField}:${SortDirection}`;

export interface UserListQueryState {
  searchQuery: string;
  statusFilter: UserStatusFilter;
  departmentFilter: UserDepartmentFilter;
  actionFilter: UserActionFilter;
  sortField: UserSortField;
  sortDirection: SortDirection;
}

export interface UserSortOption {
  value: UserSortOptionKey;
  label: string;
}

export interface DepartmentFacetOption {
  id: string;
  name: string;
  count: number;
}

export interface UserFilterFacets {
  statusCounts: Record<'ACTIVE' | 'LOCKED' | 'DISABLED' | 'PENDING', number>;
  actionCounts: Record<'DISABLE' | 'LOCK' | 'UNLOCK' | 'REACTIVATE', number>;
  departmentOptions: DepartmentFacetOption[];
  unassignedDepartmentCount: number;
}

export const UNASSIGNED_DEPARTMENT_LABEL = 'Chưa gán';

export const DEFAULT_USER_LIST_QUERY: UserListQueryState = {
  searchQuery: '',
  statusFilter: 'ALL',
  departmentFilter: 'ALL',
  actionFilter: 'ALL',
  sortField: 'status',
  sortDirection: 'asc',
};

export const USER_SORT_OPTIONS: readonly UserSortOption[] = [
  { value: 'status:asc', label: 'Trạng thái: ACTIVE → Vô hiệu' },
  { value: 'status:desc', label: 'Trạng thái: Vô hiệu → ACTIVE' },
  { value: 'clearance:desc', label: 'Độ mật: Cao → Thấp' },
  { value: 'clearance:asc', label: 'Độ mật: Thấp → Cao' },
  { value: 'department:asc', label: 'Phòng ban: A → Z' },
  { value: 'department:desc', label: 'Phòng ban: Z → A' },
  { value: 'action:asc', label: 'Thao tác: Vô hiệu trước' },
  { value: 'action:desc', label: 'Thao tác: Kích hoạt trước' },
  { value: 'fullName:asc', label: 'Tài khoản: A → Z' },
  { value: 'fullName:desc', label: 'Tài khoản: Z → A' },
  { value: 'email:asc', label: 'Email: A → Z' },
  { value: 'email:desc', label: 'Email: Z → A' },
];

const VI_COLLATOR = new Intl.Collator('vi', { sensitivity: 'base', numeric: true });

const STATUS_PRIORITY_RANK: Record<string, number> = {
  ACTIVE: 0,
  LOCKED: 1,
  PENDING: 2,
  DISABLED: 3,
};

const ACTION_PRIORITY_RANK: Record<string, number> = {
  ACTIVE: 0, // Khóa + Vô hiệu
  LOCKED: 1, // Mở khóa + Vô hiệu
  PENDING: 2, // Vô hiệu
  DISABLED: 3, // Kích hoạt
};

const VALID_SORT_FIELDS = new Set<UserSortField>([
  'status',
  'department',
  'clearance',
  'action',
  'fullName',
  'email',
]);

function normalizeStatus(status: string): string {
  return status.trim().toUpperCase();
}

function getStatusRank(status: string): number {
  return STATUS_PRIORITY_RANK[normalizeStatus(status)] ?? 99;
}

function getActionRank(status: string): number {
  return ACTION_PRIORITY_RANK[normalizeStatus(status)] ?? 99;
}

/**
 * Thuật toán: Lập Chỉ Mục Tra Cứu Tên Phòng Ban `O(D)` (`buildDepartmentNameMap`)
 */
export function buildDepartmentNameMap(
  departments: readonly DepartmentQueryRecord[],
): Map<string, string> {
  const map = new Map<string, string>();
  for (const dept of departments) {
    map.set(String(dept.id), dept.name);
  }
  return map;
}

/**
 * Thuật toán: Phân Giải Nhãn Phòng Ban Của Tài Khoản Trong `O(1)` (`resolveUserDepartmentName`)
 */
export function resolveUserDepartmentName(
  user: Pick<UserQueryRecord, 'departmentId'>,
  departmentNamesById: ReadonlyMap<string, string>,
): string | null {
  if (user.departmentId === null || user.departmentId === '') return null;
  return departmentNamesById.get(String(user.departmentId)) ?? null;
}

/**
 * Thuật toán: Khớp Tài Khoản Với Bộ Lọc Thao Tác Khả Dụng Trên Cột `Thao tác` (`matchesUserActionFilter`)
 */
export function matchesUserActionFilter(status: string, actionFilter: UserActionFilter): boolean {
  const normalized = normalizeStatus(status);
  switch (actionFilter) {
    case 'ALL':
      return true;
    case 'DISABLE':
      return normalized !== 'DISABLED';
    case 'LOCK':
      return normalized === 'ACTIVE';
    case 'UNLOCK':
      return normalized === 'LOCKED';
    case 'REACTIVATE':
      return normalized === 'DISABLED';
  }
}

export function formatUserSortOption(
  sortField: UserSortField,
  sortDirection: SortDirection,
): UserSortOptionKey {
  return `${sortField}:${sortDirection}`;
}

export function parseUserSortOption(raw: string): {
  sortField: UserSortField;
  sortDirection: SortDirection;
} {
  const [rawField, rawDir] = raw.split(':');
  const sortField = VALID_SORT_FIELDS.has(rawField as UserSortField)
    ? (rawField as UserSortField)
    : DEFAULT_USER_LIST_QUERY.sortField;
  const sortDirection: SortDirection = rawDir === 'desc' ? 'desc' : 'asc';
  return { sortField, sortDirection };
}

export function toggleUserSort(
  currentField: UserSortField,
  currentDirection: SortDirection,
  nextField: UserSortField,
): { sortField: UserSortField; sortDirection: SortDirection } {
  if (currentField === nextField) {
    return {
      sortField: nextField,
      sortDirection: currentDirection === 'asc' ? 'desc' : 'asc',
    };
  }
  return {
    sortField: nextField,
    sortDirection: 'asc',
  };
}

export function hasActiveUserFilters(query: UserListQueryState): boolean {
  return (
    query.searchQuery.trim().length > 0 ||
    query.statusFilter !== 'ALL' ||
    query.departmentFilter !== 'ALL' ||
    query.actionFilter !== 'ALL'
  );
}

export function isNonDefaultUserQuery(query: UserListQueryState): boolean {
  return (
    hasActiveUserFilters(query) ||
    query.sortField !== DEFAULT_USER_LIST_QUERY.sortField ||
    query.sortDirection !== DEFAULT_USER_LIST_QUERY.sortDirection
  );
}

/**
 * Thuật toán: Tổng Hợp Số Lượng Từng Nhóm Trạng Thái, Phòng Ban & Thao Tác Trong Một Lượt Duyệt `O(N + D log D)` (`computeUserFilterFacets`)
 */
export function computeUserFilterFacets(
  users: readonly UserQueryRecord[],
  departments: readonly DepartmentQueryRecord[],
): UserFilterFacets {
  const departmentNamesById = buildDepartmentNameMap(departments);
  const statusCounts: UserFilterFacets['statusCounts'] = {
    ACTIVE: 0,
    LOCKED: 0,
    DISABLED: 0,
    PENDING: 0,
  };
  const actionCounts: UserFilterFacets['actionCounts'] = {
    DISABLE: 0,
    LOCK: 0,
    UNLOCK: 0,
    REACTIVATE: 0,
  };
  const deptCounts = new Map<string, number>();
  let unassignedDepartmentCount = 0;

  for (const user of users) {
    const normalizedStatus = normalizeStatus(user.status);
    if (
      normalizedStatus === 'ACTIVE' ||
      normalizedStatus === 'LOCKED' ||
      normalizedStatus === 'DISABLED' ||
      normalizedStatus === 'PENDING'
    ) {
      statusCounts[normalizedStatus] += 1;
    }

    if (matchesUserActionFilter(normalizedStatus, 'DISABLE')) actionCounts.DISABLE += 1;
    if (matchesUserActionFilter(normalizedStatus, 'LOCK')) actionCounts.LOCK += 1;
    if (matchesUserActionFilter(normalizedStatus, 'UNLOCK')) actionCounts.UNLOCK += 1;
    if (matchesUserActionFilter(normalizedStatus, 'REACTIVATE')) actionCounts.REACTIVATE += 1;

    const deptName = resolveUserDepartmentName(user, departmentNamesById);
    if (deptName === null) {
      unassignedDepartmentCount += 1;
    } else {
      const deptKey = String(user.departmentId);
      deptCounts.set(deptKey, (deptCounts.get(deptKey) ?? 0) + 1);
    }
  }

  const departmentOptions: DepartmentFacetOption[] = [...departments]
    .map((dept) => {
      const id = String(dept.id);
      return {
        id,
        name: dept.name,
        count: deptCounts.get(id) ?? 0,
      };
    })
    .sort((a, b) => VI_COLLATOR.compare(a.name, b.name));

  return {
    statusCounts,
    actionCounts,
    departmentOptions,
    unassignedDepartmentCount,
  };
}

/**
 * Thuật toán: Lọc Đa Chiều Kết Hợp Sắp Xếp Xác Định Danh Sách Tài Khoản (`filterAndSortUsers`)
 * Mục đích: Kết hợp bộ lọc tìm kiếm, trạng thái, phòng ban và thao tác khả dụng, sau đó sắp xếp bất biến theo tiêu chí đã chọn với bộ phá vỡ hòa nhất quán.
 */
export function filterAndSortUsers<T extends UserQueryRecord>(
  users: readonly T[],
  departments: readonly DepartmentQueryRecord[],
  query: UserListQueryState,
): T[] {
  const departmentNamesById = buildDepartmentNameMap(departments);
  const normalizedQuery = query.searchQuery.trim().toLowerCase();
  const dirMultiplier = query.sortDirection === 'desc' ? -1 : 1;

  const filtered = users.filter((user) => {
    const normalizedStatus = normalizeStatus(user.status);
    const resolvedDeptName = resolveUserDepartmentName(user, departmentNamesById);

    if (query.statusFilter !== 'ALL' && normalizedStatus !== query.statusFilter) {
      return false;
    }

    if (query.departmentFilter === 'UNASSIGNED') {
      if (resolvedDeptName !== null) return false;
    } else if (query.departmentFilter !== 'ALL') {
      if (resolvedDeptName === null || String(user.departmentId) !== query.departmentFilter) {
        return false;
      }
    }

    if (!matchesUserActionFilter(normalizedStatus, query.actionFilter)) {
      return false;
    }

    if (normalizedQuery.length > 0) {
      const deptLabel = (resolvedDeptName ?? UNASSIGNED_DEPARTMENT_LABEL).toLowerCase();
      const employeeCode = (user.employeeCode ?? '').toLowerCase();
      const clearanceText =
        `${user.clearanceName ?? 'chưa cấp'} ${user.clearanceCode ?? ''}`.toLowerCase();
      const matchesText =
        user.fullName.toLowerCase().includes(normalizedQuery) ||
        user.username.toLowerCase().includes(normalizedQuery) ||
        user.email.toLowerCase().includes(normalizedQuery) ||
        employeeCode.includes(normalizedQuery) ||
        deptLabel.includes(normalizedQuery) ||
        clearanceText.includes(normalizedQuery) ||
        normalizedStatus.toLowerCase().includes(normalizedQuery);
      if (!matchesText) return false;
    }

    return true;
  });

  return filtered.sort((a, b) => {
    const deptA = resolveUserDepartmentName(a, departmentNamesById);
    const deptB = resolveUserDepartmentName(b, departmentNamesById);

    let primaryCmp = 0;

    switch (query.sortField) {
      case 'status':
        primaryCmp = getStatusRank(a.status) - getStatusRank(b.status);
        break;
      case 'clearance':
        primaryCmp = (a.clearanceRank ?? 0) - (b.clearanceRank ?? 0);
        break;
      case 'department':
        if (deptA === null && deptB === null) {
          primaryCmp = 0;
        } else if (deptA === null) {
          primaryCmp = 1;
        } else if (deptB === null) {
          primaryCmp = -1;
        } else {
          primaryCmp = VI_COLLATOR.compare(deptA, deptB);
        }
        break;
      case 'action':
        primaryCmp = getActionRank(a.status) - getActionRank(b.status);
        break;
      case 'fullName':
        primaryCmp = VI_COLLATOR.compare(a.fullName, b.fullName);
        break;
      case 'email':
        primaryCmp = VI_COLLATOR.compare(a.email, b.email);
        break;
    }

    if (primaryCmp !== 0) {
      return primaryCmp * dirMultiplier;
    }

    if (query.sortField === 'department') {
      const statusTie = getStatusRank(a.status) - getStatusRank(b.status);
      if (statusTie !== 0) return statusTie;
    }

    const nameTie = VI_COLLATOR.compare(a.fullName, b.fullName);
    if (nameTie !== 0) return nameTie;

    const usernameTie = VI_COLLATOR.compare(a.username, b.username);
    if (usernameTie !== 0) return usernameTie;

    return VI_COLLATOR.compare(String(a.id), String(b.id));
  });
}

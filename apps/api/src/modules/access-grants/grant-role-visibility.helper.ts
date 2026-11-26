/**
 * @module GrantRoleVisibilityHelper
 * Thuật toán: Phân giải phạm vi hiển thị giấy phép theo vai trò (`principal_type = 'ROLE'`)
 * có đối chiếu bao đóng cây phòng ban `user_roles.scope_department_id` với `documents.department_id` (BUG-110).
 * Đảm bảo giao diện Người đọc chỉ hiển thị các giấy phép vai trò mà cổng PEP thực sự cho phép truy cập.
 */
import type { getDatabaseClient } from '@sda/database';
import type { AuthorizationService } from '../rbac/authorization.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface ActiveUserRoleScope {
  roleId: bigint;
  scopeDepartmentId: bigint | null;
}

/**
 * Thuật toán: Truy vấn danh sách gán vai trò đang hiệu lực của người dùng (`valid_from <= now`, `valid_to` rỗng hoặc tương lai, vai trò và phòng ban phạm vi đang hoạt động).
 */
export async function loadActiveUserRoleScopes(
  database: PrismaClient,
  userId: bigint,
  now: Date = new Date(),
): Promise<ActiveUserRoleScope[]> {
  if (typeof database?.userRole?.findMany !== 'function') {
    return [];
  }

  const rows = await database.userRole
    .findMany({
      where: {
        user_id: userId,
        valid_from: { lte: now },
        AND: [
          { OR: [{ valid_to: null }, { valid_to: { gt: now } }] },
          { OR: [{ scope_department_id: null }, { departments: { is: { is_active: true } } }] },
        ],
        roles: { is_active: true },
      },
      select: {
        role_id: true,
        scope_department_id: true,
      },
    })
    .catch(() => []);

  return rows.map((row) => ({
    roleId: row.role_id,
    scopeDepartmentId: row.scope_department_id ?? null,
  }));
}

/**
 * Thuật toán: Kiểm tra `docDepartmentId` có thuộc cây con của `scopeDepartmentId` hay không (ưu tiên `AuthorizationService.departmentWithinScope`, dự phòng duyệt ngược tổ tiên chống chu trình).
 */
export async function isDocumentDepartmentWithinRoleScope(
  database: PrismaClient,
  authorization: AuthorizationService | undefined,
  docDepartmentId: bigint | null | undefined,
  scopeDepartmentId: bigint | null,
): Promise<boolean> {
  if (scopeDepartmentId === null) return true;
  if (docDepartmentId === null || docDepartmentId === undefined) return false;
  if (docDepartmentId === scopeDepartmentId) return true;

  if (authorization && typeof authorization.departmentWithinScope === 'function') {
    return authorization.departmentWithinScope(docDepartmentId, scopeDepartmentId);
  }

  if (typeof database?.department?.findUnique !== 'function') {
    return false;
  }

  const visited = new Set<bigint>();
  let current: bigint | null = docDepartmentId;
  while (current !== null && !visited.has(current)) {
    if (current === scopeDepartmentId) return true;
    visited.add(current);
    const dept: { parent_id: bigint | null } | null = await database.department.findUnique({
      where: { id: current },
      select: { parent_id: true },
    });
    current = dept?.parent_id ?? null;
  }
  return false;
}

/**
 * Thuật toán: Xác minh người dùng hiện hành có nắm giữ vai trò `roleId` bao phủ phòng ban tài liệu `docDepartmentId` hay không.
 */
export async function canUserReadRoleGrant(params: {
  database: PrismaClient;
  authorization?: AuthorizationService | undefined;
  userId: bigint;
  roleId: bigint;
  docDepartmentId: bigint | null | undefined;
  now?: Date | undefined;
}): Promise<boolean> {
  const { database, authorization, userId, roleId, docDepartmentId, now } = params;
  if (typeof database?.userRole?.findMany === 'function') {
    const activeRoles = await loadActiveUserRoleScopes(database, userId, now);
    const matching = activeRoles.filter((r) => r.roleId === roleId);
    if (matching.length === 0) return false;

    for (const assignment of matching) {
      if (
        await isDocumentDepartmentWithinRoleScope(
          database,
          authorization,
          docDepartmentId,
          assignment.scopeDepartmentId,
        )
      ) {
        return true;
      }
    }
    return false;
  }

  // Fallback tương thích mock kiểm thử đơn vị chỉ cài `userRole.findFirst`
  if (typeof database?.userRole?.findFirst === 'function') {
    const effectiveNow = now ?? new Date();
    const row = await database.userRole.findFirst({
      where: {
        user_id: userId,
        role_id: roleId,
        valid_from: { lte: effectiveNow },
        AND: [
          { OR: [{ valid_to: null }, { valid_to: { gt: effectiveNow } }] },
          { OR: [{ scope_department_id: null }, { departments: { is: { is_active: true } } }] },
        ],
        roles: { is_active: true },
      },
      select: { role_id: true, scope_department_id: true },
    });
    if (!row) return false;
    return isDocumentDepartmentWithinRoleScope(
      database,
      authorization,
      docDepartmentId,
      row.scope_department_id ?? null,
    );
  }

  return false;
}

export interface ScopedRoleSqlAccess {
  globalRoleIds: bigint[];
  scopedRoleDepts: Array<{ roleId: bigint; departmentIds: bigint[] }>;
}

/**
 * Thuật toán: Tách vai trò hiệu lực của người dùng thành 2 tập phục vụ truy vấn SQL có đối chiếu `scope_department_id` (HIGH-02):
 *   - `globalRoleIds`: các vai trò gắn phạm vi toàn cục (`scope_department_id IS NULL`).
 *   - `scopedRoleDepts`: các vai trò giới hạn phòng ban kèm bao đóng cây con các phòng ban đang `is_active = true`.
 */
export async function resolveScopedRoleAccessForSql(params: {
  database: PrismaClient;
  authorization?: AuthorizationService | undefined;
  userId: bigint;
  now?: Date | undefined;
}): Promise<ScopedRoleSqlAccess> {
  const { database, authorization, userId, now } = params;
  let activeRoles: ActiveUserRoleScope[] = [];

  if (authorization && typeof authorization.effectiveGrants === 'function') {
    const grants = await authorization.effectiveGrants(userId);
    const seen = new Set<string>();
    for (const g of grants) {
      const scopeId = g.scopeDepartmentId ?? null;
      const key = `${g.roleId.toString()}:${scopeId === null ? 'null' : scopeId.toString()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      activeRoles.push({ roleId: g.roleId, scopeDepartmentId: scopeId });
    }
  } else {
    activeRoles = await loadActiveUserRoleScopes(database, userId, now);
  }

  if (activeRoles.length === 0) {
    return { globalRoleIds: [], scopedRoleDepts: [] };
  }

  const globalRoleIds = new Set<bigint>();
  const scopedRootsByRole = new Map<bigint, Set<bigint>>();

  for (const assignment of activeRoles) {
    if (assignment.scopeDepartmentId === null) {
      globalRoleIds.add(assignment.roleId);
      scopedRootsByRole.delete(assignment.roleId);
    } else if (!globalRoleIds.has(assignment.roleId)) {
      let roots = scopedRootsByRole.get(assignment.roleId);
      if (!roots) {
        roots = new Set<bigint>();
        scopedRootsByRole.set(assignment.roleId, roots);
      }
      roots.add(assignment.scopeDepartmentId);
    }
  }

  const scopedRoleDepts: Array<{ roleId: bigint; departmentIds: bigint[] }> = [];
  if (scopedRootsByRole.size > 0) {
    const activeDepartments =
      typeof database?.department?.findMany === 'function'
        ? await database.department
            .findMany({ where: { is_active: true }, select: { id: true, parent_id: true } })
            .catch(() => null)
        : null;
    const activeDeptIdSet = activeDepartments
      ? new Set<bigint>(activeDepartments.map((d) => d.id))
      : null;

    for (const [roleId, rootIds] of scopedRootsByRole.entries()) {
      const validRoots = activeDeptIdSet
        ? new Set<bigint>([...rootIds].filter((id) => activeDeptIdSet.has(id)))
        : rootIds;
      if (validRoots.size === 0) continue;
      const subtree = expandDepartmentSubtreeInMemory(validRoots, activeDepartments);
      if (subtree.size > 0) {
        scopedRoleDepts.push({ roleId, departmentIds: [...subtree] });
      }
    }
  }

  return {
    globalRoleIds: [...globalRoleIds],
    scopedRoleDepts,
  };
}

/**
 * Thuật toán: Khai triển bao đóng cây con phòng ban cho các vai trò giới hạn phạm vi và sinh mảng nhánh `OR` Prisma cho `listGrants`.
 */
export async function buildReceivedRoleGrantOrBranches(params: {
  database: PrismaClient;
  authorization?: AuthorizationService | undefined;
  userId: bigint;
  documentScope?: { documentId: string; departmentId: bigint | null | undefined } | undefined;
}): Promise<Record<string, unknown>[]> {
  const { database, authorization, userId, documentScope } = params;
  const activeRoles = await loadActiveUserRoleScopes(database, userId);
  if (activeRoles.length === 0) return [];

  if (documentScope) {
    const matchedRoleIds = new Set<bigint>();
    for (const assignment of activeRoles) {
      if (matchedRoleIds.has(assignment.roleId)) continue;
      const withinScope = await isDocumentDepartmentWithinRoleScope(
        database,
        authorization,
        documentScope.departmentId,
        assignment.scopeDepartmentId,
      );
      if (withinScope) {
        matchedRoleIds.add(assignment.roleId);
      }
    }
    if (matchedRoleIds.size === 0) return [];
    return [{ principal_type: 'ROLE', principal_role_id: { in: [...matchedRoleIds] } }];
  }

  const globalRoleIds = new Set<bigint>();
  const scopedRootsByRole = new Map<bigint, Set<bigint>>();

  for (const assignment of activeRoles) {
    if (assignment.scopeDepartmentId === null) {
      globalRoleIds.add(assignment.roleId);
      scopedRootsByRole.delete(assignment.roleId);
    } else if (!globalRoleIds.has(assignment.roleId)) {
      let roots = scopedRootsByRole.get(assignment.roleId);
      if (!roots) {
        roots = new Set<bigint>();
        scopedRootsByRole.set(assignment.roleId, roots);
      }
      roots.add(assignment.scopeDepartmentId);
    }
  }

  const branches: Record<string, unknown>[] = [];
  if (globalRoleIds.size > 0) {
    branches.push({
      principal_type: 'ROLE',
      principal_role_id: { in: [...globalRoleIds] },
      documents: { status: { not: 'DELETED' } },
    });
  }

  if (scopedRootsByRole.size > 0) {
    const allDepartments =
      typeof database?.department?.findMany === 'function'
        ? await database.department
            .findMany({ where: { is_active: true }, select: { id: true, parent_id: true } })
            .catch(() => null)
        : null;
    const activeDeptIdSet = allDepartments
      ? new Set<bigint>(allDepartments.map((d) => d.id))
      : null;

    for (const [roleId, rootIds] of scopedRootsByRole.entries()) {
      const validRoots = activeDeptIdSet
        ? new Set<bigint>([...rootIds].filter((id) => activeDeptIdSet.has(id)))
        : rootIds;
      if (validRoots.size === 0) continue;
      const subtree = expandDepartmentSubtreeInMemory(validRoots, allDepartments);
      branches.push({
        principal_type: 'ROLE',
        principal_role_id: roleId,
        documents: {
          status: { not: 'DELETED' },
          department_id: { in: [...subtree] },
        },
      });
    }
  }

  return branches;
}

/**
 * Thuật toán: Tính bao đóng bắc cầu cây con phòng ban trong bộ nhớ có tập `subtree` chống chu trình.
 */
function expandDepartmentSubtreeInMemory(
  roots: ReadonlySet<bigint>,
  departments: ReadonlyArray<{ id: bigint; parent_id: bigint | null }> | null,
): Set<bigint> {
  const subtree = new Set<bigint>(roots);
  if (!departments || departments.length === 0) return subtree;

  let changed = true;
  while (changed) {
    changed = false;
    for (const dept of departments) {
      if (dept.parent_id !== null && subtree.has(dept.parent_id) && !subtree.has(dept.id)) {
        subtree.add(dept.id);
        changed = true;
      }
    }
  }
  return subtree;
}

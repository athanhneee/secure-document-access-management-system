import type { DepartmentRow } from './types';

export interface AssignableRoleScopeOption {
  value: string;
  scopeDepartmentId: string | null;
  label: string;
}

export interface BuildAssignableRoleScopeOptionsInput {
  targetDepartmentId: string | null | undefined;
  departments: readonly DepartmentRow[];
  hasGlobalUserManage?: boolean | undefined;
  userManageDepartmentIds?: readonly string[] | undefined;
}

/**
 * Thuật toán: Xây Dựng Tập Phạm Vi Phòng Ban Hợp Lệ Khi Gán Vai Trò Theo Chuỗi Tổ Tiên (`buildAssignableRoleScopeOptions`, BUG-038)
 * Mục đích:
 *   - Chỉ hiển thị "Toàn hệ thống" (`scopeDepartmentId: null`) khi người gán sở hữu quyền `USER:MANAGE` toàn cục.
 *   - Duyệt ngược từ `targetUser.departmentId` lên các phòng ban cha tổ tiên đang hoạt động (có tập `visited` chống chu trình) để đảm bảo mọi phạm vi được chọn đều chứa phòng ban của người nhận (tuân thủ điều kiện BE `departmentWithinScope`).
 *   - Nếu người gán chỉ có quyền `USER:MANAGE` theo phòng ban, chỉ giữ các nút nằm trong cây con thuộc phạm vi quản trị của người gán và mặc định chọn sẵn phòng ban hợp lệ đầu tiên.
 */
export function buildAssignableRoleScopeOptions(
  input: BuildAssignableRoleScopeOptionsInput,
): AssignableRoleScopeOption[] {
  const { targetDepartmentId, departments, hasGlobalUserManage, userManageDepartmentIds } = input;

  const canAssignGlobal =
    typeof hasGlobalUserManage === 'boolean'
      ? hasGlobalUserManage
      : !(Array.isArray(userManageDepartmentIds) && userManageDepartmentIds.length > 0);

  const allById = new Map<string, DepartmentRow>();
  const activeById = new Map<string, DepartmentRow>();
  for (const dept of departments) {
    const key = String(dept.id);
    allById.set(key, dept);
    if (dept.isActive) {
      activeById.set(key, dept);
    }
  }

  const collectAncestors = (startId: string): Set<string> => {
    const ancestors = new Set<string>();
    let current: string | null = startId;
    while (current && !ancestors.has(current)) {
      ancestors.add(current);
      const row = allById.get(current);
      if (!row) break;
      current = row.parentId !== null && row.parentId !== undefined ? String(row.parentId) : null;
    }
    return ancestors;
  };

  const targetAncestorChain: DepartmentRow[] = [];
  const visitedTargetWalk = new Set<string>();
  let cursor =
    targetDepartmentId !== null && targetDepartmentId !== undefined && targetDepartmentId !== ''
      ? String(targetDepartmentId)
      : null;

  while (cursor && !visitedTargetWalk.has(cursor)) {
    visitedTargetWalk.add(cursor);
    const dept = activeById.get(cursor);
    if (!dept) break;
    targetAncestorChain.push(dept);
    cursor = dept.parentId !== null && dept.parentId !== undefined ? String(dept.parentId) : null;
  }

  const adminScopeSet =
    !canAssignGlobal && Array.isArray(userManageDepartmentIds) && userManageDepartmentIds.length > 0
      ? new Set(userManageDepartmentIds.map(String))
      : null;

  const manageableAncestorChain = targetAncestorChain.filter((candidate) => {
    if (canAssignGlobal || adminScopeSet === null) return true;
    const candidateAncestors = collectAncestors(String(candidate.id));
    for (const ancId of candidateAncestors) {
      if (adminScopeSet.has(ancId)) return true;
    }
    return false;
  });

  const options: AssignableRoleScopeOption[] = [];
  if (canAssignGlobal) {
    options.push({
      value: '',
      scopeDepartmentId: null,
      label: 'Toàn hệ thống (Không giới hạn phòng ban)',
    });
  }

  manageableAncestorChain.forEach((dept, idx) => {
    const deptId = String(dept.id);
    const isDirectTargetDept =
      targetDepartmentId !== null &&
      targetDepartmentId !== undefined &&
      deptId === String(targetDepartmentId);
    const prefix = isDirectTargetDept || idx === 0 ? 'Phòng ban trực thuộc' : 'Phòng ban cấp trên';
    options.push({
      value: deptId,
      scopeDepartmentId: deptId,
      label: `${prefix}: ${dept.name} (${dept.code})`,
    });
  });

  return options;
}

/**
 * @module AuthorizationService
 * Dịch vụ phân giải quyền RBAC có phạm vi phân cấp phòng ban (Hierarchical Scoped RBAC):
 * tính bao đóng bắc cầu cây phòng ban, kiểm tra thống trị ủy quyền chống leo thang đặc quyền
 * và duyệt ngược tổ tiên có bảo vệ chu trình.
 */
import { ForbiddenException, Injectable } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import type { AuthPrincipal } from '../auth/auth.types.js';
import { AuthorizationCache, type EffectiveGrant } from './authorization-cache.js';

@Injectable()
export class AuthorizationService {
  private readonly database = getDatabaseClient();

  constructor(private readonly cache: AuthorizationCache) {}

  /**
   * Thuật toán: Tổng hợp và trải phẳng tập quyền hiệu lực theo cửa sổ thời gian (Temporal Effective-Grant Materialization).
   * Cơ chế hoạt động: Chỉ lấy các phép gán thỏa `valid_from <= now < valid_to` của người dùng `ACTIVE`, vai trò `is_active`
   * và phòng ban phạm vi (nếu có) đang `is_active`, sau đó tích Đề-các phẳng qua `role_permissions` và lưu vào cache cắt trần TTL.
   */
  async effectiveGrants(userId: bigint): Promise<EffectiveGrant[]> {
    const cached = this.cache.get(userId);
    if (cached) return cached;
    const now = new Date();
    const assignments = await this.database.userRole.findMany({
      where: {
        user_id: userId,
        valid_from: { lte: now },
        AND: [
          { OR: [{ valid_to: null }, { valid_to: { gt: now } }] },
          { OR: [{ scope_department_id: null }, { departments: { is: { is_active: true } } }] },
        ],
        roles: { is_active: true },
        users_user_roles_user_idTousers: { status: 'ACTIVE' },
      },
      include: {
        roles: {
          include: {
            role_permissions: { include: { permissions: true } },
          },
        },
      },
    });
    const grants = assignments.flatMap((assignment) =>
      assignment.roles.role_permissions.map((mapping) => ({
        permissionId: mapping.permissions.id,
        code: mapping.permissions.code,
        resource: mapping.permissions.resource_type,
        action: mapping.permissions.action,
        roleId: assignment.roles.id,
        roleCode: assignment.roles.code,
        scopeDepartmentId: assignment.scope_department_id,
        validTo: assignment.valid_to,
      })),
    );
    this.cache.set(userId, grants);
    return grants;
  }

  /**
   * Thuật toán: Kiểm tra quyền phân cấp theo tổ tiên phòng ban (Hierarchical Scope Dominance Check).
   * Cơ chế hoạt động:
   *   - Nếu đòi phạm vi toàn cục (`requireGlobal`) hoặc không truyền phòng ban đích: bắt buộc có grant `scopeDepartmentId === null`.
   *   - Nếu có `targetDepartmentId`: thu tập tổ tiên của phòng ban đích (`departmentAncestors`) và chấp nhận nếu người dùng
   *     nắm grant toàn cục (`null`) hoặc nắm grant tại bất kỳ nút tổ tiên nào bao hàm phòng ban đích.
   */
  async hasPermission(
    principal: AuthPrincipal,
    resource: string,
    action: string,
    options: {
      targetDepartmentId?: bigint | null;
      requireGlobal?: boolean;
      anyScope?: boolean;
    } = {},
  ): Promise<boolean> {
    const matching = (await this.effectiveGrants(principal.userId)).filter(
      (grant) => grant.resource === resource && grant.action === action,
    );
    if (options.requireGlobal) return matching.some((grant) => grant.scopeDepartmentId === null);
    if (options.anyScope) return matching.length > 0;
    if (options.targetDepartmentId == null) {
      return matching.some((grant) => grant.scopeDepartmentId === null);
    }
    const ancestors = await this.departmentAncestors(options.targetDepartmentId);
    return matching.some(
      (grant) => grant.scopeDepartmentId === null || ancestors.has(grant.scopeDepartmentId),
    );
  }

  /**
   * Thuật toán: Cưỡng chế quyền truy cập hoặc ném ngoại lệ HTTP 403 (Fail-Closed Permission Assertion).
   */
  async assertPermission(
    principal: AuthPrincipal,
    resource: string,
    action: string,
    options: {
      targetDepartmentId?: bigint | null;
      requireGlobal?: boolean;
      anyScope?: boolean;
    } = {},
  ): Promise<void> {
    if (!(await this.hasPermission(principal, resource, action, options))) {
      throw new ForbiddenException('Permission is not granted for this resource scope.');
    }
  }

  /**
   * Thuật toán: Kiểm tra bất biến thống trị ủy quyền chống khuếch đại đặc quyền (Anti-Escalation Grant Dominance Check).
   * Cơ chế hoạt động: Với MỌI `permissionId` định cấp cho người khác tại phạm vi `targetDepartmentId`, người cấp
   * bắt buộc phải đang sở hữu chính quyền đó ở phạm vi toàn cục (`null`) hoặc ở một phòng ban tổ tiên bao trùm `targetDepartmentId`.
   */
  async assertCanDelegate(
    principal: AuthPrincipal,
    permissionIds: bigint[],
    targetDepartmentId: bigint | null,
  ): Promise<void> {
    const grants = await this.effectiveGrants(principal.userId);
    const ancestors =
      targetDepartmentId === null
        ? new Set<bigint>()
        : await this.departmentAncestors(targetDepartmentId);
    const allowed = permissionIds.every((permissionId) =>
      grants.some(
        (grant) =>
          grant.permissionId === permissionId &&
          (targetDepartmentId === null
            ? grant.scopeDepartmentId === null
            : grant.scopeDepartmentId === null || ancestors.has(grant.scopeDepartmentId)),
      ),
    );
    if (!allowed) {
      throw new ForbiddenException('Cannot delegate permissions outside the administrator grant.');
    }
  }

  /**
   * Thuật toán: Tính bao đóng bắc cầu cây con phòng ban bằng lặp điểm bất động tương đương BFS (Transitive Closure Fixed-Point Traversal).
   * Cơ chế hoạt động:
   *   1. Nếu có ít nhất một quyền phạm vi toàn cục (`scopeDepartmentId === null`), trả về `null` (không giới hạn phòng ban).
   *   2. Khởi tạo tập hạt giống `visible` từ các phòng ban gốc được cấp quyền.
   *   3. Lặp mở rộng biên đồ thị: nạp mọi nút con có `parent_id` thuộc `visible` cho tới khi đạt điểm bất động (`changed === false`).
   */
  async visibleDepartmentIds(
    principal: AuthPrincipal,
    resource: string,
    action: string,
  ): Promise<bigint[] | null> {
    const matching = (await this.effectiveGrants(principal.userId)).filter(
      (grant) => grant.resource === resource && grant.action === action,
    );
    if (matching.some((grant) => grant.scopeDepartmentId === null)) return null;
    const roots = matching.flatMap((grant) =>
      grant.scopeDepartmentId === null ? [] : [grant.scopeDepartmentId],
    );
    if (roots.length === 0) return [];
    const departments = await this.database.department.findMany({
      select: { id: true, parent_id: true },
    });
    const visible = new Set(roots);
    let changed = true;
    while (changed) {
      changed = false;
      for (const department of departments) {
        if (
          department.parent_id !== null &&
          visible.has(department.parent_id) &&
          !visible.has(department.id)
        ) {
          visible.add(department.id);
          changed = true;
        }
      }
    }
    return [...visible];
  }

  invalidateUser(userId: bigint): void {
    this.cache.invalidateUser(userId);
  }

  invalidateAll(): void {
    this.cache.invalidateAll();
  }

  /**
   * Thuật toán: Kiểm tra quan hệ bao hàm phòng ban con nằm trong cây con của `scopeDepartmentId`.
   */
  async departmentWithinScope(departmentId: bigint, scopeDepartmentId: bigint): Promise<boolean> {
    return (await this.departmentAncestors(departmentId)).has(scopeDepartmentId);
  }

  /**
   * Thuật toán: Duyệt ngược đường đi tổ tiên có tập đánh dấu chống lặp vô hạn khi có chu trình (Cycle-Safe Ancestor Walk).
   * Cơ chế hoạt động: Đi ngược liên kết `parent_id` từ nút hiện tại lên gốc và ghi nhận vào `Set<bigint>`;
   * dừng ngay lập tức nếu chạm `null` hoặc gặp đỉnh đã thăm (`!ancestors.has(current)`).
   */
  private async departmentAncestors(departmentId: bigint): Promise<Set<bigint>> {
    const ancestors = new Set<bigint>();
    let current: bigint | null = departmentId;
    while (current !== null && !ancestors.has(current)) {
      ancestors.add(current);
      const department: { parent_id: bigint | null } | null =
        await this.database.department.findUnique({
          where: { id: current },
          select: { parent_id: true },
        });
      current = department?.parent_id ?? null;
    }
    return ancestors;
  }
}

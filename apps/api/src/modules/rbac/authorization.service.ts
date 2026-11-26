/**
 * @module AuthorizationService
 * Dịch vụ phân giải quyền RBAC có phạm vi phân cấp phòng ban (Hierarchical Scoped RBAC):
 * tính bao đóng bắc cầu cây phòng ban bằng truy vấn đệ quy SQL `WITH RECURSIVE`, kiểm tra thống trị ủy quyền
 * chống leo thang đặc quyền, hỗ trợ tái sử dụng `Prisma.TransactionClient` chống tự khóa chết pool kết nối (`BUG-048`)
 * và chụp tem Epoch trước truy vấn CSDL chống đầu độc cache phân tán (`BUG-043`).
 */
import { ForbiddenException, Injectable } from '@nestjs/common';
import { getDatabaseClient, type Prisma } from '@sda/database';
import type { AuthPrincipal } from '../auth/auth.types.js';
import { AuthorizationCache, type EffectiveGrant } from './authorization-cache.js';

export interface PermissionCheckOptions {
  targetDepartmentId?: bigint | null;
  requireGlobal?: boolean;
  anyScope?: boolean;
  tx?: Prisma.TransactionClient | undefined;
}

@Injectable()
export class AuthorizationService {
  private readonly database = getDatabaseClient();

  constructor(private readonly cache: AuthorizationCache) {}

  /**
   * Thuật toán: Tổng hợp và trải phẳng tập quyền hiệu lực theo cửa sổ thời gian (Temporal Effective-Grant Materialization).
   *   - Khi truyền `tx` của giao dịch `SERIALIZABLE` đang mở: truy vấn trực tiếp trên `tx` (0 kết nối phụ, bảo toàn cô lập chống TOCTOU) và không ghi dữ liệu chưa commit vào cache chia sẻ (`BUG-048`).
   *   - Khi chạy ngoài giao dịch: chụp tem `(generation, globalEpoch, userEpoch)` trước khi đọc CSDL và ghi cache qua Lua CAS (`BUG-043`).
   */
  async effectiveGrants(userId: bigint, tx?: Prisma.TransactionClient): Promise<EffectiveGrant[]> {
    const canQueryOnTx = tx !== undefined && typeof tx.userRole?.findMany === 'function';
    if (canQueryOnTx) {
      return this.queryEffectiveGrantsFromClient(tx, userId);
    }

    const { grants: cached, stamp } =
      typeof this.cache.getOrCaptureStamp === 'function'
        ? await this.cache.getOrCaptureStamp(userId)
        : {
            grants: await this.cache.get(userId),
            stamp:
              typeof this.cache.captureStamp === 'function'
                ? await this.cache.captureStamp(userId)
                : undefined,
          };
    if (cached) return cached;

    const grants = await this.queryEffectiveGrantsFromClient(this.database, userId);
    await this.cache.set(userId, grants, undefined, undefined, stamp);
    return grants;
  }

  private async queryEffectiveGrantsFromClient(
    client: Pick<Prisma.TransactionClient, 'userRole'>,
    userId: bigint,
  ): Promise<EffectiveGrant[]> {
    const now = new Date();
    const assignments = await client.userRole.findMany({
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
    return assignments.flatMap((assignment) =>
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
  }

  /**
   * Thuật toán: Kiểm tra quyền phân cấp theo tổ tiên phòng ban (Hierarchical Scope Dominance Check) có hỗ trợ tái sử dụng `tx`.
   */
  async hasPermission(
    principal: AuthPrincipal,
    resource: string,
    action: string,
    options: PermissionCheckOptions = {},
    tx?: Prisma.TransactionClient,
  ): Promise<boolean> {
    const activeTx = tx ?? options.tx;
    const matching = (await this.effectiveGrants(principal.userId, activeTx)).filter(
      (grant) => grant.resource === resource && grant.action === action,
    );
    if (options.requireGlobal) return matching.some((grant) => grant.scopeDepartmentId === null);
    if (options.anyScope) return matching.length > 0;
    if (options.targetDepartmentId == null) {
      return matching.some((grant) => grant.scopeDepartmentId === null);
    }
    const ancestors = await this.departmentAncestors(options.targetDepartmentId, activeTx);
    return matching.some(
      (grant) => grant.scopeDepartmentId === null || ancestors.has(grant.scopeDepartmentId),
    );
  }

  /**
   * Thuật toán: Cưỡng chế quyền truy cập hoặc ném ngoại lệ HTTP 403 (Fail-Closed Permission Assertion) có hỗ trợ tái sử dụng `tx`.
   */
  async assertPermission(
    principal: AuthPrincipal,
    resource: string,
    action: string,
    options: PermissionCheckOptions = {},
    tx?: Prisma.TransactionClient,
  ): Promise<void> {
    if (!(await this.hasPermission(principal, resource, action, options, tx))) {
      throw new ForbiddenException('Permission is not granted for this resource scope.');
    }
  }

  /**
   * Thuật toán: Kiểm tra bất biến thống trị ủy quyền chống khuếch đại đặc quyền (Anti-Escalation Grant Dominance Check) có hỗ trợ tái sử dụng `tx`.
   */
  async assertCanDelegate(
    principal: AuthPrincipal,
    permissionIds: bigint[],
    targetDepartmentId: bigint | null,
    tx?: Prisma.TransactionClient,
  ): Promise<void> {
    const grants = await this.effectiveGrants(principal.userId, tx);
    const ancestors =
      targetDepartmentId === null
        ? new Set<bigint>()
        : await this.departmentAncestors(targetDepartmentId, tx);
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
   * Thuật toán: Tính bao đóng bắc cầu cây con phòng ban bằng CTE đệ quy SQL `WITH RECURSIVE` chống chu trình (`ARRAY[d.id]`).
   * Chỉ rơi về duyệt lặp trong bộ nhớ khi đối tượng Prisma giả lập trong kiểm thử đơn vị không có `$queryRaw`.
   */
  async visibleDepartmentIds(
    principal: AuthPrincipal,
    resource: string,
    action: string,
    tx?: Prisma.TransactionClient,
  ): Promise<bigint[] | null> {
    const matching = (await this.effectiveGrants(principal.userId, tx)).filter(
      (grant) => grant.resource === resource && grant.action === action,
    );
    if (matching.some((grant) => grant.scopeDepartmentId === null)) return null;
    const roots = [
      ...new Set(
        matching.flatMap((grant) =>
          grant.scopeDepartmentId === null ? [] : [grant.scopeDepartmentId],
        ),
      ),
    ];
    if (roots.length === 0) return [];
    const activeDb =
      tx && (typeof tx.$queryRaw === 'function' || typeof tx.department?.findMany === 'function')
        ? tx
        : this.database;
    if (typeof activeDb?.$queryRaw === 'function') {
      const rootStrings = roots.map((id) => id.toString());
      const rows = await activeDb.$queryRaw<Array<{ id: bigint }>>`
        WITH RECURSIVE subtree AS (
          SELECT d.id, ARRAY[d.id] AS visited
          FROM departments d
          WHERE d.id = ANY((${rootStrings}::text[])::bigint[])
          UNION ALL
          SELECT c.id, s.visited || c.id
          FROM departments c
          INNER JOIN subtree s ON c.parent_id = s.id
          WHERE NOT (c.id = ANY(s.visited))
        )
        SELECT DISTINCT id FROM subtree
      `;
      return rows.map((row) => BigInt(row.id));
    }
    const departments = await activeDb.department.findMany({
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

  async invalidateUser(userId: bigint): Promise<void> {
    await this.cache.invalidateUser(userId);
  }

  async invalidateAll(): Promise<void> {
    await this.cache.invalidateAll();
  }

  /**
   * Thuật toán: Kiểm tra quan hệ bao hàm phòng ban con nằm trong cây con của `scopeDepartmentId` (hỗ trợ tái sử dụng `tx`).
   */
  async departmentWithinScope(
    departmentId: bigint,
    scopeDepartmentId: bigint,
    tx?: Prisma.TransactionClient,
  ): Promise<boolean> {
    return (await this.departmentAncestors(departmentId, tx)).has(scopeDepartmentId);
  }

  /**
   * Thuật toán: Truy vấn đường đi tổ tiên đơn truy vấn bằng `WITH RECURSIVE` kèm mảng `visited` chống chu trình (hỗ trợ tái sử dụng `tx` chống tự khóa chết pool `BUG-048`);
   * dự phòng sang duyệt lặp `findUnique` khi mock kiểm thử không hỗ trợ `$queryRaw`.
   */
  private async departmentAncestors(
    departmentId: bigint,
    tx?: Prisma.TransactionClient,
  ): Promise<Set<bigint>> {
    const activeDb =
      tx && (typeof tx.$queryRaw === 'function' || typeof tx.department?.findUnique === 'function')
        ? tx
        : this.database;
    if (typeof activeDb?.$queryRaw === 'function') {
      const rows = await activeDb.$queryRaw<Array<{ id: bigint }>>`
        WITH RECURSIVE ancestor_tree AS (
          SELECT d.id, d.parent_id, ARRAY[d.id] AS visited
          FROM departments d
          WHERE d.id = ${departmentId}
          UNION ALL
          SELECT p.id, p.parent_id, a.visited || p.id
          FROM departments p
          INNER JOIN ancestor_tree a ON p.id = a.parent_id
          WHERE NOT (p.id = ANY(a.visited))
        )
        SELECT id FROM ancestor_tree
      `;
      return new Set(rows.map((row) => BigInt(row.id)));
    }
    const ancestors = new Set<bigint>();
    let current: bigint | null = departmentId;
    while (current !== null && !ancestors.has(current)) {
      ancestors.add(current);
      const department: { parent_id: bigint | null } | null = await activeDb.department.findUnique({
        where: { id: current },
        select: { parent_id: true },
      });
      current = department?.parent_id ?? null;
    }
    return ancestors;
  }
}

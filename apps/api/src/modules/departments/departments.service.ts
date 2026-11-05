/**
 * Module: Quản lý Cây Phân cấp Phòng ban Tổ chức (Hierarchical Department Tree Service)
 * Thuật toán: Thao tác cây cha-con với cô lập giao dịch `Serializable`, kiểm soát đồng thời lạc quan
 *   Compare-And-Swap (`expectedVersion`), phát hiện chu trình bằng duyệt ngược tổ tiên có tập `visited`
 *   và kiểm tra toàn vẹn tham chiếu trước khi vô hiệu hóa nút phòng ban.
 */
import { ConflictException, Injectable, NotFoundException, Optional } from '@nestjs/common';
import { getDatabaseClient, withSerializableTransaction } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { RbacAuditService } from '../rbac/rbac-audit.service.js';
import {
  assertDepartmentHasNoActiveDependents,
  isDepartmentDescendant,
  presentDepartment,
} from './department-tree.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

const DEPARTMENT_SELECT = {
  id: true,
  code: true,
  name: true,
  parent_id: true,
  is_active: true,
  version: true,
} as const;

@Injectable()
export class DepartmentsService {
  private readonly database: PrismaClient;

  constructor(
    private readonly authorization: AuthorizationService,
    private readonly audit: RbacAuditService,
    @Optional() databaseClient?: PrismaClient,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Thuật toán: Lọc Cây Phòng Ban Theo Phạm Vi Quyền Quản Trị (Scope-Filtered Department Listing)
   * Mục đích: Chỉ trả về tập các nút phòng ban nằm trong phạm vi quản lý của người gọi.
   */
  async list(principal: AuthPrincipal) {
    const visible = await this.authorization.visibleDepartmentIds(
      principal,
      'DEPARTMENT',
      'MANAGE',
    );
    const departments = await this.database.department.findMany({
      where: visible === null ? {} : { id: { in: visible } },
      orderBy: [{ code: 'asc' }, { id: 'asc' }],
      select: DEPARTMENT_SELECT,
    });
    return { data: departments.map((department) => presentDepartment(department)) };
  }

  /**
   * Thuật toán: Tra Cứu Danh Mục Phòng Ban Đang Hoạt Động (Active Department Directory Lookup)
   * Mục đích: Cung cấp danh sách rút gọn `(id, code, name)` của các phòng ban đang mở cho giao diện chọn lựa.
   */
  async lookup() {
    const departments = await this.database.department.findMany({
      where: { is_active: true },
      orderBy: [{ code: 'asc' }, { id: 'asc' }],
      select: { id: true, code: true, name: true },
    });
    return {
      data: departments.map((d) => ({
        id: d.id.toString(),
        code: d.code,
        name: d.name,
      })),
    };
  }

  /**
   * Thuật toán: Truy Xuất Nút Phòng Ban Chống Lộ Tồn Tại (Anti-Enumeration Node Fetch)
   * Mục đích: Nạp chi tiết phòng ban nếu và chỉ nếu nút tồn tại và người gọi có quyền quản trị trên phạm vi đó.
   */
  async get(principal: AuthPrincipal, id: bigint) {
    const department = await this.database.department.findUnique({
      where: { id },
      select: DEPARTMENT_SELECT,
    });
    if (
      !department ||
      !(await this.authorization.hasPermission(principal, 'DEPARTMENT', 'MANAGE', {
        targetDepartmentId: id,
      }))
    ) {
      throw new NotFoundException('Department not found.');
    }
    return presentDepartment(department);
  }

  /**
   * Thuật toán: Thêm Nút Con Vào Cây Phòng Ban Trong Giao Dịch Cô Lập Tuần Tự (Serializable Tree Node Insertion)
   * Mục đích: Tạo phòng ban gốc hoặc phòng ban trực thuộc nút cha đang hoạt động kèm ghi kiểm toán nguyên tử.
   */
  async create(
    principal: AuthPrincipal,
    input: { code: string; name: string; parentId?: bigint | null | undefined },
    context: RequestContext,
  ) {
    await this.authorization.assertPermission(principal, 'DEPARTMENT', 'MANAGE', {
      targetDepartmentId: input.parentId ?? null,
    });
    const department = await withSerializableTransaction(
      async (transaction) => {
        if (input.parentId !== null && input.parentId !== undefined) {
          const parent = await transaction.department.findFirst({
            where: { id: input.parentId, is_active: true },
          });
          if (!parent) throw new NotFoundException('Active parent department not found.');
        }
        const created = await transaction.department.create({
          data: { code: input.code, name: input.name, parent_id: input.parentId ?? null },
        });
        await this.audit.record(
          transaction,
          {
            action: 'DEPARTMENT_CREATED',
            objectType: 'DEPARTMENT',
            objectId: created.id.toString(),
            before: null,
            after: presentDepartment(created),
          },
          principal,
          context,
        );
        return created;
      },
      { client: this.database },
    );
    return presentDepartment(department);
  }

  /**
   * Thuật toán: Tái Cấu Trúc Nhánh Cây Phòng Ban Chống Chu Trình Kèm CAS Lạc Quan (Cycle-Safe Tree Reparenting)
   * Mục đích: Đổi tên hoặc di chuyển phòng ban sang nút cha mới mà không tạo chu trình khép kín trên cây phân cấp,
   *   đồng thời chống ghi đè mất dữ liệu khi có cập nhật đồng thời.
   */
  async update(
    principal: AuthPrincipal,
    id: bigint,
    input: {
      expectedVersion: number;
      name?: string | undefined;
      parentId?: bigint | null | undefined;
    },
    context: RequestContext,
  ) {
    const department = await withSerializableTransaction(
      async (transaction) => {
        const before = await transaction.department.findUnique({ where: { id } });
        if (
          !before ||
          !(await this.authorization.hasPermission(principal, 'DEPARTMENT', 'MANAGE', {
            targetDepartmentId: id,
          }))
        ) {
          throw new NotFoundException('Department not found.');
        }
        if (input.parentId === id) {
          throw new ConflictException('Department cannot be its own parent.');
        }
        if (input.parentId !== null && input.parentId !== undefined) {
          await this.authorization.assertPermission(principal, 'DEPARTMENT', 'MANAGE', {
            targetDepartmentId: input.parentId,
          });
          const parent = await transaction.department.findFirst({
            where: { id: input.parentId, is_active: true },
          });
          if (!parent) throw new NotFoundException('Active parent department not found.');
          if (await isDepartmentDescendant(transaction, input.parentId, id)) {
            throw new ConflictException('Department hierarchy cycle is not allowed.');
          }
        }
        const changed = await transaction.department.updateMany({
          where: { id, version: input.expectedVersion },
          data: {
            ...(input.name !== undefined ? { name: input.name } : {}),
            ...(input.parentId !== undefined ? { parent_id: input.parentId } : {}),
            updated_at: new Date(),
            version: { increment: 1 },
          },
        });
        if (changed.count !== 1) {
          throw new ConflictException('Department was changed by another request.');
        }
        const after = await transaction.department.findUniqueOrThrow({ where: { id } });
        await this.audit.record(
          transaction,
          {
            action: 'DEPARTMENT_UPDATED',
            objectType: 'DEPARTMENT',
            objectId: id.toString(),
            before: presentDepartment(before),
            after: presentDepartment(after),
          },
          principal,
          context,
        );
        return after;
      },
      { client: this.database },
    );
    this.authorization.invalidateAll();
    return presentDepartment(department);
  }

  /**
   * Thuật toán: Vô Hiệu Hóa Nút Lá Có Kiểm Chứng Toàn Vẹn Tham Chiếu (Referential-Integrity Leaf Deactivation)
   * Mục đích: Chỉ cho phép ngưng hoạt động phòng ban khi không còn bất kỳ phụ thuộc hoạt động nào.
   */
  async deactivate(
    principal: AuthPrincipal,
    id: bigint,
    expectedVersion: number,
    context: RequestContext,
  ) {
    const department = await withSerializableTransaction(
      async (transaction) => {
        const before = await transaction.department.findUnique({ where: { id } });
        if (
          !before ||
          !(await this.authorization.hasPermission(principal, 'DEPARTMENT', 'MANAGE', {
            targetDepartmentId: id,
          }))
        ) {
          throw new NotFoundException('Department not found.');
        }
        const now = new Date();
        await assertDepartmentHasNoActiveDependents(transaction, id, now);
        const changed = await transaction.department.updateMany({
          where: { id, version: expectedVersion },
          data: { is_active: false, updated_at: now, version: { increment: 1 } },
        });
        if (changed.count !== 1) {
          throw new ConflictException('Department was changed by another request.');
        }
        const after = await transaction.department.findUniqueOrThrow({ where: { id } });
        await this.audit.record(
          transaction,
          {
            action: 'DEPARTMENT_DEACTIVATED',
            objectType: 'DEPARTMENT',
            objectId: id.toString(),
            before: presentDepartment(before),
            after: presentDepartment(after),
          },
          principal,
          context,
        );
        return after;
      },
      { client: this.database },
    );
    this.authorization.invalidateAll();
    return presentDepartment(department);
  }
}

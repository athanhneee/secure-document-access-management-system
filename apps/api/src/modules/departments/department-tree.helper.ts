/**
 * Module: Bộ Trợ Giúp Đồ Thị Phân Cấp & Toàn Vẹn Tham Chiếu Phòng Ban (Department Tree & Referential Integrity Helpers)
 * Thuật toán: Duyệt ngược chuỗi tổ tiên kèm tập đỉnh đã thăm O(H) để chặn chu trình cây và kiểm chứng
 *   song song các ràng buộc tham chiếu đang hoạt động trước khi vô hiệu hóa nút lá.
 */
import { ConflictException } from '@nestjs/common';
import type { Prisma } from '@sda/database';

export interface PresentableDepartment {
  id: bigint;
  code: string;
  name: string;
  parent_id: bigint | null;
  is_active: boolean;
  version: number;
}

/**
 * Thuật toán: Duyệt Ngược Chuỗi Tổ Tiên Kèm Tập Đã Thăm Để Phát Hiện Chu Trình Cây (Upward Ancestor Walk with Visited Cycle Guard)
 * Mục đích: Kiểm tra xem nút `candidate` (nút cha dự kiến mới) có nằm trong cây con của `root` (nút đang cập nhật) hay không,
 *   qua đó ngăn chặn việc gán cha ngược tạo thành đồ thị có chu trình.
 * Cơ chế hoạt động:
 *   - Xuất phát từ `current = candidate` và khởi tạo tập băm `seen = new Set<bigint>()` lưu các đỉnh đã đi qua.
 *   - Lặp chừng nào `current !== null` và `!seen.has(current)`:
 *     1. Nếu `current === root` thì kết luận `candidate` là hậu duệ của `root` (`return true` -> phát hiện chu trình).
 *     2. Đánh dấu `seen.add(current)` để bảo đảm vòng lặp luôn dừng hữu hạn O(H) ngay cả khi dữ liệu cũ có chu trình lỗi.
 *     3. Bước nhảy ngược lên nút cha kế tiếp thông qua con trỏ `parent_id`.
 *   - Nếu chạm gốc cây (`null`) hoặc gặp đỉnh lặp mà không chạm `root`, trả về `false` (an toàn không tạo chu trình).
 */
export async function isDepartmentDescendant(
  transaction: Prisma.TransactionClient,
  candidate: bigint,
  root: bigint,
): Promise<boolean> {
  let current: bigint | null = candidate;
  const seen = new Set<bigint>();
  while (current !== null && !seen.has(current)) {
    if (current === root) return true;
    seen.add(current);
    const node: { parent_id: bigint | null } | null = await transaction.department.findUnique({
      where: { id: current },
      select: { parent_id: true },
    });
    current = node?.parent_id ?? null;
  }
  return false;
}

/**
 * Thuật toán: Kiểm Chứng Toàn Vẹn Tham Chiếu Nút Lá Song Song (Parallel Leaf Referential-Integrity Guard)
 * Mục đích: Đảm bảo phòng ban không còn phòng ban con đang mở, người dùng hoạt động hoặc gán vai trò theo phạm vi còn hiệu lực.
 * Cơ chế hoạt động:
 *   - Thực thi đồng thời 3 truy vấn `COUNT(*)` trong cùng giao dịch `Serializable` và từ chối `409 Conflict` nếu tổng phụ thuộc `> 0`.
 */
export async function assertDepartmentHasNoActiveDependents(
  transaction: Prisma.TransactionClient,
  id: bigint,
  now: Date,
): Promise<void> {
  const [activeChildren, activeUsers, activeScopes] = await Promise.all([
    transaction.department.count({ where: { parent_id: id, is_active: true } }),
    transaction.user.count({ where: { department_id: id, status: { not: 'DISABLED' } } }),
    transaction.userRole.count({
      where: {
        scope_department_id: id,
        valid_from: { lte: now },
        OR: [{ valid_to: null }, { valid_to: { gt: now } }],
      },
    }),
  ]);
  if (activeChildren + activeUsers + activeScopes > 0) {
    throw new ConflictException(
      'Department still has active children, users, or scoped role assignments.',
    );
  }
}

export function presentDepartment(
  department: PresentableDepartment,
): Record<string, string | number | boolean | null> {
  return {
    id: department.id.toString(),
    code: department.code,
    name: department.name,
    parentId: department.parent_id?.toString() ?? null,
    isActive: department.is_active,
    version: department.version,
  };
}

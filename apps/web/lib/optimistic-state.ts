/**
 * Thuật toán: Biến Đổi Trạng Thái Lạc Quan Bất Biến Kèm Khôi Phục Tức Thì Dưới 16ms (`optimistic-state`)
 * Mục đích: Cung cấp các phép biến đổi mảng bất biến `O(N)` để cập nhật giao diện ngay trong khung hình đầu tiên (`< 16ms`, đạt chuẩn `< 0,1s`) trước khi yêu cầu mạng hoàn tất, đồng thời cho phép hoàn tác nguyên vẹn về ảnh chụp trước đó nếu máy chủ từ chối.
 * Cơ chế hoạt động:
 *   - Mọi hàm đều trả về mảng mới mà không đột biến phần tử gốc (`Object.assign` / spread bất biến), đảm bảo ảnh chụp `previousItems` lưu trong closure trước lệnh `await` luôn nguyên vẹn 100% khi cần `rollback`.
 *   - Đối với các thực thể có kiểm soát đồng thời lạc quan (`version`), tự động tăng `version + 1` cục bộ để khớp trạng thái dự kiến trước khi đồng bộ ngầm với máy chủ.
 */

export type OptimisticUserAction = 'lock' | 'unlock' | 'disable';

const USER_ACTION_TO_STATUS: Record<OptimisticUserAction, string> = {
  lock: 'LOCKED',
  unlock: 'ACTIVE',
  disable: 'DISABLED',
};

/**
 * Thuật toán: Ánh Xạ Hành Động Khóa/Mở Khóa/Vô Hiệu Sang Trạng Thái Tài Khoản Lạc Quan (`applyOptimisticUserStatus`)
 * Độ phức tạp: Thời gian `O(N)`, không gian `O(N)` theo số lượng tài khoản hiển thị.
 */
export function applyOptimisticUserStatus<
  T extends { id: string; status: string; version: number },
>(users: readonly T[], userId: string, action: OptimisticUserAction): T[] {
  const nextStatus = USER_ACTION_TO_STATUS[action];
  return users.map((user) =>
    user.id === userId ? { ...user, status: nextStatus, version: user.version + 1 } : user,
  );
}

/**
 * Thuật toán: Vô Hiệu Hóa Vai Trò RBAC Lạc Quan (`applyOptimisticRoleDisable`)
 * Độ phức tạp: Thời gian `O(N)` theo số vai trò hiện có.
 */
export function applyOptimisticRoleDisable<
  T extends { id: string; isActive: boolean; version: number },
>(roles: readonly T[], roleId: string): T[] {
  return roles.map((role) =>
    role.id === roleId ? { ...role, isActive: false, version: role.version + 1 } : role,
  );
}

/**
 * Thuật toán: Kích Hoạt Chính Sách ABAC Lạc Quan (`applyOptimisticPolicyActivate`)
 * Độ phức tạp: Thời gian `O(N)` theo số chính sách trong bảng PDP.
 */
export function applyOptimisticPolicyActivate<T extends { id: string; isActive: boolean }>(
  policies: readonly T[],
  policyId: string,
): T[] {
  return policies.map((policy) =>
    policy.id === policyId ? { ...policy, isActive: true } : policy,
  );
}

/**
 * Thuật toán: Cập Nhật Nhãn Trạng Thái Thực Thể Theo Định Danh (`applyOptimisticStatusById`)
 * Mục đích: Chuyển tiếp tức thời trường `status` cho tài liệu (`ACTIVE`/`ARCHIVED`), giấy phép (`REVOKED`), yêu cầu truy cập (`CANCELLED`), phiên đọc (`TERMINATED`) hoặc cảnh báo an ninh.
 */
// CONFLICT-RESOLVED: Giữ tham số tổng quát T extends { id: string; status: string } với nextStatus: T['status'] để bảo toàn nguyên vẹn kiểu phần tử hợp nhất (DocumentItem, AccessGrantItem, MyRequestItem, DocumentSessionItem, SecurityAlertItem) khi setState.
export function applyOptimisticStatusById<T extends { id: string; status: string }>(
  items: readonly T[],
  targetId: string,
  nextStatus: T['status'],
): T[] {
  return items.map((item) => (item.id === targetId ? { ...item, status: nextStatus } : item));
}

/**
 * Thuật toán: Loại Bỏ Lạc Quan Bản Ghi Đã Xử Lý Khỏi Hàng Đợi (`removeOptimisticById`)
 * Mục đích: Rút ngay yêu cầu chờ duyệt (`PENDING`) hoặc phiên đăng nhập từ xa đã thu hồi khỏi danh sách hiển thị trong `O(N)`.
 */
export function removeOptimisticById<T extends { id: string }>(
  items: readonly T[],
  targetId: string,
): T[] {
  return items.filter((item) => item.id !== targetId);
}

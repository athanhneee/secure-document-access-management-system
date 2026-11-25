/**
 * Thuật toán: Từ Điển Việt Hóa Quyền Nguyên Tử RBAC & Suy Diễn Nhãn Đa Tầng (`resolvePermissionLabel`, `resolvePermissionScopeLabel`)
 * Mục đích:
 *   - Chuyển đổi toàn bộ 34 mã quyền hạt nhân RBAC (bao gồm `ALERT_VIEW`, `AUDIT_EXPORT`, `AUDIT_VIEW`, `SYSTEM_REPORT_EXPORT`, `WATERMARK_TRACE`...) và cặp `resource_type : action` sang tiếng Việt nghiệp vụ chuẩn xác.
 *   - Hoạt động tức thì ngay cả trên cơ sở dữ liệu hiện hữu chưa chạy lại seed (nơi cột `permissions.name` đang lưu bản sao của `code`), đồng thời vẫn tôn trọng tên tiếng Việt tùy biến nếu quản trị viên đặt riêng.
 */

export const PERMISSION_LABELS_BY_CODE: Readonly<Record<string, string>> = {
  USER_MANAGE: 'Quản lý người dùng',
  DEPARTMENT_MANAGE: 'Quản lý phòng ban',
  ROLE_MANAGE: 'Quản lý vai trò RBAC',
  ATTRIBUTE_MANAGE: 'Quản lý thuộc tính ABAC',
  POLICY_MANAGE: 'Quản lý chính sách ABAC',
  POLICY_SIMULATE: 'Mô phỏng chính sách ABAC',
  WATERMARK_CONFIG_MANAGE: 'Quản lý cấu hình watermark',
  SYSTEM_HEALTH_VIEW: 'Xem sức khỏe hệ thống',
  SYSTEM_HEALTH_MANAGE: 'Quản trị sức khỏe hệ thống',
  DOCUMENT_UPLOAD: 'Tải lên tài liệu',
  DOCUMENT_CLASSIFY: 'Phân loại độ mật tài liệu',
  DOCUMENT_VERSION_CREATE: 'Tạo phiên bản tài liệu',
  DOCUMENT_ARCHIVE: 'Lưu trữ tài liệu',
  DOCUMENT_MANAGE: 'Quản lý tài liệu',
  DOCUMENT_DISCOVER: 'Tra cứu danh mục tài liệu',
  DOCUMENT_VIEW: 'Xem nội dung tài liệu',
  DOCUMENT_DOWNLOAD: 'Tải xuống tài liệu',
  ACCESS_REQUEST_CREATE: 'Gửi yêu cầu cấp quyền',
  ACCESS_REQUEST_VIEW_OWN: 'Xem yêu cầu truy cập cá nhân',
  ACCESS_REQUEST_CANCEL: 'Hủy yêu cầu cấp quyền',
  ACCESS_REQUEST_DECIDE: 'Phê duyệt yêu cầu cấp quyền',
  ACCESS_GRANT_CREATE: 'Cấp quyền truy cập',
  ACCESS_GRANT_REVOKE: 'Thu hồi quyền truy cập',
  ACCESS_GRANT_VIEW: 'Xem danh sách cấp quyền',
  AUDIT_VIEW: 'Xem nhật ký kiểm toán',
  AUDIT_EXPORT: 'Xuất nhật ký kiểm toán',
  ALERT_VIEW: 'Xem cảnh báo an ninh',
  ALERT_MANAGE: 'Xử lý cảnh báo an ninh',
  WATERMARK_TRACE: 'Truy vết watermark',
  INCIDENT_CREATE: 'Tạo hồ sơ sự cố',
  INCIDENT_MANAGE: 'Quản lý & điều tra sự cố',
  NOTIFICATION_VIEW: 'Xem thông báo',
  SYSTEM_REPORT_EXPORT: 'Xuất báo cáo hệ thống',
  ACCESS_SESSION_TERMINATE: 'Ngắt phiên truy cập khẩn cấp',
};

export const PERMISSION_RESOURCE_LABELS: Readonly<Record<string, string>> = {
  USER: 'Tài khoản người dùng',
  DEPARTMENT: 'Phòng ban',
  ROLE: 'Vai trò RBAC',
  ATTRIBUTE: 'Thuộc tính ABAC',
  POLICY: 'Chính sách ABAC',
  WATERMARK_CONFIG: 'Cấu hình watermark',
  SYSTEM_HEALTH: 'Sức khỏe hệ thống',
  DOCUMENT: 'Tài liệu mật',
  DOCUMENT_VERSION: 'Phiên bản tài liệu',
  ACCESS_REQUEST: 'Yêu cầu cấp quyền',
  ACCESS_GRANT: 'Quyền truy cập',
  AUDIT_LOG: 'Nhật ký kiểm toán',
  SECURITY_ALERT: 'Cảnh báo an ninh',
  WATERMARK_INSTANCE: 'Dấu watermark',
  INCIDENT_REPORT: 'Báo cáo sự cố',
  NOTIFICATION: 'Thông báo hệ thống',
  SYSTEM_REPORT: 'Báo cáo hệ thống',
  ACCESS_SESSION: 'Phiên truy cập',
};

export const PERMISSION_ACTION_LABELS: Readonly<Record<string, string>> = {
  MANAGE: 'Quản trị toàn phần',
  SIMULATE: 'Mô phỏng đánh giá',
  VIEW: 'Xem thông tin',
  READ: 'Xem thông tin',
  UPLOAD: 'Tải lên',
  CLASSIFY: 'Phân loại độ mật',
  CREATE: 'Khởi tạo mới',
  ARCHIVE: 'Lưu trữ',
  DISCOVER: 'Tra cứu danh mục',
  DOWNLOAD: 'Tải xuống',
  VIEW_OWN: 'Xem phạm vi cá nhân',
  CANCEL: 'Hủy bỏ',
  DECIDE: 'Phê duyệt / từ chối',
  REVOKE: 'Thu hồi',
  EXPORT: 'Kết xuất dữ liệu',
  TRACE: 'Truy vết pháp y',
  TERMINATE: 'Ngắt khẩn cấp',
};

export interface PermissionDisplayLike {
  code: string;
  name?: string | null | undefined;
  resource?: string | null | undefined;
  resourceType?: string | null | undefined;
  action?: string | null | undefined;
}

/**
 * Thuật toán: Chuẩn Hóa Khóa Tra Cứu Quyền Bất Biến Hoa Thường (`normalizeKey`)
 * Cơ chế: Loại bỏ khoảng trắng thừa, chuyển sang chữ in hoa và đồng nhất dấu phân tách `:` về `_` trong `O(L)`.
 */
function normalizeKey(raw: string | null | undefined): string {
  return (raw ?? '').trim().toUpperCase().replaceAll(':', '_');
}

/**
 * Thuật toán: Phân Giải Tên Quyền Tiếng Việt Ưu Tiên Đa Bậc (`resolvePermissionLabel`)
 * Cơ chế:
 *   1. Nếu `name` từ máy chủ khác với mã kỹ thuật `code` (ví dụ quyền tùy biến đã đặt tên tiếng Việt), ưu tiên trả về `name`.
 *   2. Tra bảng băm hằng `O(1)` `PERMISSION_LABELS_BY_CODE` theo khóa chuẩn hóa của `code`.
 *   3. Nếu chưa khớp, tổng hợp tự động từ từ điển hành động và tài nguyên (`PERMISSION_ACTION_LABELS` + `PERMISSION_RESOURCE_LABELS`), cuối cùng dự phòng về `code`.
 */
export function resolvePermissionLabel(perm: PermissionDisplayLike): string {
  const normalizedCode = normalizeKey(perm.code);
  const trimmedName = perm.name?.trim();
  if (trimmedName && normalizeKey(trimmedName) !== normalizedCode) {
    return trimmedName;
  }

  const mappedByCode = PERMISSION_LABELS_BY_CODE[normalizedCode];
  if (mappedByCode) {
    return mappedByCode;
  }

  const resourceKey = normalizeKey(perm.resource ?? perm.resourceType);
  const actionKey = normalizeKey(perm.action);
  const resourceLabel = PERMISSION_RESOURCE_LABELS[resourceKey];
  const actionLabel = PERMISSION_ACTION_LABELS[actionKey];
  if (actionLabel && resourceLabel) {
    return `${actionLabel} ${resourceLabel.toLowerCase()}`;
  }

  return perm.code;
}

/**
 * Thuật toán: Phân Giải Nhãn Phạm Vi Tài Nguyên & Hành Động Tiếng Việt (`resolvePermissionScopeLabel`)
 * Cơ chế: Ánh xạ `O(1)` cặp `(resourceType, action)` sang chuỗi mô tả tiếng Việt phân tách bằng dấu chấm giữa `·`.
 */
export function resolvePermissionScopeLabel(perm: {
  resource?: string | null | undefined;
  resourceType?: string | null | undefined;
  action?: string | null | undefined;
}): string {
  const rawResource = (perm.resource ?? perm.resourceType ?? '').trim();
  const rawAction = (perm.action ?? '').trim();
  const resourceLabel = PERMISSION_RESOURCE_LABELS[normalizeKey(rawResource)] || rawResource;
  const actionLabel = PERMISSION_ACTION_LABELS[normalizeKey(rawAction)] || rawAction;

  if (resourceLabel && actionLabel) {
    return `${resourceLabel} · ${actionLabel}`;
  }
  return resourceLabel || actionLabel;
}

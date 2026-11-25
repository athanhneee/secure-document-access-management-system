/**
 * Thuật toán: Từ Điển Ánh Xạ Nhãn Trạng Thái, Quyền Hạn & Sự Kiện Chuẩn Production (`ui-labels`)
 * Mục đích:
 *   - Tập trung hóa toàn bộ nhãn hiển thị tiếng Việt cho các mã enum từ máy chủ (trạng thái tài khoản, tài liệu, yêu cầu, quyền truy cập, cảnh báo, sự cố, báo cáo, chính sách ABAC và lỗi chuỗi toàn vẹn) trong thời gian tra cứu `O(1)`.
 *   - Loại bỏ hoàn toàn tình trạng hiển thị raw enum tiếng Anh (`ACTIVE`, `PENDING`, `VIEW`, `OPEN`, `PERMIT`...), giá trị `Invalid Date` và rò rỉ tên cột kỹ thuật lên giao diện người dùng cuối.
 */

export const BRAND_NAME = 'SecureDocument';

const USER_STATUS_LABELS: Readonly<Record<string, string>> = {
  ACTIVE: 'Đang hoạt động',
  LOCKED: 'Tạm khóa',
  DISABLED: 'Vô hiệu hóa',
  PENDING: 'Chờ kích hoạt',
};

const DOCUMENT_STATUS_LABELS: Readonly<Record<string, string>> = {
  ACTIVE: 'Đang hiệu lực',
  DRAFT: 'Bản nháp',
  ARCHIVED: 'Đã lưu trữ',
};

const GRANT_STATUS_LABELS: Readonly<Record<string, string>> = {
  ACTIVE: 'Đang hiệu lực',
  REVOKED: 'Đã thu hồi',
  EXPIRED: 'Đã hết hạn',
  SUSPENDED: 'Tạm ngưng',
};

const REQUEST_STATUS_LABELS: Readonly<Record<string, string>> = {
  PENDING: 'Chờ duyệt',
  APPROVED: 'Đã duyệt',
  REJECTED: 'Từ chối',
  CANCELLED: 'Đã hủy',
  EXPIRED: 'Đã hết hạn',
};

const PERMISSION_ACTION_LABELS: Readonly<Record<string, string>> = {
  ALL: 'Tất cả thao tác',
  DISCOVER: 'Tra cứu',
  VIEW: 'Chỉ xem',
  DOWNLOAD: 'Xem & Tải về',
  SHARE: 'Chia sẻ',
  MANAGE: 'Quản trị',
};

const PRINCIPAL_TYPE_LABELS: Readonly<Record<string, string>> = {
  USER: 'Người dùng',
  ROLE: 'Vai trò',
};

const SCAN_STATUS_LABELS: Readonly<Record<string, string>> = {
  CLEAN: 'An toàn',
  PENDING: 'Đang kiểm tra',
  INFECTED: 'Phát hiện mã độc',
  FAILED: 'Kiểm tra lỗi',
};

const ALERT_SEVERITY_LABELS: Readonly<Record<string, string>> = {
  CRITICAL: 'Nghiêm trọng',
  HIGH: 'Cao',
  MEDIUM: 'Trung bình',
  LOW: 'Thấp',
};

const ALERT_STATUS_LABELS: Readonly<Record<string, string>> = {
  OPEN: 'Chờ xử lý',
  INVESTIGATING: 'Đang điều tra',
  ESCALATED: 'Đã chuyển cấp xử lý',
  RESOLVED: 'Đã xử lý',
  FALSE_POSITIVE: 'Báo động giả',
};

const INCIDENT_STATUS_LABELS: Readonly<Record<string, string>> = {
  DRAFT: 'Bản nháp',
  SUBMITTED: 'Chờ phê duyệt',
  IN_REVIEW: 'Đang xem xét',
  CLOSED: 'Đã đóng',
};

const INCIDENT_ACTION_TYPE_LABELS: Readonly<Record<string, string>> = {
  REVOKE_ACCESS: 'Thu hồi quyền truy cập',
  LOCK_ACCOUNT: 'Tạm khóa tài khoản',
  ROTATE_POLICY: 'Cập nhật chính sách bảo mật',
  FORENSIC_AUDIT: 'Kiểm tra chuyên sâu',
};

const SESSION_STATUS_LABELS: Readonly<Record<string, string>> = {
  ACTIVE: 'Đang hoạt động',
  ENDED: 'Đã kết thúc',
  TERMINATED: 'Đã ngắt',
  EXPIRED: 'Đã hết hạn',
  REVOKED: 'Đã thu hồi',
};

const AUDIT_OUTCOME_LABELS: Readonly<Record<string, string>> = {
  SUCCESS: 'Thành công',
  DENIED: 'Bị từ chối',
  FAILED: 'Thất bại',
  FAILURE: 'Thất bại',
};

const EXPORT_TYPE_LABELS: Readonly<Record<string, string>> = {
  AUDIT_LOGS: 'Nhật ký kiểm toán',
  SYSTEM_REPORT: 'Báo cáo hệ thống',
  SECURITY_ALERTS: 'Cảnh báo an ninh',
  INCIDENT_REPORTS: 'Báo cáo sự cố',
  INCIDENT_REPORT: 'Báo cáo sự cố',
};

const EXPORT_STATUS_LABELS: Readonly<Record<string, string>> = {
  PENDING: 'Đang chờ xử lý',
  PROCESSING: 'Đang tạo báo cáo',
  COMPLETED: 'Sẵn sàng tải về',
  FAILED: 'Thất bại',
  EXPIRED: 'Đã hết hạn',
};

const EXPORT_FORMAT_LABELS: Readonly<Record<string, string>> = {
  CSV: 'CSV',
  EXCEL: 'Excel (.xlsx)',
  JSON: 'JSON',
  PDF: 'PDF',
};

const SERVICE_HEALTH_LABELS: Readonly<Record<string, string>> = {
  ONLINE: 'Hoạt động bình thường',
  HEALTHY: 'Hoạt động bình thường',
  DEGRADED: 'Suy giảm hiệu năng',
  OFFLINE: 'Ngừng hoạt động',
  DOWN: 'Ngừng hoạt động',
};

const POLICY_EFFECT_LABELS: Readonly<Record<string, string>> = {
  PERMIT: 'Cho phép',
  DENY: 'Từ chối',
};

const ABAC_REASON_LABELS: Readonly<Record<string, string>> = {
  ACTION_NOT_TARGETED: 'Thao tác không nằm trong phạm vi áp dụng của chính sách',
  DEFAULT_DENY_NO_GROUP_MATCH: 'Mặc định từ chối do không có nhóm điều kiện nào khớp',
  RULE_PERMIT_MATCHED: 'Thỏa mãn điều kiện cho phép của chính sách',
  EXPLICIT_DENY_RULE_MATCHED: 'Khớp quy tắc từ chối tường minh',
  EXPLICIT_DENY: 'Khớp quy tắc từ chối tường minh (DENY_OVERRIDES)',
  STEP_UP_MFA_REQUIRED: 'Yêu cầu xác thực đa yếu tố (MFA) bổ sung',
  INSUFFICIENT_CLEARANCE: 'Cấp thẩm quyền không đủ cho độ mật tài liệu (Bell-LaPadula)',
  MISSING_REQUIRED_ATTRIBUTE: 'Thiếu thuộc tính ngữ cảnh bắt buộc',
  INVALID_POLICY: 'Chính sách không hợp lệ (từ chối mặc định)',
  POLICY_PERMIT: 'Chính sách cho phép truy cập',
  POLICY_DENY: 'Chính sách từ chối truy cập',
  DEFAULT_DENY: 'Mặc định từ chối truy cập (không có luật cho phép khớp)',
};

const AUDIT_ACTION_LABELS: Readonly<Record<string, string>> = {
  LOGIN: 'Đăng nhập hệ thống',
  LOGOUT: 'Đăng xuất hệ thống',
  LOGOUT_ALL: 'Đăng xuất toàn bộ thiết bị',
  LOGOUT_OTHERS: 'Đăng xuất các thiết bị khác',
  TOKEN_REFRESH: 'Làm mới phiên xác thực',
  REFRESH_REUSE: 'Tái sử dụng Refresh Token đã thu hồi',
  SESSION_REVOKED: 'Thu hồi phiên đăng nhập',
  MFA_VERIFY: 'Xác thực đa yếu tố (MFA)',
  MFA_ENABLED: 'Kích hoạt xác thực đa yếu tố',
  MFA_DISABLED: 'Hủy xác thực đa yếu tố',
  MFA_DISABLE_BLOCKED: 'Chặn hủy MFA do chính sách bảo mật',
  MFA_DISABLE_DENIED: 'Từ chối hủy MFA',
  MFA_ENROLLMENT_STARTED: 'Bắt đầu thiết lập MFA',
  MFA_ENROLLMENT_BLOCKED: 'Chặn thiết lập MFA trùng lặp',
  MFA_FACTOR_REMOVED: 'Gỡ bỏ phương thức xác thực MFA',
  MFA_WEBAUTHN_ENROLL_START: 'Bắt đầu đăng ký Passkey / khóa bảo mật',
  MFA_WEBAUTHN_ENROLLED: 'Đăng ký khóa bảo mật / Passkey',
  MFA_WEBAUTHN_AUTH_OPTIONS: 'Tạo thử thách xác thực Passkey',
  MFA_WEBAUTHN_VERIFY: 'Xác thực bằng khóa bảo mật / Passkey',
  PASSWORD_RESET_REQUEST: 'Yêu cầu đặt lại mật khẩu',
  PASSWORD_RESET: 'Đặt lại mật khẩu thành công',
  PASSWORD_CHANGE: 'Đổi mật khẩu tài khoản',
  PASSWORD_CHANGED: 'Đổi mật khẩu tài khoản',
  AUTH_LOGIN: 'Đăng nhập hệ thống',
  AUTH_LOGIN_SUCCESS: 'Đăng nhập thành công',
  AUTH_LOGIN_FAILED: 'Đăng nhập thất bại',
  AUTH_LOGOUT: 'Đăng xuất hệ thống',
  AUTH_MFA_VERIFY: 'Xác thực đa yếu tố',
  AUTH_MFA_ENROLL: 'Thiết lập xác thực đa yếu tố',
  AUTH_PASSWORD_RESET: 'Đặt lại mật khẩu',
  AUTH_SESSION_REVOKE: 'Thu hồi phiên đăng nhập',
  ACCESS_PERMITTED: 'Cho phép truy cập tài liệu',
  ACCESS_DENIED: 'Từ chối truy cập tài liệu',
  DOCUMENT_CREATED: 'Khởi tạo hồ sơ tài liệu mới',
  DOCUMENT_UPLOAD: 'Tải lên tài liệu',
  DOCUMENT_UPLOAD_STARTED: 'Bắt đầu tải lên tài liệu',
  DOCUMENT_UPLOAD_COMPLETED: 'Hoàn tất tải lên tài liệu',
  DOCUMENT_UPLOAD_FAILED: 'Tải lên tài liệu thất bại',
  DOCUMENT_SCAN_RESULT: 'Kết quả quét mã độc tài liệu',
  DOCUMENT_ACTIVATE: 'Kích hoạt tài liệu',
  DOCUMENT_ACTIVATED: 'Kích hoạt tài liệu',
  DOCUMENT_METADATA_UPDATED: 'Cập nhật thông tin tài liệu',
  DOCUMENT_CURRENT_VERSION_SET: 'Đặt phiên bản tài liệu hiện hành',
  DOCUMENT_VERSION_UPLOAD: 'Tải lên phiên bản mới',
  DOCUMENT_OWNER_TRANSFERRED: 'Chuyển giao quyền sở hữu tài liệu',
  DOCUMENT_RECLASSIFY: 'Điều chỉnh mức độ mật',
  DOCUMENT_RECLASSIFIED: 'Điều chỉnh mức độ mật',
  DOCUMENT_ARCHIVE: 'Lưu trữ tài liệu',
  DOCUMENT_ARCHIVED: 'Lưu trữ tài liệu',
  DOCUMENT_VIEW: 'Xem tài liệu',
  DOCUMENT_VIEWED: 'Xem tài liệu',
  DOCUMENT_PREVIEW: 'Xem trước tài liệu',
  DOCUMENT_PREVIEWED: 'Xem trước tài liệu',
  DOCUMENT_DOWNLOAD: 'Tải về tài liệu',
  DOCUMENT_DOWNLOADED: 'Tải về tài liệu',
  DOCUMENT_DISCOVER: 'Tra cứu danh mục tài liệu',
  DOCUMENT_SEARCHED: 'Tìm kiếm tài liệu',
  DOCUMENT_RETENTION_WARNING: 'Cảnh báo hạn lưu trữ tài liệu',
  ACCESS_REQUEST_CREATE: 'Gửi yêu cầu quyền truy cập',
  ACCESS_REQUEST_CREATED: 'Gửi yêu cầu quyền truy cập',
  ACCESS_REQUEST_APPROVE: 'Phê duyệt yêu cầu truy cập',
  ACCESS_REQUEST_APPROVED: 'Phê duyệt yêu cầu truy cập',
  ACCESS_REQUEST_REJECT: 'Từ chối yêu cầu truy cập',
  ACCESS_REQUEST_REJECTED: 'Từ chối yêu cầu truy cập',
  ACCESS_REQUEST_CANCEL: 'Hủy yêu cầu truy cập',
  ACCESS_REQUEST_CANCELLED: 'Hủy yêu cầu truy cập',
  ACCESS_GRANT_CREATE: 'Cấp quyền truy cập',
  GRANT_CREATED: 'Cấp quyền truy cập',
  GRANT_EXTENDED: 'Gia hạn quyền truy cập',
  GRANT_UPGRADED: 'Nâng cấp quyền truy cập',
  GRANT_EXPIRED: 'Hết hạn quyền truy cập',
  GRANT_REVOKED: 'Thu hồi quyền truy cập',
  ACCESS_GRANT_REVOKE: 'Thu hồi quyền truy cập',
  ACCESS_SESSION_CREATE: 'Mở phiên đọc tài liệu',
  ACCESS_SESSION_TERMINATE: 'Ngắt phiên đọc tài liệu',
  ACCESS_SESSION_TERMINATED: 'Ngắt phiên đọc tài liệu',
  ACCESS_SESSION_ENDED: 'Kết thúc phiên đọc tài liệu',
  POLICY_CREATE: 'Tạo chính sách truy cập',
  POLICY_UPDATE: 'Cập nhật chính sách truy cập',
  POLICY_ACTIVATE: 'Kích hoạt chính sách truy cập',
  POLICY_ACTIVATED: 'Kích hoạt chính sách truy cập',
  POLICY_DEACTIVATED: 'Vô hiệu hóa chính sách truy cập',
  POLICY_DELETED: 'Xóa chính sách truy cập',
  POLICY_SIMULATED: 'Mô phỏng đánh giá chính sách',
  WATERMARK_GENERATED: 'Đóng dấu watermark pháp chứng',
  WATERMARK_TRACE: 'Truy vết watermark bảo mật',
  WATERMARK_TRACE_PERFORMED: 'Truy vết nguồn gốc watermark',
  WATERMARK_VERIFIED: 'Đối soát truy vết watermark',
  WATERMARK_CONFIG_UPDATE: 'Cập nhật cấu hình watermark',
  WATERMARK_CONFIG_UPDATED: 'Cập nhật cấu hình watermark',
  ALERT_UPDATE: 'Cập nhật cảnh báo an ninh',
  SECURITY_ALERT_STATUS_UPDATED: 'Cập nhật trạng thái cảnh báo',
  SECURITY_ALERT_ASSIGNED: 'Phân công xử lý cảnh báo',
  SECURITY_ALERT_NOTE_ADDED: 'Thêm ghi chú điều tra cảnh báo',
  DETECTION_RULE_CONFIGURED: 'Cập nhật quy tắc phát hiện bất thường',
  INCIDENT_CREATE: 'Tạo hồ sơ sự cố',
  INCIDENT_REPORT_CREATED: 'Tạo hồ sơ sự cố an ninh',
  INCIDENT_UPDATE: 'Cập nhật hồ sơ sự cố',
  INCIDENT_REPORT_UPDATED: 'Cập nhật hồ sơ sự cố an ninh',
  INCIDENT_REPORT_SUBMITTED: 'Trình duyệt hồ sơ sự cố',
  INCIDENT_REPORT_IN_REVIEW: 'Chuyển thẩm định hồ sơ sự cố',
  INCIDENT_REPORT_CLOSED: 'Đóng hồ sơ sự cố an ninh',
  INCIDENT_ACTION_CREATED: 'Thêm hành động khắc phục sự cố',
  INCIDENT_ACTION_COMPLETED: 'Hoàn thành hành động khắc phục',
  NETWORK_DLP_BLOCKED: 'Chặn rò rỉ dữ liệu mạng (DLP)',
  NETWORK_DLP_DETECTED: 'Phát hiện vi phạm dữ liệu mạng (DLP)',
  AUDIT_EXPORT: 'Xuất báo cáo kiểm toán',
  AUDIT_LOG_EXPORTED: 'Xuất trực tiếp nhật ký kiểm toán',
  AUDIT_VERIFY: 'Kiểm tra toàn vẹn nhật ký',
  AUDIT_CHAIN_VERIFIED: 'Kiểm chứng toàn vẹn chuỗi băm',
  AUDIT_ANCHOR_CREATED: 'Khởi tạo điểm neo chữ ký HMAC',
  REPORT_EXPORT_REQUESTED: 'Yêu cầu xuất báo cáo',
  REPORT_EXPORT_DOWNLOADED: 'Tải về báo cáo đã xuất',
  USER_CREATE: 'Tạo tài khoản người dùng',
  USER_CREATED: 'Tạo tài khoản người dùng',
  USER_UPDATE: 'Cập nhật tài khoản người dùng',
  USER_UPDATED: 'Cập nhật tài khoản người dùng',
  USER_LOCKED: 'Tạm khóa tài khoản người dùng',
  USER_UNLOCKED: 'Mở khóa tài khoản người dùng',
  USER_DISABLED: 'Vô hiệu hóa tài khoản người dùng',
  USER_REACTIVATED: 'Kích hoạt lại tài khoản người dùng',
  USER_CLEARANCE_UPDATE: 'Cập nhật cấp thẩm quyền bảo mật',
  USER_CLEARANCE_UPDATED: 'Cập nhật cấp thẩm quyền bảo mật',
  DEPARTMENT_CREATED: 'Tạo phòng ban mới',
  DEPARTMENT_UPDATED: 'Cập nhật thông tin phòng ban',
  DEPARTMENT_ACTIVATED: 'Kích hoạt phòng ban',
  DEPARTMENT_DEACTIVATED: 'Ngừng hoạt động phòng ban',
  ROLE_CREATED: 'Tạo vai trò mới',
  ROLE_UPDATED: 'Cập nhật thông tin vai trò',
  ROLE_ENABLED: 'Kích hoạt vai trò',
  ROLE_DISABLED: 'Vô hiệu hóa vai trò',
  ROLE_DELETED: 'Xóa vai trò tùy chỉnh',
  ROLE_PERMISSIONS_REPLACED: 'Cập nhật danh sách quyền của vai trò',
  ROLE_ASSIGN: 'Gán vai trò người dùng',
  USER_ROLE_ASSIGNED: 'Gán vai trò người dùng',
  USER_ROLE_REVOKED: 'Thu hồi vai trò người dùng',
};

const AUDIT_OBJECT_TYPE_LABELS: Readonly<Record<string, string>> = {
  DOCUMENT: 'Tài liệu',
  DOCUMENT_VERSION: 'Phiên bản tài liệu',
  ACCESS_GRANT: 'Quyền truy cập',
  ACCESS_REQUEST: 'Yêu cầu truy cập',
  ACCESS_SESSION: 'Phiên đọc tài liệu',
  AUTH_SESSION: 'Phiên đăng nhập',
  AUTHENTICATION: 'Xác thực người dùng',
  USER: 'Tài khoản người dùng',
  USER_ROLE: 'Gán vai trò người dùng',
  ROLE: 'Vai trò',
  ROLE_PERMISSION: 'Quyền hạn vai trò',
  DEPARTMENT: 'Phòng ban',
  POLICY: 'Chính sách bảo mật',
  POLICY_SIMULATION: 'Mô phỏng chính sách truy cập',
  SECURITY_ALERT: 'Cảnh báo an ninh',
  DETECTION_RULE_CONFIG: 'Quy tắc phát hiện bất thường',
  INCIDENT_REPORT: 'Hồ sơ sự cố',
  INCIDENT_ACTION: 'Hành động khắc phục sự cố',
  WATERMARK_INSTANCE: 'Watermark bảo mật',
  WATERMARK_CONFIG: 'Cấu hình watermark',
  EXPORT_JOB: 'Báo cáo xuất tệp',
  ASYNC_EXPORT_JOB: 'Tác vụ xuất báo cáo',
  AUDIT_LOG: 'Nhật ký kiểm toán',
  AUDIT_ANCHOR: 'Điểm neo chữ ký kiểm toán',
};

const AUDIT_PARTITION_LABELS: Readonly<Record<string, string>> = {
  GLOBAL: 'Toàn hệ thống',
  AUTH: 'Xác thực & phiên đăng nhập',
  DOCUMENT: 'Tài liệu & phiên bản',
  ACCESS_SESSION: 'Phiên đọc tài liệu',
  RBAC: 'Phân quyền & tổ chức',
  AUDIT: 'Kiểm toán & xuất báo cáo',
  SECURITY: 'An ninh & watermark',
  SECURITY_OPERATIONS: 'Vận hành an ninh (SOC)',
};

const AUDIT_VIOLATION_CODE_LABELS: Readonly<Record<string, string>> = {
  AUDIT_CHAIN_BROKEN: 'Phát hiện đứt gãy liên kết giữa các bản ghi nhật ký',
  AUDIT_SEQUENCE_GAP: 'Phát hiện thiếu hụt số thứ tự trong chuỗi nhật ký',
  AUDIT_LOG_TAMPERED: 'Phát hiện dấu hiệu chỉnh sửa nội dung bản ghi nhật ký',
  AUDIT_ANCHOR_MISMATCH: 'Mã đối soát chữ ký nhật ký không khớp với giá trị lưu trữ',
  CHAIN_BROKEN: 'Phát hiện đứt gãy liên kết giữa các bản ghi nhật ký',
  SEQUENCE_GAP: 'Phát hiện thiếu hụt số thứ tự trong chuỗi nhật ký',
  HMAC_MISMATCH: 'Phát hiện dấu hiệu chỉnh sửa nội dung bản ghi nhật ký',
  HASH_MISMATCH: 'Phát hiện sai lệch mã kiểm tra toàn vẹn bản ghi',
};

// CONFLICT-RESOLVED: Thay thế 7 mã rác không tồn tại bằng đầy đủ 9 loại cảnh báo thực tế của API/Worker (#11).
const DETECTION_RULE_LABELS: Readonly<Record<string, string>> = {
  MASS_DOWNLOAD: 'Tải về hàng loạt bất thường',
  REPEATED_DENIED: 'Bị từ chối truy cập liên tiếp',
  OFF_HOURS_ACCESS: 'Truy cập tài liệu mật ngoài giờ',
  UNTRUSTED_CONTEXT: 'Truy cập từ IP / thiết bị chưa tin cậy',
  REFRESH_TOKEN_REUSE: 'Tái sử dụng Refresh Token (nghi vấn chiếm đoạt phiên)',
  AUDIT_INTEGRITY_COMPROMISED: 'Vi phạm tính toàn vẹn chuỗi nhật ký kiểm toán',
  NETWORK_DLP_VIOLATION: 'Vi phạm chống thất thoát dữ liệu mạng (DLP)',
  WEBAUTHN_CLONE_DETECTED: 'Phát hiện dấu hiệu nhân bản khóa FIDO2 / Passkey',
  RETENTION_OVERDUE: 'Tài liệu quá hạn lưu trữ bảo mật',
  ANOMALY_DETECTION: 'Phát hiện hành vi bất thường',
};

const CLASSIFICATION_LEVEL_LABELS: Readonly<Record<string, string>> = {
  PUBLIC: 'Công khai',
  UNCLASSIFIED: 'Không mật',
  INTERNAL: 'Nội bộ',
  RESTRICTED: 'Hạn chế nội bộ',
  CONFIDENTIAL: 'Mật',
  SECRET: 'Tối mật',
  TOP_SECRET: 'Tuyệt mật',
};

function normalizeKey(raw: string | null | undefined): string {
  return (raw ?? '').trim().toUpperCase();
}

export function formatUserStatusLabel(status: string | null | undefined): string {
  const key = normalizeKey(status);
  return USER_STATUS_LABELS[key] ?? (status?.trim() || 'Không xác định');
}

export function formatActiveBooleanLabel(isActive: boolean): string {
  return isActive ? 'Đang hoạt động' : 'Ngừng hoạt động';
}

export function formatDocumentStatusLabel(status: string | null | undefined): string {
  const key = normalizeKey(status);
  return DOCUMENT_STATUS_LABELS[key] ?? (status?.trim() || 'Không xác định');
}

export function formatGrantStatusLabel(status: string | null | undefined): string {
  const key = normalizeKey(status);
  return GRANT_STATUS_LABELS[key] ?? (status?.trim() || 'Không xác định');
}

export function formatRequestStatusLabel(status: string | null | undefined): string {
  const key = normalizeKey(status);
  return REQUEST_STATUS_LABELS[key] ?? (status?.trim() || 'Không xác định');
}

export function formatPermissionActionLabel(action: string | null | undefined): string {
  const key = normalizeKey(action);
  return PERMISSION_ACTION_LABELS[key] ?? (action?.trim() || 'Không xác định');
}

export function formatPrincipalTypeLabel(type: string | null | undefined): string {
  const key = normalizeKey(type);
  return PRINCIPAL_TYPE_LABELS[key] ?? (type?.trim() || 'Không xác định');
}

export function formatScanStatusLabel(status: string | null | undefined): string {
  const key = normalizeKey(status);
  return SCAN_STATUS_LABELS[key] ?? (status?.trim() || 'Không xác định');
}

export function formatAlertSeverityLabel(severity: string | null | undefined): string {
  const key = normalizeKey(severity);
  return ALERT_SEVERITY_LABELS[key] ?? (severity?.trim() || 'Không xác định');
}

export function formatAlertStatusLabel(status: string | null | undefined): string {
  const key = normalizeKey(status);
  return ALERT_STATUS_LABELS[key] ?? (status?.trim() || 'Không xác định');
}

export function formatIncidentStatusLabel(status: string | null | undefined): string {
  const key = normalizeKey(status);
  return INCIDENT_STATUS_LABELS[key] ?? (status?.trim() || 'Không xác định');
}

export function formatIncidentActionTypeLabel(actionType: string | null | undefined): string {
  const key = normalizeKey(actionType);
  return INCIDENT_ACTION_TYPE_LABELS[key] ?? (actionType?.trim() || 'Hành động xử lý');
}

export function formatSessionStatusLabel(status: string | null | undefined): string {
  const key = normalizeKey(status);
  return SESSION_STATUS_LABELS[key] ?? (status?.trim() || 'Không xác định');
}

export function formatAuditOutcomeLabel(outcome: string | null | undefined): string {
  const key = normalizeKey(outcome);
  return AUDIT_OUTCOME_LABELS[key] ?? (outcome?.trim() || 'Không xác định');
}

export function formatExportTypeLabel(type: string | null | undefined): string {
  const key = normalizeKey(type);
  return EXPORT_TYPE_LABELS[key] ?? 'Báo cáo kiểm toán';
}

export function formatExportStatusLabel(status: string | null | undefined): string {
  const key = normalizeKey(status);
  return EXPORT_STATUS_LABELS[key] ?? (status?.trim() || 'Không xác định');
}

export function formatExportFormatLabel(format: string | null | undefined): string {
  const key = normalizeKey(format);
  return EXPORT_FORMAT_LABELS[key] ?? (format?.trim() || 'Không xác định');
}

export function formatServiceHealthLabel(status: string | null | undefined): string {
  const key = normalizeKey(status);
  return SERVICE_HEALTH_LABELS[key] ?? 'Không xác định';
}

export function formatPolicyEffectLabel(effect: string | null | undefined): string {
  const key = normalizeKey(effect);
  return POLICY_EFFECT_LABELS[key] ?? (effect?.trim() || 'Không xác định');
}

export function formatObligationLabel(type: string, value?: string | number | boolean): string {
  const key = normalizeKey(type);
  if (key === 'MAX_SESSION_MINUTES') {
    return value !== undefined ? `Giới hạn phiên: ${value} phút` : 'Giới hạn thời gian phiên';
  }
  const map: Readonly<Record<string, string>> = {
    REQUIRE_WATERMARK: 'Gắn watermark bảo mật',
    REQUIRE_MFA: 'Yêu cầu xác thực đa yếu tố (MFA)',
    FORBID_DOWNLOAD: 'Cấm tải về tệp gốc',
    NO_CACHE: 'Không lưu bộ đệm trên thiết bị',
  };
  return map[key] ?? type;
}

export function formatAbacReasonLabel(reasonCode: string | null | undefined): string {
  const key = normalizeKey(reasonCode);
  return ABAC_REASON_LABELS[key] ?? (reasonCode?.trim() || 'Không xác định');
}

export function formatAuditActionLabel(action: string | null | undefined): string {
  const key = normalizeKey(action);
  if (!key) return 'Sự kiện hệ thống';
  return AUDIT_ACTION_LABELS[key] ?? action!.trim();
}

export function formatAuditObjectTypeLabel(objectType: string | null | undefined): string {
  const key = normalizeKey(objectType);
  if (!key) return '—';
  return AUDIT_OBJECT_TYPE_LABELS[key] ?? objectType!.trim();
}

export function formatDetectionRuleLabel(ruleCode: string | null | undefined): string {
  const key = normalizeKey(ruleCode);
  if (!key) return 'Phát hiện hành vi bất thường';
  return DETECTION_RULE_LABELS[key] ?? ruleCode!.trim();
}

export function formatClassificationLabel(level: string | null | undefined): string {
  const key = normalizeKey(level);
  if (!key) return 'Chưa phân loại';
  return CLASSIFICATION_LEVEL_LABELS[key] ?? level!.trim();
}

export function formatAuditPartitionLabel(partition: string | null | undefined): string {
  const key = normalizeKey(partition);
  if (!key) return 'Toàn hệ thống';
  return AUDIT_PARTITION_LABELS[key] ?? partition!.trim();
}

export function formatAuditViolationMessage(
  partition: string | null | undefined,
  code?: string | null,
  sequenceNo?: number | string | null,
): string {
  const partitionLabel = formatAuditPartitionLabel(partition);
  const key = normalizeKey(code);
  const baseMessage =
    AUDIT_VIOLATION_CODE_LABELS[key] ?? 'Phát hiện sai lệch tính toàn vẹn trong chuỗi nhật ký';
  const seqSuffix =
    sequenceNo !== undefined && sequenceNo !== null && String(sequenceNo).trim() !== ''
      ? ` (bản ghi số #${sequenceNo})`
      : '';
  return `${partitionLabel}: ${baseMessage}${seqSuffix}.`;
}

export function formatSafeDateVi(
  value: string | null | undefined,
  options?: { includeTime?: boolean },
): string {
  if (!value || value.trim() === '' || value.trim() === '—') return '—';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return '—';
  return options?.includeTime ? parsed.toLocaleString('vi-VN') : parsed.toLocaleDateString('vi-VN');
}

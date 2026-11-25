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
  POLICY_PERMIT: 'Chính sách cho phép truy cập',
  POLICY_DENY: 'Chính sách từ chối truy cập',
  DEFAULT_DENY: 'Mặc định từ chối truy cập',
};

const AUDIT_ACTION_LABELS: Readonly<Record<string, string>> = {
  AUTH_LOGIN: 'Đăng nhập hệ thống',
  AUTH_LOGIN_SUCCESS: 'Đăng nhập thành công',
  AUTH_LOGIN_FAILED: 'Đăng nhập thất bại',
  AUTH_LOGOUT: 'Đăng xuất hệ thống',
  AUTH_MFA_VERIFY: 'Xác thực đa yếu tố',
  AUTH_MFA_ENROLL: 'Thiết lập xác thực đa yếu tố',
  AUTH_PASSWORD_RESET: 'Đặt lại mật khẩu',
  AUTH_SESSION_REVOKE: 'Thu hồi phiên đăng nhập',
  DOCUMENT_UPLOAD: 'Tải lên tài liệu',
  DOCUMENT_ACTIVATE: 'Kích hoạt tài liệu',
  DOCUMENT_VERSION_UPLOAD: 'Tải lên phiên bản mới',
  DOCUMENT_RECLASSIFY: 'Điều chỉnh mức độ mật',
  DOCUMENT_ARCHIVE: 'Lưu trữ tài liệu',
  DOCUMENT_VIEW: 'Xem tài liệu',
  DOCUMENT_PREVIEW: 'Xem trước tài liệu',
  DOCUMENT_DOWNLOAD: 'Tải về tài liệu',
  DOCUMENT_DISCOVER: 'Tra cứu danh mục tài liệu',
  ACCESS_REQUEST_CREATE: 'Gửi yêu cầu quyền truy cập',
  ACCESS_REQUEST_APPROVE: 'Phê duyệt yêu cầu truy cập',
  ACCESS_REQUEST_REJECT: 'Từ chối yêu cầu truy cập',
  ACCESS_REQUEST_CANCEL: 'Hủy yêu cầu truy cập',
  ACCESS_GRANT_CREATE: 'Cấp quyền truy cập',
  ACCESS_GRANT_REVOKE: 'Thu hồi quyền truy cập',
  ACCESS_SESSION_CREATE: 'Mở phiên đọc tài liệu',
  ACCESS_SESSION_TERMINATE: 'Ngắt phiên đọc tài liệu',
  POLICY_CREATE: 'Tạo chính sách truy cập',
  POLICY_UPDATE: 'Cập nhật chính sách truy cập',
  POLICY_ACTIVATE: 'Kích hoạt chính sách truy cập',
  POLICY_SIMULATED: 'Mô phỏng đánh giá chính sách',
  WATERMARK_TRACE: 'Truy vết watermark bảo mật',
  WATERMARK_CONFIG_UPDATE: 'Cập nhật cấu hình watermark',
  ALERT_UPDATE: 'Cập nhật cảnh báo an ninh',
  INCIDENT_CREATE: 'Tạo hồ sơ sự cố',
  INCIDENT_UPDATE: 'Cập nhật hồ sơ sự cố',
  AUDIT_EXPORT: 'Xuất báo cáo kiểm toán',
  AUDIT_VERIFY: 'Kiểm tra toàn vẹn nhật ký',
  USER_CREATE: 'Tạo tài khoản người dùng',
  USER_UPDATE: 'Cập nhật tài khoản người dùng',
  USER_CLEARANCE_UPDATE: 'Cập nhật cấp thẩm quyền bảo mật',
  ROLE_ASSIGN: 'Gán vai trò người dùng',
};

const AUDIT_OBJECT_TYPE_LABELS: Readonly<Record<string, string>> = {
  DOCUMENT: 'Tài liệu',
  DOCUMENT_VERSION: 'Phiên bản tài liệu',
  ACCESS_GRANT: 'Quyền truy cập',
  ACCESS_REQUEST: 'Yêu cầu truy cập',
  ACCESS_SESSION: 'Phiên đọc tài liệu',
  AUTH_SESSION: 'Phiên đăng nhập',
  USER: 'Tài khoản người dùng',
  ROLE: 'Vai trò',
  DEPARTMENT: 'Phòng ban',
  POLICY: 'Chính sách bảo mật',
  SECURITY_ALERT: 'Cảnh báo an ninh',
  INCIDENT_REPORT: 'Hồ sơ sự cố',
  WATERMARK_INSTANCE: 'Watermark bảo mật',
  WATERMARK_CONFIG: 'Cấu hình watermark',
  EXPORT_JOB: 'Báo cáo xuất tệp',
  AUDIT_LOG: 'Nhật ký kiểm toán',
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

const DETECTION_RULE_LABELS: Readonly<Record<string, string>> = {
  ANOMALY_DETECTION: 'Phát hiện hành vi bất thường',
  RAPID_DOWNLOAD_BURST: 'Tải về hàng loạt bất thường',
  OFF_HOURS_SECRET_ACCESS: 'Truy cập tài liệu mật ngoài giờ làm việc',
  REPEATED_ACCESS_DENIED: 'Truy cập bị từ chối liên tiếp nhiều lần',
  SUSPICIOUS_IP_SHIFT: 'Thay đổi địa chỉ IP truy cập bất thường',
  REFRESH_TOKEN_REUSE: 'Nghi vấn chiếm đoạt phiên đăng nhập',
  WATERMARK_EGRESS_BLOCK: 'Phát hiện rò rỉ tài liệu có watermark bảo mật',
  SENSITIVE_DATA_EXFILTRATION: 'Phát hiện dữ liệu nhạy cảm truyền ra ngoài',
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

export function formatAuditPartitionLabel(partition: string | null | undefined): string {
  const key = normalizeKey(partition);
  if (!key || key === 'GLOBAL') return 'Toàn hệ thống';
  return partition!.trim();
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

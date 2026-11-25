/**
 * Thuật toán: Ánh Xạ Tất Định Mã Lỗi Nghiệp Vụ & Thông Điệp Máy Chủ Sang Tiếng Việt Chuẩn Xác (`localizeApiErrorMessage`)
 * Mục đích: Chuyển đổi nhất quán các mã `errorCode` từ `@sda/contracts` và thông báo tiếng Anh thô từ tầng Guard/Filter của Backend sang thông điệp tiếng Việt rõ nghĩa, dễ hành động cho người dùng cuối mà không làm lộ chi tiết hạ tầng nội bộ.
 * Cơ chế hoạt động:
 *   - Bước 1: Chuẩn hóa `errorCode` (hoặc `code`) sang chữ in hoa và gộp mảng/chuỗi `message` từ phản hồi lỗi.
 *   - Bước 2: Tra cứu `O(1)` trên bảng mã lỗi miền chuyên biệt (`SPECIFIC_ERROR_CODE_MAP`); nếu khớp thì trả ngay bản dịch chuẩn xác.
 *   - Bước 3: Nếu thông điệp gốc đã chứa dấu tiếng Việt hợp lệ thì bảo toàn nguyên vẹn; ngược lại đối sánh bảng câu tiếng Anh phổ biến của Auth/CSRF/WebAuthn trước khi lùi về bảng mã HTTP tổng quát (`GENERIC_ERROR_CODE_MAP`).
 */

export interface RawApiErrorPayload {
  statusCode?: number;
  errorCode?: string;
  code?: string;
  message?: string | string[];
  error?: string;
  details?: unknown;
}

const ABAC_ATTRIBUTE_LABELS: Readonly<Record<string, string>> = {
  SUBJECT_DEPARTMENT: 'phòng ban trực thuộc',
  CLEARANCE_LEVEL: 'cấp thẩm quyền bảo mật',
  EMPLOYMENT_STATUS: 'trạng thái nhân sự',
  CLASSIFICATION_RANK: 'hạng phân loại tài liệu',
  RESOURCE_DEPARTMENT: 'phòng ban quản lý tài liệu',
  RESOURCE_CATEGORY: 'danh mục nghiệp vụ tài liệu',
};

const KNOWN_ABAC_REASONS = [
  'MISSING_REQUIRED_ATTRIBUTE',
  'INSUFFICIENT_CLEARANCE',
  'EXPLICIT_DENY',
  'DEFAULT_DENY',
  'INVALID_POLICY',
] as const;

type AbacReasonCode = (typeof KNOWN_ABAC_REASONS)[number];

/**
 * Thuật toán: Phân Tích Lý Do Từ Chối ABAC Từ `details` & Thông Điệp Máy Chủ (`resolveAbacPolicyDenialMessage`)
 * Mục đích: Phân biệt rõ nguyên nhân từ chối của động cơ ABAC (`MISSING_REQUIRED_ATTRIBUTE`, `INSUFFICIENT_CLEARANCE`, `EXPLICIT_DENY`, `DEFAULT_DENY`, `INVALID_POLICY`)
 *   cùng danh sách thuộc tính bị thiếu (như `SUBJECT_DEPARTMENT`, `CLEARANCE_LEVEL`) để hiển thị hướng dẫn khắc phục cụ thể cho người dùng.
 */
function resolveAbacPolicyDenialMessage(
  normalizedCode: string,
  rawText: string,
  details?: unknown,
): string | null {
  if (normalizedCode !== 'POLICY_DENIED' && normalizedCode !== 'GRANT_ABAC_DENIED') {
    return null;
  }

  const isGrantContext = normalizedCode === 'GRANT_ABAC_DENIED';
  const detailObj =
    details && typeof details === 'object' && !Array.isArray(details)
      ? (details as Record<string, unknown>)
      : null;

  let reasonCode: AbacReasonCode | null = null;
  const detailReason = typeof detailObj?.['reasonCode'] === 'string' ? detailObj['reasonCode'] : '';
  if (KNOWN_ABAC_REASONS.includes(detailReason as AbacReasonCode)) {
    reasonCode = detailReason as AbacReasonCode;
  } else {
    const upperText = rawText.toUpperCase();
    reasonCode = KNOWN_ABAC_REASONS.find((code) => upperText.includes(code)) ?? null;
  }

  if (!reasonCode) return null;

  if (reasonCode === 'MISSING_REQUIRED_ATTRIBUTE') {
    const rawMissing = Array.isArray(detailObj?.['missingAttributes'])
      ? detailObj['missingAttributes'].filter((item): item is string => typeof item === 'string')
      : [];
    const upperText = rawText.toUpperCase();
    const detectedKeys =
      rawMissing.length > 0
        ? rawMissing
        : Object.keys(ABAC_ATTRIBUTE_LABELS).filter((key) => upperText.includes(key));
    const missingLabels = [...new Set(detectedKeys)]
      .map((key) => ABAC_ATTRIBUTE_LABELS[key])
      .filter((label): label is string => Boolean(label));

    if (missingLabels.length > 0) {
      const joined = missingLabels.join(', ');
      return isGrantContext
        ? `Đối tượng nhận quyền chưa đủ thuộc tính bắt buộc (${joined}) theo chính sách bảo mật.`
        : `Tài khoản chưa đủ thuộc tính bắt buộc (${joined}) theo chính sách bảo mật. Vui lòng liên hệ quản trị viên để cập nhật.`;
    }
    return isGrantContext
      ? 'Đối tượng nhận quyền chưa đủ thuộc tính bắt buộc (phòng ban hoặc cấp thẩm tra) theo chính sách bảo mật.'
      : 'Tài khoản chưa đủ thuộc tính bắt buộc (phòng ban hoặc cấp thẩm tra) theo chính sách bảo mật. Vui lòng liên hệ quản trị viên để bổ sung.';
  }

  if (reasonCode === 'INSUFFICIENT_CLEARANCE') {
    return isGrantContext
      ? 'Người nhận chưa đủ cấp thẩm quyền bảo mật đối với mức độ mật của tài liệu theo chính sách bảo mật.'
      : 'Cấp thẩm quyền bảo mật của tài khoản chưa đáp ứng mức độ mật của tài liệu theo chính sách bảo mật.';
  }

  if (reasonCode === 'EXPLICIT_DENY') {
    return isGrantContext
      ? 'Chính sách bảo mật hiện hành từ chối cấp quyền truy cập tài liệu này do khớp quy tắc chặn.'
      : 'Chính sách bảo mật hiện hành từ chối truy cập tài liệu này (ví dụ: tài liệu Tuyệt mật yêu cầu xác thực đa yếu tố MFA hoặc phiên có mức rủi ro cao).';
  }

  if (reasonCode === 'DEFAULT_DENY') {
    return isGrantContext
      ? 'Chính sách bảo mật hiện hành không có quy tắc cho phép phù hợp với đối tượng nhận quyền này.'
      : 'Chính sách bảo mật hiện hành không có quy tắc cho phép phù hợp với trạng thái tài khoản hoặc ngữ cảnh truy cập hiện tại.';
  }

  return 'Cấu hình chính sách bảo mật hiện không hợp lệ nên hệ thống tạm chặn truy cập để bảo vệ tài liệu. Vui lòng báo quản trị viên.';
}

const VIETNAMESE_DIACRITIC_RE =
  /[àáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ]/iu;

const SPECIFIC_ERROR_CODE_MAP: Readonly<Record<string, string>> = {
  INVALID_CREDENTIALS: 'Tên đăng nhập hoặc mật khẩu không chính xác.',
  ACCOUNT_LOCKED: 'Tài khoản đang bị tạm khóa bảo mật.',
  ACCOUNT_DISABLED: 'Tài khoản đã bị vô hiệu hóa.',
  USER_NOT_ACTIVE: 'Tài khoản người dùng hiện không ở trạng thái hoạt động.',
  ROLE_NOT_ACTIVE: 'Vai trò được chỉ định hiện đã ngừng kích hoạt.',
  DOCUMENT_ACCESS_DENIED:
    'Bạn chưa có quyền truy cập hiệu lực để thực hiện thao tác này trên tài liệu.',
  POLICY_DENIED: 'Chính sách bảo mật hiện hành không cho phép truy cập tài liệu này.',
  GRANT_ABAC_DENIED: 'Chính sách bảo mật hiện hành không cho phép cấp quyền truy cập tài liệu này.',
  STEP_UP_MFA_REQUIRED: 'Tài liệu mật yêu cầu xác thực đa yếu tố (MFA) trước khi truy cập.',
  CLEARANCE_INSUFFICIENT:
    'Cấp thẩm quyền bảo mật của tài khoản không đủ để truy cập tài liệu mật này.',
  BELL_LAPADULA_CLEARANCE_INSUFFICIENT:
    'Cấp thẩm quyền bảo mật của tài khoản không đủ đối với mức độ mật của tài liệu này.',
  GRANT_CLEARANCE_INSUFFICIENT:
    'Người nhận chưa đủ cấp thẩm quyền bảo mật đối với mức độ mật của tài liệu.',
  WATERMARK_TOKEN_NOT_FOUND: 'Không tìm thấy mã watermark này trong dữ liệu đối soát.',
  AMBIGUOUS_WATERMARK_TOKEN:
    'Tiền tố mã watermark khớp nhiều bản ghi, vui lòng nhập đầy đủ chuỗi mã.',
  WATERMARK_CONFIG_NOT_FOUND: 'Không tìm thấy cấu hình mẫu watermark phù hợp.',
  WATERMARK_GENERATION_FAILED: 'Không thể gắn watermark bảo mật vào tài liệu.',
  DOWNLOAD_TICKET_INVALID: 'Liên kết tải xuống không hợp lệ hoặc đã được sử dụng.',
  DOWNLOAD_TICKET_EXPIRED: 'Liên kết tải xuống dùng một lần đã hết hạn hiệu lực.',
  GRANT_EXPIRED: 'Quyền truy cập tài liệu đã hết thời hạn hiệu lực.',
  GRANT_REVOKED: 'Quyền truy cập tài liệu đã bị thu hồi.',
  GRANT_ALREADY_REVOKED: 'Quyền truy cập này đã được thu hồi trước đó.',
  GRANT_NOT_FOUND: 'Không tìm thấy quyền truy cập tương ứng.',
  GRANT_OVERLAP_EXISTS:
    'Người nhận đang có quyền truy cập còn hiệu lực với phạm vi rộng hơn hoặc không tương thích cho tài liệu này. Vui lòng thu hồi quyền hiện tại trước khi cấp quyền mức khác.',
  GRANT_DOWNLOAD_FORBIDDEN: 'Mức độ mật của tài liệu không cho phép cấp quyền tải về.',
  GRANT_DURATION_EXCEEDED: 'Thời hạn cấp quyền vượt quá giới hạn tối đa theo quy định.',
  GRANT_TIME_RANGE_INVALID: 'Khoảng thời gian hiệu lực của quyền truy cập không hợp lệ.',
  GRANT_PRINCIPAL_INVALID: 'Đối tượng nhận quyền truy cập không hợp lệ.',
  GRANT_CONCURRENCY_CONFLICT:
    'Quyền truy cập vừa được thay đổi bởi thao tác khác, vui lòng tải lại danh sách.',
  DOCUMENT_NOT_FOUND: 'Không tìm thấy tài liệu yêu cầu trong kho lưu trữ.',
  DOCUMENT_NOT_DISCOVERABLE: 'Tài liệu không nằm trong phạm vi danh mục được phép tra cứu.',
  DOCUMENT_ALREADY_ACTIVE: 'Tài liệu đã ở trạng thái kích hoạt chính thức.',
  DOCUMENT_ARCHIVED: 'Tài liệu đã chuyển sang lưu trữ nên không thể thực hiện thao tác này.',
  DOCUMENT_ACTIVATION_FAILED: 'Không thể kích hoạt tài liệu do phiên bản tệp chưa sẵn sàng.',
  VERSION_NOT_CLEAN: 'Phiên bản tệp chưa hoàn tất kiểm định an toàn mã độc.',
  VERSION_NOT_FOUND: 'Không tìm thấy phiên bản tài liệu được chỉ định.',
  INVALID_VERSION_TARGET: 'Phiên bản tài liệu đích không hợp lệ.',
  RETENTION_DATE_INVALID:
    'Thời hạn lưu trữ bảo mật không hợp lệ hoặc nằm trong quá khứ (phải từ ngày hôm nay trở đi).',
  TECHNICAL_ADMIN_CANNOT_OWN:
    'Quản trị viên hệ thống không được sở hữu tài liệu nghiệp vụ theo nguyên tắc Phân tách nhiệm vụ.',
  MALWARE_DETECTED: 'Phát hiện mã độc trong tệp tải lên — yêu cầu đã bị chặn an toàn.',
  INVALID_FILE_TYPE: 'Định dạng tệp tải lên không nằm trong danh sách cho phép.',
  FILE_SIZE_EXCEEDED: 'Dung lượng tệp vượt quá giới hạn tối đa cho phép.',
  SEARCH_QUERY_TOO_LONG: 'Từ khóa tìm kiếm vượt quá độ dài tối đa cho phép.',
  SEARCH_QUERY_INVALID: 'Từ khóa tìm kiếm chứa cú pháp không hợp lệ.',
  ACCESS_REQUEST_NOT_FOUND: 'Không tìm thấy yêu cầu xin cấp quyền truy cập.',
  ACCESS_REQUEST_ALREADY_DECIDED: 'Yêu cầu cấp quyền này đã được phê duyệt hoặc từ chối trước đó.',
  ACCESS_REQUEST_DUPLICATE: 'Bạn đã có một yêu cầu cấp quyền đang chờ duyệt cho tài liệu này.',
  SESSION_NOT_FOUND: 'Không tìm thấy phiên đọc tài liệu đang hoạt động.',
  SESSION_EXPIRED: 'Phiên đọc tài liệu an toàn đã hết thời hạn hiệu lực.',
  SESSION_TERMINATED: 'Phiên truy cập tài liệu đã bị chấm dứt bởi chính sách an ninh.',
  SESSION_USER_MISMATCH: 'Phiên truy cập không khớp với định danh người dùng hiện tại.',
  OFFICE_CONVERSION_FAILED: 'Không thể chuyển đổi tài liệu sang định dạng xem trước PDF.',
  OFFICE_CONVERSION_TIMEOUT: 'Quá thời gian chờ chuyển đổi tài liệu sang bản xem trước PDF.',
  OFFICE_MACRO_BLOCKED: 'Tài liệu chứa macro thực thi đã bị chặn theo chính sách an ninh.',
  OFFICE_EXTERNAL_RESOURCE_BLOCKED: 'Tài liệu chứa liên kết tài nguyên ngoài đã bị chặn an toàn.',
  ALERT_NOT_FOUND: 'Không tìm thấy cảnh báo an ninh yêu cầu.',
  ALERT_INVALID_TRANSITION: 'Chuyển trạng thái cảnh báo an ninh không hợp lệ.',
  RESOLUTION_NOTE_REQUIRED: 'Vui lòng nhập ghi chú xử lý trước khi đóng cảnh báo an ninh.',
  INCIDENT_NOT_FOUND: 'Không tìm thấy hồ sơ sự cố an ninh.',
  INCIDENT_INVALID_TRANSITION: 'Chuyển trạng thái hồ sơ sự cố không hợp lệ.',
  INCIDENT_ACTION_NOT_FOUND: 'Không tìm thấy hạng mục hành động ứng phó sự cố.',
  COMPLETION_NOTE_REQUIRED: 'Vui lòng nhập ghi chú hoàn tất hành động khắc phục.',
  AUDITOR_CANNOT_MUTATE_INCIDENTS:
    'Kiểm toán viên độc lập chỉ có quyền tra cứu, không được chỉnh sửa hồ sơ sự cố.',
  EXPORT_JOB_NOT_FOUND: 'Không tìm thấy tác vụ kết xuất báo cáo.',
  EXPORT_JOB_EXPIRED: 'Tệp báo cáo kết xuất đã hết thời hạn tải xuống.',
  EXPORT_JOB_PENDING: 'Báo cáo kết xuất đang được tạo, vui lòng thử lại sau giây lát.',
  EXPORT_UNAUTHORIZED: 'Bạn không có thẩm quyền truy cập tệp báo cáo kết xuất này.',
  NOTIFICATION_NOT_FOUND: 'Không tìm thấy thông báo hệ thống yêu cầu.',
  WEBAUTHN_REGISTRATION_FAILED: 'Đăng ký khóa bảo mật / Passkey không thành công.',
  WEBAUTHN_VERIFICATION_FAILED: 'Xác thực khóa bảo mật / Passkey không thành công.',
  WEBAUTHN_CHALLENGE_INVALID: 'Phiên xác thực khóa bảo mật không hợp lệ hoặc đã hết hạn.',
  WEBAUTHN_CREDENTIAL_NOT_FOUND: 'Không tìm thấy khóa bảo mật khớp với tài khoản này.',
  WEBAUTHN_CLONE_DETECTED: 'Phát hiện bất thường trên khóa bảo mật — từ chối xác thực.',
  AUDIT_MUTATION_FORBIDDEN: 'Nhật ký kiểm toán là bất biến, nghiêm cấm sửa đổi hoặc xóa.',
  AUDIT_CHAIN_BROKEN: 'Phát hiện đứt gãy liên kết trong chuỗi nhật ký kiểm toán.',
  AUDIT_SEQUENCE_GAP: 'Phát hiện thiếu hụt số thứ tự trong chuỗi nhật ký kiểm toán.',
  AUDIT_ANCHOR_MISMATCH: 'Mã đối soát toàn vẹn nhật ký kiểm toán không khớp.',
  AUDIT_LOG_TAMPERED: 'Cảnh báo: phát hiện dấu hiệu can thiệp trái phép vào nhật ký kiểm toán.',
  AUDIT_EXPORT_FAILED: 'Xuất nhật ký kiểm toán không thành công.',
  AUDIT_WRITE_FAILED: 'Không thể ghi nhận bản ghi kiểm toán bắt buộc.',
  INVALID_POLICY: 'Cấu trúc điều kiện của chính sách bảo mật không hợp lệ.',
  RATE_LIMIT_EXCEEDED: 'Tần suất gửi yêu cầu vượt ngưỡng an toàn. Vui lòng thử lại sau ít phút.',
  SERVICE_UNAVAILABLE: 'Dịch vụ tạm thời gián đoạn hoặc đang bảo trì. Vui lòng thử lại sau.',
  REDIS_STATE_UNAVAILABLE: 'Dịch vụ quản lý phiên tạm thời gián đoạn. Vui lòng thử lại.',
  DISTRIBUTED_LOCK_TIMEOUT:
    'Hệ thống đang xử lý giao dịch đồng thời, vui lòng thử lại sau giây lát.',
};

const EXACT_MESSAGE_MAP: Readonly<Record<string, string>> = {
  'unable to authenticate with the supplied credentials.':
    'Tên đăng nhập hoặc mật khẩu không chính xác.',
  'authentication required.': 'Vui lòng đăng nhập để tiếp tục sử dụng hệ thống.',
  'authentication context is unavailable.': 'Ngữ cảnh phiên xác thực không khả dụng.',
  'session is no longer valid.':
    'Phiên làm việc đã hết hạn hoặc bị thu hồi. Vui lòng đăng nhập lại.',
  'mfa verification is required.': 'Yêu cầu xác thực đa yếu tố (MFA) để tiếp tục.',
  'verified mfa is required.': 'Thao tác này yêu cầu phiên đã xác thực đa yếu tố (MFA).',
  'mfa verification failed.': 'Mã xác thực đa yếu tố (MFA) không chính xác hoặc đã hết hạn.',
  'step-up authentication failed.': 'Xác thực nâng cấp bảo mật không thành công.',
  'step-up mfa verification is required to enroll or modify mfa factors.':
    'Phiên hiện tại cần xác thực đa yếu tố (MFA) bước 2 trước khi đăng ký hoặc thay đổi phương thức bảo mật. Hãy xác thực tại trang MFA rồi thử lại.',
  'an active totp authenticator is already enabled for this account.':
    'Tài khoản này đã kích hoạt sẵn ứng dụng xác thực TOTP (6 số). Bạn có thể chuyển sang nhập mã xác thực hoặc quản lý nhân tố tại trang Phiên & thiết bị.',
  'cannot remove the last active mfa factor for a privileged role.':
    'Không thể gỡ nhân tố MFA cuối cùng đối với vai trò đặc quyền bắt buộc bảo mật 2 lớp.',
  'requestedfrom cannot be in the past.': 'Thời điểm bắt đầu đề nghị không được nằm trong quá khứ.',
  'requesteduntil must be in the future.': 'Thời điểm kết thúc đề nghị phải nằm trong tương lai.',
  'requesteduntil must be after requestedfrom.':
    'Thời điểm kết thúc đề nghị phải lớn hơn thời điểm bắt đầu.',
  'requested access duration cannot exceed 365 days.':
    'Khoảng thời gian đề nghị truy cập không được vượt quá 365 ngày.',
  'password and live mfa verification are required.':
    'Vui lòng cung cấp mật khẩu hiện tại và mã MFA trực tiếp để xác nhận.',
  'reset request is invalid or expired.': 'Liên kết đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.',
  'refresh request is invalid.': 'Yêu cầu làm mới phiên làm việc không hợp lệ.',
  'csrf validation failed.':
    'Phiên bảo mật của trang đã hết hạn hoặc không hợp lệ. Vui lòng tải lại trang.',
  'request origin is not allowed.': 'Nguồn gửi yêu cầu không được phép theo chính sách bảo mật.',
  'validation failed for one or more fields.':
    'Thông tin biểu mẫu chưa hợp lệ. Vui lòng kiểm tra lại các trường dữ liệu.',
  'request validation failed.': 'Dữ liệu yêu cầu gửi lên không đúng định dạng quy định.',
  'retention date cannot be in the past.':
    'Thời hạn lưu trữ bảo mật không được nằm trong quá khứ (phải từ ngày hôm nay trở đi).',
  'active departmentid is required because subject_department is mandatory under abac policy.':
    'Vui lòng chọn phòng ban trực thuộc cho tài khoản (thuộc tính bắt buộc theo chính sách bảo mật ABAC).',
  'department cannot be cleared because subject_department is mandatory under abac policy.':
    'Không thể bỏ trống phòng ban trực thuộc vì đây là thuộc tính bắt buộc theo chính sách bảo mật ABAC.',
  'active session was not found.': 'Không tìm thấy phiên đăng nhập thiết bị đang hoạt động.',
  'no webauthn security keys found for this account.':
    'Tài khoản này chưa đăng ký khóa bảo mật / Passkey.',
  'security key credential was not recognized for this user.':
    'Khóa bảo mật không khớp với tài khoản hiện tại.',
  'security key credential is no longer active.':
    'Khóa bảo mật này đã ngừng kích hoạt hoặc bị thu hồi.',
  'security key cloning or replay attack detected.':
    'Phát hiện dấu hiệu bất thường trên khóa bảo mật.',
  'fido2 / webauthn registration verification failed.':
    'Xác minh đăng ký khóa bảo mật / Passkey không thành công.',
  'fido2 / webauthn authentication failed.': 'Xác thực khóa bảo mật / Passkey không thành công.',
  'an unexpected internal error occurred. contact the administrator with the correlation id.':
    'Máy chủ gặp sự cố xử lý nội bộ. Vui lòng thử lại hoặc liên hệ quản trị viên.',
  'disabled accounts cannot be unlocked.':
    'Tài khoản đã vô hiệu hóa không thể dùng thao tác Mở khóa; vui lòng dùng thao tác Kích hoạt lại.',
  'only disabled accounts can be reactivated.':
    'Chỉ có thể kích hoạt lại các tài khoản đang ở trạng thái Vô hiệu hóa.',
  'validto must be later than validfrom.':
    'Thời điểm kết thúc hiệu lực phải lớn hơn thời điểm bắt đầu.',
  'validto must be later than validfrom':
    'Thời điểm kết thúc hiệu lực phải lớn hơn thời điểm bắt đầu.',
  'validto must be in the future.': 'Thời điểm kết thúc hiệu lực phải nằm trong tương lai.',
  'validto must be in the future': 'Thời điểm kết thúc hiệu lực phải nằm trong tương lai.',
  'validfrom cannot be in the past.': 'Thời điểm bắt đầu hiệu lực không được nằm trong quá khứ.',
  'validfrom cannot be in the past': 'Thời điểm bắt đầu hiệu lực không được nằm trong quá khứ.',
  'administrators cannot assign roles to themselves.':
    'Quản trị viên không thể tự gán vai trò cho chính mình.',
  'administrators cannot revoke their own roles.':
    'Quản trị viên không thể tự thu hồi vai trò của chính mình.',
  'administrators cannot change a role they hold.':
    'Quản trị viên không thể tự chỉnh sửa vai trò mà chính mình đang nắm giữ.',
  'administrators cannot disable a role they hold.':
    'Quản trị viên không thể tự vô hiệu hóa vai trò mà chính mình đang nắm giữ.',
  'administrators cannot lock themselves.':
    'Quản trị viên không thể tự khóa tài khoản của chính mình.',
  'administrators cannot disable themselves.':
    'Quản trị viên không thể tự vô hiệu hóa tài khoản của chính mình.',
  'role assignment history prevents deletion; disable the role instead.':
    'Vai trò đã có lịch sử gán cho người dùng nên không thể xóa vĩnh viễn; vui lòng dùng thao tác Vô hiệu hóa.',
  'cannot activate department while parent department is inactive.':
    'Không thể kích hoạt lại phòng ban khi đơn vị cấp trên đang ngừng hoạt động.',
  'department is already active.': 'Phòng ban này hiện đang hoạt động.',
  'role is already active.': 'Vai trò này hiện đang hoạt động.',
  'system role mapping is outside the approved permission matrix.':
    'Danh sách quyền chọn cho vai trò hệ thống vượt quá ma trận đặc quyền tối thiểu cho phép.',
  'role permissions violate separation of duties across incompatible security domains.':
    'Tập quyền vi phạm nguyên tắc Phân tách nhiệm vụ (không thể gộp quyền Quản trị, SOC, Kiểm toán và Nghiệp vụ tài liệu vào cùng một vai trò).',
  'separation of duties violation: privileged roles and capabilities are mutually exclusive and cannot be combined with business roles.':
    'Vi phạm nguyên tắc Phân tách nhiệm vụ (SoD): vai trò đặc quyền (Quản trị / SOC / Kiểm toán) không được gán chồng lấp thời gian với nhau hoặc với vai trò nghiệp vụ tài liệu.',
  'separation of duties violation: updating role permissions conflicts with another role held by an assigned user.':
    'Vi phạm Phân tách nhiệm vụ (SoD): tập quyền mới xung đột với vai trò khác mà nhân sự đang nắm giữ.',
};

const GENERIC_ERROR_CODE_MAP: Readonly<Record<string, string>> = {
  VALIDATION_FAILED: 'Dữ liệu gửi lên không hợp lệ, vui lòng kiểm tra lại thông tin.',
  UNAUTHORIZED: 'Phiên xác thực không hợp lệ hoặc đã hết hạn. Vui lòng đăng nhập lại.',
  FORBIDDEN: 'Bạn không đủ thẩm quyền để thực hiện thao tác này.',
  RESOURCE_NOT_FOUND: 'Không tìm thấy tài nguyên hoặc bản ghi yêu cầu.',
  RESOURCE_CONFLICT: 'Dữ liệu bị xung đột hoặc đã tồn tại bản ghi trùng lặp.',
  INTERNAL_SERVER_ERROR: 'Hệ thống gặp sự cố nội bộ. Vui lòng thử lại sau giây lát.',
};

function translateEnglishPattern(rawMessage: string): string | null {
  const normalized = rawMessage.trim().toLowerCase();
  if (!normalized) return null;

  const exact = EXACT_MESSAGE_MAP[normalized];
  if (exact) return exact;

  if (normalized.includes('too many') || normalized.includes('rate limit')) {
    return 'Quá nhiều yêu cầu liên tiếp trong thời gian ngắn. Vui lòng đợi ít phút rồi thử lại.';
  }
  if (normalized.includes('account') && normalized.includes('locked')) {
    return 'Tài khoản đang bị tạm khóa bảo mật.';
  }
  if (normalized.includes('account') && normalized.includes('disabled')) {
    return 'Tài khoản đã bị vô hiệu hóa.';
  }
  if (normalized.includes('challenge token')) {
    return 'Phiên xác thực khóa bảo mật đã hết hạn hoặc không hợp lệ. Vui lòng thử lại.';
  }
  if (normalized.includes('password_contains_identifier')) {
    return 'Mật khẩu mới không được chứa tên đăng nhập hoặc phần tên email của tài khoản.';
  }
  if (normalized.includes('password_common')) {
    return 'Mật khẩu quá phổ biến và dễ đoán. Vui lòng chọn cụm mật khẩu độc đáo hơn.';
  }
  if (
    normalized.includes('password_length') ||
    (normalized.includes('password') && normalized.includes('15'))
  ) {
    return 'Mật khẩu bắt buộc có độ dài từ 15 đến 128 ký tự theo tiêu chuẩn bảo mật NIST SP 800-63B.';
  }
  return null;
}

export function localizeApiErrorMessage(
  status: number,
  response: RawApiErrorPayload,
  explicitMessage?: string,
): string {
  if (explicitMessage && explicitMessage.trim()) {
    const mappedExplicit = translateEnglishPattern(explicitMessage);
    return mappedExplicit ?? explicitMessage.trim();
  }

  const rawText = (
    Array.isArray(response.message)
      ? response.message.join(', ')
      : response.message || response.error || ''
  ).trim();

  const normalizedCode = (response.errorCode ?? response.code ?? '').trim().toUpperCase();
  const specificAbacMessage = resolveAbacPolicyDenialMessage(
    normalizedCode,
    rawText,
    response.details,
  );
  if (specificAbacMessage) {
    return specificAbacMessage;
  }

  if (
    normalizedCode === 'GRANT_CLEARANCE_INSUFFICIENT' &&
    rawText.toLowerCase().includes('role holders')
  ) {
    return 'Không thể cấp quyền cho vai trò này vì còn thành viên đang hoạt động có cấp thẩm quyền bảo mật thấp hơn mức độ mật của tài liệu.';
  }

  if (normalizedCode && SPECIFIC_ERROR_CODE_MAP[normalizedCode]) {
    return SPECIFIC_ERROR_CODE_MAP[normalizedCode]!;
  }

  if (rawText) {
    const patternTranslated = translateEnglishPattern(rawText);
    if (patternTranslated) return patternTranslated;
    if (VIETNAMESE_DIACRITIC_RE.test(rawText)) return rawText;
  }

  if (normalizedCode && GENERIC_ERROR_CODE_MAP[normalizedCode]) {
    return GENERIC_ERROR_CODE_MAP[normalizedCode]!;
  }

  if (status === 400) return GENERIC_ERROR_CODE_MAP['VALIDATION_FAILED']!;
  if (status === 401) return GENERIC_ERROR_CODE_MAP['UNAUTHORIZED']!;
  if (status === 403) return GENERIC_ERROR_CODE_MAP['FORBIDDEN']!;
  if (status === 404) return GENERIC_ERROR_CODE_MAP['RESOURCE_NOT_FOUND']!;
  if (status === 409) return GENERIC_ERROR_CODE_MAP['RESOURCE_CONFLICT']!;
  if (status === 429) return SPECIFIC_ERROR_CODE_MAP['RATE_LIMIT_EXCEEDED']!;
  if (status >= 500) return GENERIC_ERROR_CODE_MAP['INTERNAL_SERVER_ERROR']!;

  return rawText || `Yêu cầu không thành công (mã lỗi ${status}).`;
}

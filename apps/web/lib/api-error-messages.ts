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
}

const VIETNAMESE_DIACRITIC_RE =
  /[àáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ]/iu;

const SPECIFIC_ERROR_CODE_MAP: Readonly<Record<string, string>> = {
  INVALID_CREDENTIALS: 'Tên đăng nhập hoặc mật khẩu không chính xác.',
  ACCOUNT_LOCKED: 'Tài khoản đang bị tạm khóa bảo mật.',
  ACCOUNT_DISABLED: 'Tài khoản đã bị vô hiệu hóa.',
  USER_NOT_ACTIVE: 'Tài khoản người dùng hiện không ở trạng thái hoạt động.',
  ROLE_NOT_ACTIVE: 'Vai trò được chỉ định hiện đã ngừng kích hoạt.',
  DOCUMENT_ACCESS_DENIED: 'Bạn chưa có giấy phép hiệu lực để thực hiện thao tác này trên tài liệu.',
  POLICY_DENIED: 'Chính sách bảo mật ABAC từ chối truy cập tài liệu này.',
  GRANT_ABAC_DENIED: 'Chính sách bảo mật ABAC từ chối cấp quyền truy cập tài liệu này.',
  STEP_UP_MFA_REQUIRED: 'Tài liệu mật yêu cầu xác thực đa yếu tố (MFA) trước khi truy cập.',
  CLEARANCE_INSUFFICIENT:
    'Cấp độ thẩm quyền bảo mật của tài khoản không đủ để truy cập tài liệu mật này.',
  BELL_LAPADULA_CLEARANCE_INSUFFICIENT:
    'Vi phạm nguyên tắc Bell-LaPadula: cấp thẩm quyền không đủ cho mức phân loại mật của tài liệu.',
  GRANT_CLEARANCE_INSUFFICIENT:
    'Người nhận chưa đủ cấp thẩm quyền bảo mật đối với mức độ mật của tài liệu.',
  WATERMARK_TOKEN_NOT_FOUND: 'Không tìm thấy mã thủy vân này trong sổ cái đối soát pháp chứng.',
  AMBIGUOUS_WATERMARK_TOKEN:
    'Tiền tố mã thủy vân khớp nhiều bản ghi, vui lòng nhập đầy đủ chuỗi mã.',
  WATERMARK_CONFIG_NOT_FOUND: 'Không tìm thấy cấu hình mẫu thủy vân phù hợp.',
  WATERMARK_GENERATION_FAILED: 'Không thể nhúng dấu thủy vân bảo mật vào tài liệu.',
  DOWNLOAD_TICKET_INVALID: 'Vé tải xuống không hợp lệ hoặc đã được sử dụng.',
  DOWNLOAD_TICKET_EXPIRED: 'Vé tải xuống dùng một lần đã hết hạn hiệu lực.',
  GRANT_EXPIRED: 'Giấy phép truy cập tài liệu đã hết thời hạn hiệu lực.',
  GRANT_REVOKED: 'Giấy phép truy cập tài liệu đã bị thu hồi.',
  GRANT_ALREADY_REVOKED: 'Giấy phép truy cập này đã được thu hồi trước đó.',
  GRANT_NOT_FOUND: 'Không tìm thấy giấy phép truy cập tương ứng.',
  GRANT_OVERLAP_EXISTS: 'Đã tồn tại giấy phép truy cập trùng khoảng thời gian hiệu lực.',
  GRANT_DOWNLOAD_FORBIDDEN: 'Cấp độ mật của tài liệu không cho phép cấp quyền tải xuống.',
  GRANT_DURATION_EXCEEDED: 'Thời hạn cấp quyền vượt quá giới hạn tối đa theo quy định.',
  GRANT_TIME_RANGE_INVALID: 'Khoảng thời gian hiệu lực của giấy phép không hợp lệ.',
  GRANT_PRINCIPAL_INVALID: 'Đối tượng nhận quyền truy cập không hợp lệ.',
  GRANT_CONCURRENCY_CONFLICT:
    'Giấy phép vừa được thay đổi bởi thao tác khác, vui lòng tải lại danh sách.',
  DOCUMENT_NOT_FOUND: 'Không tìm thấy tài liệu yêu cầu trong kho lưu trữ.',
  DOCUMENT_NOT_DISCOVERABLE: 'Tài liệu không nằm trong phạm vi danh mục được phép tra cứu.',
  DOCUMENT_ALREADY_ACTIVE: 'Tài liệu đã ở trạng thái kích hoạt chính thức.',
  DOCUMENT_ARCHIVED: 'Tài liệu đã chuyển sang lưu trữ nên không thể thực hiện thao tác này.',
  DOCUMENT_ACTIVATION_FAILED: 'Không thể kích hoạt tài liệu do phiên bản tệp chưa sẵn sàng.',
  VERSION_NOT_CLEAN: 'Phiên bản tệp chưa hoàn tất kiểm định an toàn mã độc.',
  VERSION_NOT_FOUND: 'Không tìm thấy phiên bản tài liệu được chỉ định.',
  INVALID_VERSION_TARGET: 'Phiên bản tài liệu đích không hợp lệ.',
  RETENTION_DATE_INVALID: 'Ngày hết hạn lưu trữ tài liệu không hợp lệ.',
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
  WEBAUTHN_REGISTRATION_FAILED: 'Đăng ký khóa bảo mật FIDO2 / Passkey không thành công.',
  WEBAUTHN_VERIFICATION_FAILED: 'Xác thực chữ ký khóa bảo mật FIDO2 / Passkey không thành công.',
  WEBAUTHN_CHALLENGE_INVALID: 'Thách thức mật mã WebAuthn không hợp lệ hoặc đã hết hạn.',
  WEBAUTHN_CREDENTIAL_NOT_FOUND: 'Không tìm thấy khóa bảo mật FIDO2 khớp với tài khoản này.',
  WEBAUTHN_CLONE_DETECTED: 'Phát hiện bất thường bộ đếm khóa bảo mật FIDO2 — từ chối xác thực.',
  AUDIT_MUTATION_FORBIDDEN: 'Nhật ký kiểm toán là bất biến, nghiêm cấm sửa đổi hoặc xóa.',
  AUDIT_CHAIN_BROKEN: 'Phát hiện đứt gãy liên kết trên chuỗi băm nhật ký kiểm toán.',
  AUDIT_SEQUENCE_GAP: 'Phát hiện thiếu hụt số thứ tự trong chuỗi nhật ký kiểm toán.',
  AUDIT_ANCHOR_MISMATCH: 'Mỏ neo đối soát chữ ký nhật ký kiểm toán không khớp.',
  AUDIT_LOG_TAMPERED: 'Cảnh báo: phát hiện dấu hiệu can thiệp trái phép vào nhật ký kiểm toán.',
  AUDIT_EXPORT_FAILED: 'Kết xuất nhật ký kiểm toán không thành công.',
  AUDIT_WRITE_FAILED: 'Không thể ghi nhận bản ghi kiểm toán bắt buộc.',
  INVALID_POLICY: 'Cấu trúc biểu thức điều kiện chính sách ABAC không hợp lệ.',
  RATE_LIMIT_EXCEEDED: 'Tần suất gửi yêu cầu vượt ngưỡng an toàn. Vui lòng thử lại sau ít phút.',
  SERVICE_UNAVAILABLE: 'Dịch vụ tạm thời gián đoạn hoặc đang bảo trì. Vui lòng thử lại sau.',
  REDIS_STATE_UNAVAILABLE: 'Bộ nhớ điều phối phiên tạm thời gián đoạn. Vui lòng thử lại.',
  DISTRIBUTED_LOCK_TIMEOUT:
    'Hệ thống đang xử lý giao dịch đồng thời, vui lòng thử lại ngay sau đó.',
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
  'password and live mfa verification are required.':
    'Vui lòng cung cấp mật khẩu hiện tại và mã MFA trực tiếp để xác nhận.',
  'reset request is invalid or expired.': 'Liên kết đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.',
  'refresh request is invalid.': 'Yêu cầu làm mới phiên làm việc không hợp lệ.',
  'csrf validation failed.':
    'Mã bảo vệ chống giả mạo yêu cầu (CSRF) không khớp. Vui lòng tải lại trang.',
  'request origin is not allowed.': 'Nguồn gửi yêu cầu không được phép theo chính sách bảo mật.',
  'validation failed for one or more fields.':
    'Thông tin biểu mẫu chưa hợp lệ. Vui lòng kiểm tra lại các trường dữ liệu.',
  'request validation failed.': 'Dữ liệu yêu cầu gửi lên không đúng định dạng quy định.',
  'active session was not found.': 'Không tìm thấy phiên đăng nhập thiết bị đang hoạt động.',
  'no webauthn security keys found for this account.':
    'Tài khoản này chưa đăng ký khóa bảo mật vật lý FIDO2 / Passkey.',
  'security key credential was not recognized for this user.':
    'Khóa bảo mật FIDO2 không khớp với tài khoản hiện tại.',
  'security key credential is no longer active.':
    'Khóa bảo mật FIDO2 này đã ngừng kích hoạt hoặc bị thu hồi.',
  'security key cloning or replay attack detected.':
    'Phát hiện dấu hiệu sao chép hoặc phát lại khóa bảo mật FIDO2.',
  'fido2 / webauthn registration verification failed.':
    'Xác minh đăng ký khóa FIDO2 / Passkey không thành công.',
  'fido2 / webauthn authentication failed.': 'Xác thực khóa FIDO2 / Passkey không thành công.',
  'an unexpected internal error occurred. contact the administrator with the correlation id.':
    'Máy chủ gặp sự cố xử lý nội bộ. Vui lòng thử lại hoặc liên hệ quản trị viên.',
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
    return 'Thách thức mật mã xác thực đã hết hạn hoặc không hợp lệ. Vui lòng thử lại.';
  }
  if (normalized.includes('password') && normalized.includes('15')) {
    return 'Mật khẩu bắt buộc có độ dài tối thiểu 15 ký tự và đáp ứng quy tắc phức tạp.';
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

  const normalizedCode = (response.errorCode ?? response.code ?? '').trim().toUpperCase();
  if (normalizedCode && SPECIFIC_ERROR_CODE_MAP[normalizedCode]) {
    return SPECIFIC_ERROR_CODE_MAP[normalizedCode]!;
  }

  const rawText = (
    Array.isArray(response.message)
      ? response.message.join(', ')
      : response.message || response.error || ''
  ).trim();

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

  return rawText || `Yêu cầu không thành công (mã trạng thái HTTP ${status}).`;
}

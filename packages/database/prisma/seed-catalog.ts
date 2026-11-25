/**
 * Thuật toán: Danh mục dữ liệu nền tảng bất biến cho quá trình khởi tạo lũy đẳng (`seed-catalog`)
 * gồm phân loại độ mật Bell-LaPadula, ma trận RBAC tách quyền (SoD), từ điển thuộc tính ABAC và tập luật Zero-Trust gốc.
 */
export const fixedSeedTime = new Date('2026-01-01T00:00:00.000Z');
export const disabledPasswordHash = '!AUTHENTICATION_NOT_CONFIGURED_DEMO_ACCOUNT!';

// CONFLICT-RESOLVED: Giữ thang bậc CSDL chuẩn INTERNAL: 1 .. TOP_SECRET: 4 (với 0 dành riêng cho UNCLASSIFIED) và đồng bộ ngược sang packages/contracts/src/classifications.ts để khớp với tập chính sách ABAC (GTE 4 cho TOP_SECRET).
export const classificationLevels = [
  { code: 'INTERNAL', name: 'Nội bộ', rank: 1, allow_download: true },
  { code: 'CONFIDENTIAL', name: 'Mật', rank: 2, allow_download: true },
  { code: 'SECRET', name: 'Tối mật', rank: 3, allow_download: false },
  { code: 'TOP_SECRET', name: 'Tuyệt mật', rank: 4, allow_download: false },
] as const;

export const systemRoles = [
  ['SYSTEM_ADMIN', 'Quản trị viên hệ thống'],
  ['SECURITY_OFFICER', 'Nhân viên bảo mật'],
  ['AUDITOR', 'Kiểm toán viên'],
  ['DOCUMENT_OWNER', 'Chủ sở hữu tài liệu'],
  ['DOCUMENT_READER', 'Người đọc tài liệu'],
] as const;

export const permissions = [
  ['USER_MANAGE', 'USER', 'MANAGE', 'Quản lý người dùng'],
  ['DEPARTMENT_MANAGE', 'DEPARTMENT', 'MANAGE', 'Quản lý phòng ban'],
  ['ROLE_MANAGE', 'ROLE', 'MANAGE', 'Quản lý vai trò RBAC'],
  ['ATTRIBUTE_MANAGE', 'ATTRIBUTE', 'MANAGE', 'Quản lý thuộc tính ABAC'],
  ['POLICY_MANAGE', 'POLICY', 'MANAGE', 'Quản lý chính sách ABAC'],
  ['POLICY_SIMULATE', 'POLICY', 'SIMULATE', 'Mô phỏng chính sách ABAC'],
  ['WATERMARK_CONFIG_MANAGE', 'WATERMARK_CONFIG', 'MANAGE', 'Quản lý cấu hình watermark'],
  ['SYSTEM_HEALTH_VIEW', 'SYSTEM_HEALTH', 'VIEW', 'Xem sức khỏe hệ thống'],
  // CONFLICT-RESOLVED: Bổ sung cặp quyền SYSTEM_HEALTH_MANAGE và DOCUMENT_MANAGE đồng bộ giữa Prisma seed-catalog, Supabase SQL và bộ quyền RBAC tầng API.
  ['SYSTEM_HEALTH_MANAGE', 'SYSTEM_HEALTH', 'MANAGE', 'Quản trị sức khỏe hệ thống'],
  ['DOCUMENT_UPLOAD', 'DOCUMENT', 'UPLOAD', 'Tải lên tài liệu'],
  ['DOCUMENT_CLASSIFY', 'DOCUMENT', 'CLASSIFY', 'Phân loại độ mật tài liệu'],
  ['DOCUMENT_VERSION_CREATE', 'DOCUMENT_VERSION', 'CREATE', 'Tạo phiên bản tài liệu'],
  ['DOCUMENT_ARCHIVE', 'DOCUMENT', 'ARCHIVE', 'Lưu trữ tài liệu'],
  ['DOCUMENT_MANAGE', 'DOCUMENT', 'MANAGE', 'Quản lý tài liệu'],
  ['DOCUMENT_DISCOVER', 'DOCUMENT', 'DISCOVER', 'Tra cứu danh mục tài liệu'],
  ['DOCUMENT_VIEW', 'DOCUMENT', 'VIEW', 'Xem nội dung tài liệu'],
  ['DOCUMENT_DOWNLOAD', 'DOCUMENT', 'DOWNLOAD', 'Tải xuống tài liệu'],
  ['ACCESS_REQUEST_CREATE', 'ACCESS_REQUEST', 'CREATE', 'Gửi yêu cầu cấp quyền'],
  ['ACCESS_REQUEST_VIEW_OWN', 'ACCESS_REQUEST', 'VIEW_OWN', 'Xem yêu cầu truy cập cá nhân'],
  ['ACCESS_REQUEST_CANCEL', 'ACCESS_REQUEST', 'CANCEL', 'Hủy yêu cầu cấp quyền'],
  ['ACCESS_REQUEST_DECIDE', 'ACCESS_REQUEST', 'DECIDE', 'Phê duyệt yêu cầu cấp quyền'],
  ['ACCESS_GRANT_CREATE', 'ACCESS_GRANT', 'CREATE', 'Cấp quyền truy cập'],
  ['ACCESS_GRANT_REVOKE', 'ACCESS_GRANT', 'REVOKE', 'Thu hồi quyền truy cập'],
  ['ACCESS_GRANT_VIEW', 'ACCESS_GRANT', 'VIEW', 'Xem danh sách cấp quyền'],
  ['AUDIT_VIEW', 'AUDIT_LOG', 'VIEW', 'Xem nhật ký kiểm toán'],
  ['AUDIT_EXPORT', 'AUDIT_LOG', 'EXPORT', 'Xuất nhật ký kiểm toán'],
  ['ALERT_VIEW', 'SECURITY_ALERT', 'VIEW', 'Xem cảnh báo an ninh'],
  ['ALERT_MANAGE', 'SECURITY_ALERT', 'MANAGE', 'Xử lý cảnh báo an ninh'],
  ['WATERMARK_TRACE', 'WATERMARK_INSTANCE', 'TRACE', 'Truy vết watermark'],
  ['INCIDENT_CREATE', 'INCIDENT_REPORT', 'CREATE', 'Tạo hồ sơ sự cố'],
  ['INCIDENT_MANAGE', 'INCIDENT_REPORT', 'MANAGE', 'Quản lý & điều tra sự cố'],
  ['NOTIFICATION_VIEW', 'NOTIFICATION', 'VIEW', 'Xem thông báo'],
  ['SYSTEM_REPORT_EXPORT', 'SYSTEM_REPORT', 'EXPORT', 'Xuất báo cáo hệ thống'],
  ['ACCESS_SESSION_TERMINATE', 'ACCESS_SESSION', 'TERMINATE', 'Ngắt phiên truy cập khẩn cấp'],
] as const;

export const rolePermissionCodes: Record<(typeof systemRoles)[number][0], readonly string[]> = {
  SYSTEM_ADMIN: [
    'USER_MANAGE',
    'DEPARTMENT_MANAGE',
    'ROLE_MANAGE',
    'ATTRIBUTE_MANAGE',
    'POLICY_MANAGE',
    'POLICY_SIMULATE',
    'WATERMARK_CONFIG_MANAGE',
    'SYSTEM_HEALTH_VIEW',
    'SYSTEM_HEALTH_MANAGE',
  ],
  SECURITY_OFFICER: [
    'AUDIT_VIEW',
    'ALERT_VIEW',
    'ALERT_MANAGE',
    'WATERMARK_TRACE',
    'INCIDENT_CREATE',
    'INCIDENT_MANAGE',
    'ACCESS_SESSION_TERMINATE',
    'POLICY_SIMULATE',
  ],
  AUDITOR: ['AUDIT_VIEW', 'AUDIT_EXPORT', 'ALERT_VIEW', 'WATERMARK_TRACE', 'SYSTEM_REPORT_EXPORT'],
  DOCUMENT_OWNER: [
    'DOCUMENT_UPLOAD',
    'DOCUMENT_CLASSIFY',
    'DOCUMENT_VERSION_CREATE',
    'DOCUMENT_ARCHIVE',
    'DOCUMENT_MANAGE',
    'DOCUMENT_DISCOVER',
    'DOCUMENT_VIEW',
    'DOCUMENT_DOWNLOAD',
    'ACCESS_REQUEST_DECIDE',
    'ACCESS_REQUEST_VIEW_OWN',
    'ACCESS_GRANT_CREATE',
    'ACCESS_GRANT_REVOKE',
    'ACCESS_GRANT_VIEW',
    'NOTIFICATION_VIEW',
    'AUDIT_VIEW',
  ],
  DOCUMENT_READER: [
    'DOCUMENT_DISCOVER',
    'DOCUMENT_VIEW',
    'DOCUMENT_DOWNLOAD',
    'ACCESS_REQUEST_CREATE',
    'ACCESS_REQUEST_VIEW_OWN',
    'ACCESS_REQUEST_CANCEL',
    'NOTIFICATION_VIEW',
  ],
};

// CONFLICT-RESOLVED: Bổ sung danh mục giá trị chuẩn của thuộc tính EMPLOYMENT_STATUS đồng bộ với kịch bản Supabase SQL.
export const employmentStatusOptions = [
  ['ACTIVE_STAFF', 'Nhân sự chính thức', 2, 1],
  ['CONTRACTOR', 'Cộng tác viên / Nhà thầu', 1, 2],
  ['SUSPENDED', 'Tạm đình chỉ công tác', 0, 3],
] as const;

export const attributeDefinitions = [
  ['SUBJECT_DEPARTMENT', 'Phòng ban chủ thể', 'USER', 'STRING', true, false],
  ['EMPLOYMENT_STATUS', 'Trạng thái làm việc', 'USER', 'ENUM', true, false],
  ['PROJECT', 'Dự án', 'USER', 'STRING', false, true],
  ['CLASSIFICATION_RANK', 'Hạng phân loại tài liệu', 'RESOURCE', 'NUMBER', true, false],
  ['RESOURCE_OWNER', 'Chủ sở hữu tài liệu', 'RESOURCE', 'STRING', true, false],
  ['RESOURCE_DEPARTMENT', 'Phòng ban tài liệu', 'RESOURCE', 'STRING', true, false],
  ['RESOURCE_CATEGORY', 'Danh mục tài liệu', 'RESOURCE', 'STRING', true, false],
  ['RESOURCE_STATUS', 'Trạng thái tài liệu', 'RESOURCE', 'ENUM', true, false],
  ['CURRENT_TIME', 'Thời điểm truy cập', 'ENVIRONMENT', 'DATE', true, false],
  ['SOURCE_IP', 'Địa chỉ IP nguồn', 'ENVIRONMENT', 'STRING', true, false],
  ['TRUSTED_NETWORK', 'Mạng tin cậy', 'ENVIRONMENT', 'BOOLEAN', true, false],
  ['DEVICE_TRUST', 'Thiết bị tin cậy', 'ENVIRONMENT', 'BOOLEAN', true, false],
  ['MFA', 'Xác thực đa yếu tố', 'ENVIRONMENT', 'BOOLEAN', true, false],
  ['RISK_SCORE', 'Điểm rủi ro', 'ENVIRONMENT', 'NUMBER', true, false],
] as const;

export const demoUsers = [
  ['admin.demo', 'admin.demo@local.invalid', 'Quản trị viên demo', 'SYSTEM_ADMIN', 'INTERNAL'],
  [
    'security.demo',
    'security.demo@local.invalid',
    'Bảo mật demo',
    'SECURITY_OFFICER',
    'TOP_SECRET',
  ],
  ['auditor.demo', 'auditor.demo@local.invalid', 'Kiểm toán demo', 'AUDITOR', 'SECRET'],
  ['owner.demo', 'owner.demo@local.invalid', 'Chủ tài liệu demo', 'DOCUMENT_OWNER', 'SECRET'],
  ['reader.demo', 'reader.demo@local.invalid', 'Người đọc demo', 'DOCUMENT_READER', 'INTERNAL'],
] as const;

export const childDepartments = [
  ['INFORMATION_SECURITY', 'Phòng An toàn thông tin'],
  ['LEGAL_COMPLIANCE', 'Ban Pháp chế & Tuân thủ'],
  ['FINANCE_TREASURY', 'Phòng Tài chính - Kế toán'],
  ['RND_ENGINEERING', 'Khối Công nghệ & Kỹ thuật'],
] as const;

export const businessCategoriesCatalog = [
  [
    'GENERAL_OPERATIONS',
    'Nghiệp vụ chung',
    'HEAD_OFFICE',
    'Văn bản điều hành và quy trình nội bộ chung',
  ],
  [
    'SECURITY_OPERATIONS',
    'An toàn thông tin',
    'INFORMATION_SECURITY',
    'Chính sách bảo mật, báo cáo SOC và biên bản điều tra sự cố',
  ],
  [
    'LEGAL_CONTRACTS',
    'Hồ sơ Pháp lý & Hợp đồng',
    'LEGAL_COMPLIANCE',
    'Hợp đồng chiến lược, biên bản thỏa thuận bảo mật NDA',
  ],
  [
    'FINANCIAL_REPORTS',
    'Báo cáo Tài chính & Ngân sách',
    'FINANCE_TREASURY',
    'Báo cáo kiểm toán tài chính, dự toán ngân sách trọng yếu',
  ],
] as const;

export const tierWatermarkConfigs = [
  [
    'SECRET',
    'Đóng dấu Tối mật (SECRET)',
    'SECRET - DO NOT DISTRIBUTE | {username} ({employeeCode}) | {documentCode} | {timestamp} | {shortToken}',
    32,
    13,
    '#991B1B',
  ],
  [
    'TOP_SECRET',
    'Đóng dấu Tuyệt mật (TOP SECRET)',
    'TOP SECRET - FORENSIC TRACKED | {username} ({employeeCode}) | {documentCode} | {timestamp} | {shortToken}',
    38,
    14,
    '#7F1D1D',
  ],
] as const;

// CONFLICT-RESOLVED: Chuẩn hóa nghĩa vụ sang định dạng đối tượng `{ type }` khớp tuyệt đối lược đồ `PUT /abac/policies/:id`, mở rộng `POL-DENY-TOP-SECRET-WITHOUT-MFA` lên mọi hành động (`target_action: null`) và duy trì luật PERMIT nền tảng cho nhân sự đang hoạt động trên tài liệu ACTIVE.
export const baselineAbacPolicies = [
  {
    code: 'POL-DENY-HIGH-RISK-SESSION',
    name: 'Từ chối truy cập khi điểm rủi ro phiên vượt ngưỡng an toàn',
    description: 'Chặn mọi hành động trên tài liệu nếu điểm rủi ro môi trường >= 80',
    effect: 'DENY' as const,
    priority: 10,
    target_resource: 'DOCUMENT',
    target_action: null,
    combining_algorithm: 'DENY_OVERRIDES' as const,
    obligations: [{ type: 'NO_CACHE' }],
    conditions: [
      {
        context_key: 'environment.riskScore',
        operator: 'GTE' as const,
        expected_value: 80,
        condition_group: 1,
        sequence_no: 1,
      },
    ],
  },
  {
    code: 'POL-DENY-TOP-SECRET-WITHOUT-MFA',
    name: 'Bắt buộc xác thực đa yếu tố (MFA) đối với tài liệu Tuyệt mật',
    description:
      'Chặn mọi thao tác (tra cứu, xem, tải, chia sẻ, quản trị) trên tài liệu hạng 4 (TOP_SECRET) khi phiên chưa hoàn tất xác thực MFA',
    effect: 'DENY' as const,
    priority: 20,
    target_resource: 'DOCUMENT',
    target_action: null,
    combining_algorithm: 'DENY_OVERRIDES' as const,
    obligations: [{ type: 'REQUIRE_MFA' }],
    conditions: [
      {
        context_key: 'resource.classificationRank',
        operator: 'GTE' as const,
        expected_value: 4,
        condition_group: 1,
        sequence_no: 1,
      },
      {
        context_key: 'environment.mfa',
        operator: 'EQ' as const,
        expected_value: false,
        condition_group: 1,
        sequence_no: 2,
      },
    ],
  },
  {
    code: 'POL-PERMIT-CLEARED-ACTIVE-STAFF',
    name: 'Cho phép nhân sự đang hoạt động truy cập tài liệu đủ cấp độ mật',
    description:
      'Cho phép tài khoản đang hoạt động truy cập tài liệu ACTIVE khi thỏa bất biến Bell-LaPadula và không vi phạm luật DENY ưu tiên cao',
    effect: 'PERMIT' as const,
    priority: 100,
    target_resource: 'DOCUMENT',
    target_action: null,
    combining_algorithm: 'DENY_OVERRIDES' as const,
    obligations: [{ type: 'REQUIRE_WATERMARK' }, { type: 'NO_CACHE' }],
    conditions: [
      {
        context_key: 'subject.employmentStatus',
        operator: 'IN' as const,
        expected_value: ['ACTIVE', 'ACTIVE_STAFF'],
        condition_group: 1,
        sequence_no: 1,
      },
      {
        context_key: 'resource.status',
        operator: 'EQ' as const,
        expected_value: 'ACTIVE',
        condition_group: 1,
        sequence_no: 2,
      },
    ],
  },
] as const;

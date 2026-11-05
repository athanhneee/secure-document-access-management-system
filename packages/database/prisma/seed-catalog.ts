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
  ['USER_MANAGE', 'USER', 'MANAGE'],
  ['DEPARTMENT_MANAGE', 'DEPARTMENT', 'MANAGE'],
  ['ROLE_MANAGE', 'ROLE', 'MANAGE'],
  ['ATTRIBUTE_MANAGE', 'ATTRIBUTE', 'MANAGE'],
  ['POLICY_MANAGE', 'POLICY', 'MANAGE'],
  ['POLICY_SIMULATE', 'POLICY', 'SIMULATE'],
  ['WATERMARK_CONFIG_MANAGE', 'WATERMARK_CONFIG', 'MANAGE'],
  ['SYSTEM_HEALTH_VIEW', 'SYSTEM_HEALTH', 'VIEW'],
  ['DOCUMENT_UPLOAD', 'DOCUMENT', 'UPLOAD'],
  ['DOCUMENT_CLASSIFY', 'DOCUMENT', 'CLASSIFY'],
  ['DOCUMENT_VERSION_CREATE', 'DOCUMENT_VERSION', 'CREATE'],
  ['DOCUMENT_ARCHIVE', 'DOCUMENT', 'ARCHIVE'],
  ['DOCUMENT_DISCOVER', 'DOCUMENT', 'DISCOVER'],
  ['DOCUMENT_VIEW', 'DOCUMENT', 'VIEW'],
  ['DOCUMENT_DOWNLOAD', 'DOCUMENT', 'DOWNLOAD'],
  ['ACCESS_REQUEST_CREATE', 'ACCESS_REQUEST', 'CREATE'],
  ['ACCESS_REQUEST_VIEW_OWN', 'ACCESS_REQUEST', 'VIEW_OWN'],
  ['ACCESS_REQUEST_CANCEL', 'ACCESS_REQUEST', 'CANCEL'],
  ['ACCESS_REQUEST_DECIDE', 'ACCESS_REQUEST', 'DECIDE'],
  ['ACCESS_GRANT_CREATE', 'ACCESS_GRANT', 'CREATE'],
  ['ACCESS_GRANT_REVOKE', 'ACCESS_GRANT', 'REVOKE'],
  ['ACCESS_GRANT_VIEW', 'ACCESS_GRANT', 'VIEW'],
  ['AUDIT_VIEW', 'AUDIT_LOG', 'VIEW'],
  ['AUDIT_EXPORT', 'AUDIT_LOG', 'EXPORT'],
  ['ALERT_VIEW', 'SECURITY_ALERT', 'VIEW'],
  ['ALERT_MANAGE', 'SECURITY_ALERT', 'MANAGE'],
  ['WATERMARK_TRACE', 'WATERMARK_INSTANCE', 'TRACE'],
  ['INCIDENT_CREATE', 'INCIDENT_REPORT', 'CREATE'],
  ['INCIDENT_MANAGE', 'INCIDENT_REPORT', 'MANAGE'],
  ['NOTIFICATION_VIEW', 'NOTIFICATION', 'VIEW'],
  ['SYSTEM_REPORT_EXPORT', 'SYSTEM_REPORT', 'EXPORT'],
  ['ACCESS_SESSION_TERMINATE', 'ACCESS_SESSION', 'TERMINATE'],
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

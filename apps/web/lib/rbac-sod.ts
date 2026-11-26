/**
 * Thuật toán: Ma Trận Vai Trò Hệ Thống & Bộ Phân Loại Giao Tập 4 Trụ Cột Phân Tách Nhiệm Vụ SoD (`rbac-sod`)
 * Mục đích: Đồng bộ 1-1 với `apps/api/src/modules/rbac/permission-matrix.ts` và `seed-catalog.ts` (34 quyền thực tế)
 * để Modal Phân quyền nhóm chính xác 4 trụ cột SoD, khóa các ô ngoài ma trận vai trò hệ thống và khóa các quyền gây xung đột SoD trên Custom Role ngay trên giao diện.
 */

export type SodArchetype =
  'ADMIN_GOVERNANCE' | 'SECURITY_SOC' | 'AUDITOR_COMPLIANCE' | 'BUSINESS_DOCUMENT';

export type SodUiGroupKey = SodArchetype | 'SHARED_CONDITIONAL';

export const ALL_SOD_ARCHETYPES: readonly SodArchetype[] = [
  'ADMIN_GOVERNANCE',
  'SECURITY_SOC',
  'AUDITOR_COMPLIANCE',
  'BUSINESS_DOCUMENT',
];

export const SOD_ARCHETYPE_LABELS: Readonly<Record<SodArchetype, string>> = {
  ADMIN_GOVERNANCE: 'Quản trị hệ thống',
  SECURITY_SOC: 'An ninh thông tin (SOC)',
  AUDITOR_COMPLIANCE: 'Kiểm toán & Tuân thủ',
  BUSINESS_DOCUMENT: 'Nghiệp vụ tài liệu',
};

export const SOD_UI_GROUP_META: ReadonlyArray<{
  key: SodUiGroupKey;
  title: string;
  hint: string;
}> = [
  {
    key: 'ADMIN_GOVERNANCE',
    title: 'Trụ cột 1 · Quản trị hệ thống',
    hint: 'Tách biệt hoàn toàn với SOC, Kiểm toán và Nghiệp vụ tài liệu',
  },
  {
    key: 'SECURITY_SOC',
    title: 'Trụ cột 2 · An ninh thông tin (SOC)',
    hint: 'Xử lý cảnh báo, sự cố và ngắt phiên khẩn cấp',
  },
  {
    key: 'AUDITOR_COMPLIANCE',
    title: 'Trụ cột 3 · Kiểm toán & Tuân thủ',
    hint: 'Chỉ đọc & xuất báo cáo kiểm toán độc lập',
  },
  {
    key: 'BUSINESS_DOCUMENT',
    title: 'Trụ cột 4 · Nghiệp vụ tài liệu',
    hint: 'Tải lên, quản lý, cấp quyền, tra cứu và đọc tài liệu',
  },
  {
    key: 'SHARED_CONDITIONAL',
    title: 'Quyền giao thoa có điều kiện (SoD)',
    hint: 'Tương thích có chọn lọc giữa một số trụ cột theo ma trận bảo mật',
  },
];

export const SYSTEM_ROLE_ALLOWED_CODES: Readonly<Record<string, ReadonlySet<string>>> = {
  SYSTEM_ADMIN: new Set([
    'USER_MANAGE',
    'DEPARTMENT_MANAGE',
    'ROLE_MANAGE',
    'ATTRIBUTE_MANAGE',
    'POLICY_MANAGE',
    'POLICY_SIMULATE',
    'WATERMARK_CONFIG_MANAGE',
    'SYSTEM_HEALTH_VIEW',
    'SYSTEM_HEALTH_MANAGE',
    'NOTIFICATION_VIEW',
  ]),
  SECURITY_OFFICER: new Set([
    'AUDIT_VIEW',
    'ALERT_VIEW',
    'ALERT_MANAGE',
    'WATERMARK_TRACE',
    'POLICY_SIMULATE',
    'INCIDENT_CREATE',
    'INCIDENT_MANAGE',
    'ACCESS_SESSION_TERMINATE',
    'NOTIFICATION_VIEW',
  ]),
  AUDITOR: new Set([
    'AUDIT_VIEW',
    'AUDIT_EXPORT',
    'ALERT_VIEW',
    'WATERMARK_TRACE',
    'SYSTEM_REPORT_EXPORT',
    'NOTIFICATION_VIEW',
  ]),
  DOCUMENT_OWNER: new Set([
    'DOCUMENT_UPLOAD',
    'DOCUMENT_MANAGE',
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
  ]),
  DOCUMENT_READER: new Set([
    'DOCUMENT_DISCOVER',
    'DOCUMENT_VIEW',
    'DOCUMENT_DOWNLOAD',
    'ACCESS_REQUEST_CREATE',
    'ACCESS_REQUEST_VIEW_OWN',
    'ACCESS_REQUEST_CANCEL',
    'NOTIFICATION_VIEW',
  ]),
};

const ADMIN_EXCLUSIVE_CODES = new Set([
  'USER_MANAGE',
  'DEPARTMENT_MANAGE',
  'ROLE_MANAGE',
  'ATTRIBUTE_MANAGE',
  'POLICY_MANAGE',
  'WATERMARK_CONFIG_MANAGE',
  'SYSTEM_HEALTH_VIEW',
  'SYSTEM_HEALTH_MANAGE',
]);

const SECURITY_EXCLUSIVE_CODES = new Set([
  'ALERT_MANAGE',
  'INCIDENT_CREATE',
  'INCIDENT_MANAGE',
  'ACCESS_SESSION_TERMINATE',
]);

const AUDITOR_EXCLUSIVE_CODES = new Set(['AUDIT_EXPORT', 'SYSTEM_REPORT_EXPORT']);

const BUSINESS_EXCLUSIVE_CODES = new Set([
  'DOCUMENT_UPLOAD',
  'DOCUMENT_MANAGE',
  'DOCUMENT_CLASSIFY',
  'DOCUMENT_VERSION_CREATE',
  'DOCUMENT_ARCHIVE',
  'DOCUMENT_DISCOVER',
  'DOCUMENT_VIEW',
  'DOCUMENT_DOWNLOAD',
  'ACCESS_REQUEST_CREATE',
  'ACCESS_REQUEST_VIEW_OWN',
  'ACCESS_REQUEST_CANCEL',
  'ACCESS_REQUEST_DECIDE',
  'ACCESS_GRANT_CREATE',
  'ACCESS_GRANT_REVOKE',
  'ACCESS_GRANT_VIEW',
]);

export interface PermissionLike {
  code: string;
  resource?: string | undefined;
  resourceType?: string | undefined;
  action?: string | undefined;
}

/**
 * Thuật toán: Ánh Xạ Quyền Nguyên Tử Về Tập Trụ Cột SoD Được Phép (`allowedArchetypesForPermission`)
 */
export function allowedArchetypesForPermission(
  perm: string | PermissionLike,
): readonly SodArchetype[] {
  const code = (typeof perm === 'string' ? perm : perm.code).trim().toUpperCase();
  const resource =
    typeof perm === 'string'
      ? undefined
      : (perm.resource ?? perm.resourceType)?.trim().toUpperCase();
  const action = typeof perm === 'string' ? undefined : perm.action?.trim().toUpperCase();

  if (
    ADMIN_EXCLUSIVE_CODES.has(code) ||
    (resource !== undefined &&
      ['USER', 'DEPARTMENT', 'ROLE', 'ATTRIBUTE', 'WATERMARK_CONFIG', 'SYSTEM_HEALTH'].includes(
        resource,
      )) ||
    (resource === 'POLICY' && action === 'MANAGE')
  ) {
    return ['ADMIN_GOVERNANCE'];
  }
  if (
    SECURITY_EXCLUSIVE_CODES.has(code) ||
    resource === 'INCIDENT_REPORT' ||
    resource === 'ACCESS_SESSION' ||
    (resource === 'SECURITY_ALERT' && action === 'MANAGE')
  ) {
    return ['SECURITY_SOC'];
  }
  if (
    AUDITOR_EXCLUSIVE_CODES.has(code) ||
    resource === 'SYSTEM_REPORT' ||
    (resource === 'AUDIT_LOG' && action === 'EXPORT')
  ) {
    return ['AUDITOR_COMPLIANCE'];
  }
  if (
    BUSINESS_EXCLUSIVE_CODES.has(code) ||
    (resource !== undefined &&
      ['DOCUMENT', 'DOCUMENT_VERSION', 'ACCESS_REQUEST', 'ACCESS_GRANT'].includes(resource))
  ) {
    return ['BUSINESS_DOCUMENT'];
  }
  if (code === 'POLICY_SIMULATE' || (resource === 'POLICY' && action === 'SIMULATE')) {
    return ['ADMIN_GOVERNANCE', 'SECURITY_SOC'];
  }
  if (
    code === 'ALERT_VIEW' ||
    code === 'WATERMARK_TRACE' ||
    (resource === 'SECURITY_ALERT' && action === 'VIEW') ||
    resource === 'WATERMARK_INSTANCE'
  ) {
    return ['SECURITY_SOC', 'AUDITOR_COMPLIANCE'];
  }
  if (code === 'AUDIT_VIEW' || (resource === 'AUDIT_LOG' && action === 'VIEW')) {
    return ['SECURITY_SOC', 'AUDITOR_COMPLIANCE', 'BUSINESS_DOCUMENT'];
  }
  return ALL_SOD_ARCHETYPES;
}

/**
 * Thuật toán: Phân Nhóm Giao Diện Theo 4 Trụ Cột SoD + Quyền Giao Thoa Có Điều Kiện (`resolvePermissionUiGroup`)
 */
export function resolvePermissionUiGroup(perm: PermissionLike): SodUiGroupKey {
  const archetypes = allowedArchetypesForPermission(perm);
  if (archetypes.length === 1) return archetypes[0]!;
  return 'SHARED_CONDITIONAL';
}

/**
 * Thuật toán: Giao Tập Lưới Phân Tách Nhiệm Vụ Cho Tập Quyền Đang Chọn (`resolveCompatibleSodArchetypes`)
 */
export function resolveCompatibleSodArchetypes(
  selectedPermissions: readonly (string | PermissionLike)[],
): Set<SodArchetype> {
  let compatible = new Set<SodArchetype>(ALL_SOD_ARCHETYPES);
  for (const perm of selectedPermissions) {
    const allowed = allowedArchetypesForPermission(perm);
    const next = new Set<SodArchetype>();
    for (const archetype of allowed) {
      if (compatible.has(archetype)) next.add(archetype);
    }
    compatible = next;
    if (compatible.size === 0) break;
  }
  return compatible;
}

/**
 * Thuật toán: Kiểm Tra Xem Một Quyền Có Thể Chọn Thêm Mà Không Vi Phạm SoD Hay Không (`isPermissionSodCompatibleWithSelection`)
 */
export function isPermissionSodCompatibleWithSelection(
  candidate: PermissionLike,
  compatibleArchetypes: ReadonlySet<SodArchetype>,
): boolean {
  if (compatibleArchetypes.size === 0) return false;
  return allowedArchetypesForPermission(candidate).some((arch) => compatibleArchetypes.has(arch));
}

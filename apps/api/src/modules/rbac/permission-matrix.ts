export const SYSTEM_ROLE_PERMISSION_MATRIX = {
  SYSTEM_ADMIN: [
    'USER_MANAGE',
    'DEPARTMENT_MANAGE',
    'ROLE_MANAGE',
    'ATTRIBUTE_MANAGE',
    'POLICY_MANAGE',
    'POLICY_SIMULATE',
    'WATERMARK_CONFIG_MANAGE',
    'SYSTEM_HEALTH_VIEW',
    // CONFLICT-RESOLVED: Bổ sung quyền SYSTEM_HEALTH_MANAGE cho SYSTEM_ADMIN để điều hành chụp ảnh sức khỏe và dọn dẹp dữ liệu quá hạn.
    'SYSTEM_HEALTH_MANAGE',
  ],
  SECURITY_OFFICER: [
    'AUDIT_VIEW',
    'ALERT_VIEW',
    'ALERT_MANAGE',
    'WATERMARK_TRACE',
    'POLICY_SIMULATE',
    'INCIDENT_CREATE',
    'INCIDENT_MANAGE',
    'ACCESS_SESSION_TERMINATE',
  ],
  AUDITOR: ['AUDIT_VIEW', 'AUDIT_EXPORT', 'ALERT_VIEW', 'WATERMARK_TRACE', 'SYSTEM_REPORT_EXPORT'],
  DOCUMENT_OWNER: [
    'DOCUMENT_UPLOAD',
    // CONFLICT-RESOLVED: Bổ sung quyền DOCUMENT_MANAGE cho DOCUMENT_OWNER đồng bộ với seed-catalog.ts và chuyển quyền sở hữu tài liệu.
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
} as const;

export const PRIVILEGED_SEPARATION_ROLES = new Set(['SYSTEM_ADMIN', 'SECURITY_OFFICER', 'AUDITOR']);
const BUSINESS_SYSTEM_ROLES = new Set(['DOCUMENT_OWNER', 'DOCUMENT_READER']);
const POLICY_SIMULATION_ROLES = new Set(['SYSTEM_ADMIN', 'SECURITY_OFFICER']);

export type SodArchetype =
  'ADMIN_GOVERNANCE' | 'SECURITY_SOC' | 'AUDITOR_COMPLIANCE' | 'BUSINESS_DOCUMENT';

const ALL_SOD_ARCHETYPES: readonly SodArchetype[] = [
  'ADMIN_GOVERNANCE',
  'SECURITY_SOC',
  'AUDITOR_COMPLIANCE',
  'BUSINESS_DOCUMENT',
];

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
  'NOTIFICATION_VIEW',
]);

export interface PermissionCapabilityLike {
  code: string;
  resource_type?: string | undefined;
  action?: string | undefined;
}

/**
 * Thuật toán: Ánh xạ một quyền nguyên tử (theo cả `code` lẫn cặp `resource_type:action`) về tập trụ cột Phân tách Nhiệm vụ (SoD) được phép chứa quyền đó.
 */
function allowedArchetypesForPermission(
  perm: string | PermissionCapabilityLike,
): readonly SodArchetype[] {
  const code = typeof perm === 'string' ? perm : perm.code;
  const resource = typeof perm === 'string' ? undefined : perm.resource_type;
  const action = typeof perm === 'string' ? undefined : perm.action;

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
      ['DOCUMENT', 'DOCUMENT_VERSION', 'ACCESS_REQUEST', 'ACCESS_GRANT', 'NOTIFICATION'].includes(
        resource,
      ))
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
 * Thuật toán: Giao tập Lưới Phân tách Nhiệm vụ (Lattice Intersection SoD Classifier).
 * Tính tập các trụ cột SoD tương thích đồng thời với mã vai trò và toàn bộ tập quyền bên trong;
 * nếu giao tập rỗng (`size === 0`), vai trò hoặc tổ hợp vai trò vi phạm Phân tách Nhiệm vụ.
 */
export function resolveCompatibleSodArchetypes(
  roles: ReadonlyArray<{
    code?: string | undefined;
    permissions?: Iterable<string | PermissionCapabilityLike> | undefined;
  }>,
): Set<SodArchetype> {
  let compatible = new Set<SodArchetype>(ALL_SOD_ARCHETYPES);

  for (const role of roles) {
    if (role.code === 'SYSTEM_ADMIN') {
      compatible = intersectArchetypes(compatible, ['ADMIN_GOVERNANCE']);
    } else if (role.code === 'SECURITY_OFFICER') {
      compatible = intersectArchetypes(compatible, ['SECURITY_SOC']);
    } else if (role.code === 'AUDITOR') {
      compatible = intersectArchetypes(compatible, ['AUDITOR_COMPLIANCE']);
    } else if (role.code !== undefined && BUSINESS_SYSTEM_ROLES.has(role.code)) {
      compatible = intersectArchetypes(compatible, ['BUSINESS_DOCUMENT']);
    }

    if (role.permissions) {
      for (const perm of role.permissions) {
        compatible = intersectArchetypes(compatible, allowedArchetypesForPermission(perm));
        if (compatible.size === 0) return compatible;
      }
    }
  }
  return compatible;
}

function intersectArchetypes(
  current: Set<SodArchetype>,
  allowed: readonly SodArchetype[],
): Set<SodArchetype> {
  const next = new Set<SodArchetype>();
  for (const item of allowed) {
    if (current.has(item)) next.add(item);
  }
  return next;
}

/**
 * Thuật toán: Kiểm tra xem một vai trò (theo mã hoặc tập quyền thực tế) có mang đặc quyền quản trị/SOC/kiểm toán cấm truy cập nội dung tài liệu hay không.
 */
export function isPrivilegedSeparationRoleOrCapability(
  roleCode: string | undefined,
  permissions?: Iterable<string | PermissionCapabilityLike>,
): boolean {
  if (roleCode !== undefined && PRIVILEGED_SEPARATION_ROLES.has(roleCode)) {
    return true;
  }
  const compatible = resolveCompatibleSodArchetypes([{ code: roleCode, permissions }]);
  return !compatible.has('BUSINESS_DOCUMENT');
}

/**
 * Thuật toán: Kiểm tra tính tương thích Phân tách Nhiệm vụ giữa tập vai trò chồng lấp thời gian của một người dùng.
 */
export function areOverlappingRolesSodCompatible(
  roles: ReadonlyArray<{
    code: string;
    permissions?: Iterable<string | PermissionCapabilityLike> | undefined;
  }>,
): boolean {
  // CONFLICT-RESOLVED: Kết hợp kiểm tra xung đột mã vai trò hệ thống và giao tập quyền bên trong Custom Role để triệt tiêu SoD bypass (HIGH-01).
  const distinctCodes = new Set(roles.map((r) => r.code));
  const hasSystemPrivilegedCode = roles.some((r) => PRIVILEGED_SEPARATION_ROLES.has(r.code));
  if (hasSystemPrivilegedCode && distinctCodes.size > 1) {
    return false;
  }
  return resolveCompatibleSodArchetypes(roles).size > 0;
}

/**
 * Thuật toán: Kiểm tra quyền mô phỏng chính sách qua tập băm `POLICY_SIMULATION_ROLES` trong O(k).
 */
export function canSimulatePolicy(roleCodes: readonly string[]): boolean {
  return roleCodes.some((roleCode) => POLICY_SIMULATION_ROLES.has(roleCode));
}

/**
 * Thuật toán: Kiểm tra tính bao hàm tập con quyền được phép đối với vai trò hệ thống bất biến (Subset Ceiling Check).
 */
export function systemRoleAllows(roleCode: string, permissionCodes: string[]): boolean {
  const allowed =
    SYSTEM_ROLE_PERMISSION_MATRIX[roleCode as keyof typeof SYSTEM_ROLE_PERMISSION_MATRIX];
  return (
    allowed !== undefined &&
    permissionCodes.every((code) => (allowed as readonly string[]).includes(code))
  );
}

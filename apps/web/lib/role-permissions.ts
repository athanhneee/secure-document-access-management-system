/**
 * Thuật toán: Ánh Xạ Ma Trận Quyền RBAC Nghiêm Ngặt & Định Tuyến 5 Phân Hệ Theo Quyền Thực Tế (`role-permissions`)
 * Mục đích:
 *   - Đối chiếu tuyệt đối trên mảng `user.permissions` do máy chủ `/users/me` trả về (kể cả khi `permissions: []` do vai trò bị gỡ sạch quyền) — tuyệt đối KHÔNG suy diễn quyền giả từ `ROLE_DEFAULT_PERMISSIONS`.
 *   - Cho phép vai trò tùy chỉnh (Custom Role như `HR_MANAGER` có `USER:MANAGE`) tự động vào đúng phân hệ tương ứng mà không bị khóa cứng theo 5 mã vai trò hệ thống.
 *   - Giữ nguyên nguyên tắc Least-Privilege cho 5 vai trò hệ thống chuẩn để mỗi vai trò chỉ thấy đúng 1 phân hệ chuyên biệt của mình.
 */

export type SystemRoleType =
  'SYSTEM_ADMIN' | 'DOCUMENT_OWNER' | 'DOCUMENT_READER' | 'SECURITY_OFFICER' | 'AUDITOR';

export interface PermissionPrincipalLike {
  roles: readonly string[];
  permissions?: readonly string[] | null | undefined;
}

export const ROLE_DEFAULT_PERMISSIONS: Record<SystemRoleType, readonly string[]> = {
  SYSTEM_ADMIN: [
    'USER:MANAGE',
    'DEPARTMENT:MANAGE',
    'ROLE:MANAGE',
    'ATTRIBUTE:MANAGE',
    'POLICY:MANAGE',
    'POLICY:SIMULATE',
    'WATERMARK_CONFIG:MANAGE',
    'SYSTEM_HEALTH:VIEW',
    'SYSTEM_HEALTH:MANAGE',
  ],
  SECURITY_OFFICER: [
    'AUDIT_LOG:VIEW',
    'SECURITY_ALERT:VIEW',
    'SECURITY_ALERT:MANAGE',
    'WATERMARK_INSTANCE:TRACE',
    'INCIDENT_REPORT:CREATE',
    'INCIDENT_REPORT:MANAGE',
    'ACCESS_SESSION:TERMINATE',
    'POLICY:SIMULATE',
  ],
  AUDITOR: [
    'AUDIT_LOG:VIEW',
    'AUDIT_LOG:EXPORT',
    'SECURITY_ALERT:VIEW',
    'WATERMARK_INSTANCE:TRACE',
    'SYSTEM_REPORT:EXPORT',
  ],
  DOCUMENT_OWNER: [
    'DOCUMENT:UPLOAD',
    'DOCUMENT:CLASSIFY',
    'DOCUMENT_VERSION:CREATE',
    'DOCUMENT:ARCHIVE',
    'DOCUMENT:MANAGE',
    'DOCUMENT:DISCOVER',
    'DOCUMENT:VIEW',
    'DOCUMENT:DOWNLOAD',
    'ACCESS_REQUEST:DECIDE',
    'ACCESS_REQUEST:VIEW_OWN',
    'ACCESS_GRANT:CREATE',
    'ACCESS_GRANT:REVOKE',
    'ACCESS_GRANT:VIEW',
    'NOTIFICATION:VIEW',
    'AUDIT_LOG:VIEW',
  ],
  DOCUMENT_READER: [
    'DOCUMENT:DISCOVER',
    'DOCUMENT:VIEW',
    'DOCUMENT:DOWNLOAD',
    'ACCESS_REQUEST:CREATE',
    'ACCESS_REQUEST:VIEW_OWN',
    'ACCESS_REQUEST:CANCEL',
    'NOTIFICATION:VIEW',
  ],
};

export const PORTAL_PRIORITY_ORDER: readonly SystemRoleType[] = [
  'SYSTEM_ADMIN',
  'DOCUMENT_OWNER',
  'SECURITY_OFFICER',
  'AUDITOR',
  'DOCUMENT_READER',
];

export const PORTAL_PATHS: Record<SystemRoleType, string> = {
  SYSTEM_ADMIN: '/admin',
  DOCUMENT_OWNER: '/owner',
  DOCUMENT_READER: '/reader',
  SECURITY_OFFICER: '/security',
  AUDITOR: '/auditor',
};

const ADMIN_CORE_PERMISSIONS = [
  'USER:MANAGE',
  'DEPARTMENT:MANAGE',
  'ROLE:MANAGE',
  'ATTRIBUTE:MANAGE',
  'POLICY:MANAGE',
  'WATERMARK_CONFIG:MANAGE',
  'SYSTEM_HEALTH:VIEW',
  'SYSTEM_HEALTH:MANAGE',
] as const;

const OWNER_CORE_PERMISSIONS = [
  'DOCUMENT:UPLOAD',
  'DOCUMENT:MANAGE',
  'DOCUMENT:CLASSIFY',
  'DOCUMENT_VERSION:CREATE',
  'DOCUMENT:ARCHIVE',
  'ACCESS_REQUEST:DECIDE',
  'ACCESS_GRANT:CREATE',
  'ACCESS_GRANT:REVOKE',
  'ACCESS_GRANT:VIEW',
] as const;

const READER_EXCLUSIVE_PERMISSIONS = ['ACCESS_REQUEST:CREATE', 'ACCESS_REQUEST:CANCEL'] as const;

const READER_SHARED_PERMISSIONS = [
  'DOCUMENT:DISCOVER',
  'DOCUMENT:VIEW',
  'DOCUMENT:DOWNLOAD',
  'ACCESS_REQUEST:VIEW_OWN',
] as const;

const SECURITY_CORE_PERMISSIONS = [
  'SECURITY_ALERT:MANAGE',
  'INCIDENT_REPORT:CREATE',
  'INCIDENT_REPORT:MANAGE',
  'ACCESS_SESSION:TERMINATE',
] as const;

const SECURITY_SHARED_PERMISSIONS = ['SECURITY_ALERT:VIEW', 'WATERMARK_INSTANCE:TRACE'] as const;

const AUDITOR_CORE_PERMISSIONS = ['AUDIT_LOG:EXPORT', 'SYSTEM_REPORT:EXPORT'] as const;

function normalizePermissionToken(token: string): string {
  return token.trim().toUpperCase().replaceAll(':', '_');
}

function hasAnyPermission(
  user: PermissionPrincipalLike | null | undefined,
  candidates: readonly string[],
): boolean {
  return candidates.some((perm) => checkEffectivePermission(user, perm));
}

/**
 * Thuật toán: Kiểm Tra Quyền Hiệu Lực Nghiêm Ngặt Không Suy Diễn Quyền Giả (`checkEffectivePermission`)
 * Cơ chế:
 *   - Chuẩn hóa ký hiệu `RESOURCE:ACTION` và `RESOURCE_ACTION` về cùng dạng khóa chữ hoa.
 *   - Luôn đánh giá trực tiếp trên `user.permissions` thực tế do Backend cấp; khi `user.permissions` rỗng (`[]`) trả về `false` (Fail-Closed), triệt tiêu lỗi hiển thị nút ảo khi vai trò bị gỡ sạch quyền.
 */
export function checkEffectivePermission(
  user: PermissionPrincipalLike | null | undefined,
  permission: string,
): boolean {
  if (!user || !Array.isArray(user.permissions)) return false;
  const target = normalizePermissionToken(permission);
  if (!target) return false;
  return user.permissions.some((granted) => normalizePermissionToken(granted) === target);
}

/**
 * Thuật toán: Đánh Giá Quyền Truy Cập Từng Phân Hệ Trong 5 Không Gian Làm Việc Theo Tập Quyền Thực Tế (`canAccessPortal`)
 * Mục đích:
 *   - Cho phép mọi Custom Role (ví dụ `HR_MANAGER` chỉ có `USER:MANAGE` hoặc `DOC_VIEWER` chỉ có `DOCUMENT:VIEW`) truy cập đúng phân hệ phục vụ quyền của mình.
 *   - Loại trừ xung đột quyền dùng chung (`AUDIT_LOG:VIEW`, `DOCUMENT:VIEW`, `SECURITY_ALERT:VIEW`, `POLICY:SIMULATE`) để 5 vai trò hệ thống chuẩn không bị trùng chéo sang phân hệ khác.
 *   - Khi tài khoản bị gỡ sạch quyền (`permissions: []`), trả về `false` cho cả 5 phân hệ.
 */
export function canAccessPortal(
  user: PermissionPrincipalLike | null | undefined,
  portal: SystemRoleType,
): boolean {
  if (!user || !Array.isArray(user.permissions) || user.permissions.length === 0) {
    return false;
  }

  const hasAdminCore = hasAnyPermission(user, ADMIN_CORE_PERMISSIONS);
  const hasOwnerCore = hasAnyPermission(user, OWNER_CORE_PERMISSIONS);
  const hasSecurityCore = hasAnyPermission(user, SECURITY_CORE_PERMISSIONS);
  const hasAuditorCore = hasAnyPermission(user, AUDITOR_CORE_PERMISSIONS);

  switch (portal) {
    case 'SYSTEM_ADMIN':
      if (hasAdminCore) return true;
      return (
        checkEffectivePermission(user, 'POLICY:SIMULATE') &&
        !hasSecurityCore &&
        !user.roles.includes('SECURITY_OFFICER')
      );

    case 'DOCUMENT_OWNER':
      return hasOwnerCore;

    case 'DOCUMENT_READER':
      if (hasAnyPermission(user, READER_EXCLUSIVE_PERMISSIONS)) return true;
      if (!hasAnyPermission(user, READER_SHARED_PERMISSIONS)) return false;
      return !hasOwnerCore || user.roles.includes('DOCUMENT_READER');

    case 'SECURITY_OFFICER':
      if (hasSecurityCore) return true;
      if (!hasAnyPermission(user, SECURITY_SHARED_PERMISSIONS)) return false;
      return (
        (!hasAuditorCore && !user.roles.includes('AUDITOR')) ||
        user.roles.includes('SECURITY_OFFICER')
      );

    case 'AUDITOR':
      if (hasAuditorCore) return true;
      if (!checkEffectivePermission(user, 'AUDIT_LOG:VIEW')) return false;
      return (
        (!hasOwnerCore &&
          !hasSecurityCore &&
          !user.roles.includes('DOCUMENT_OWNER') &&
          !user.roles.includes('SECURITY_OFFICER')) ||
        user.roles.includes('AUDITOR')
      );
  }
}

/**
 * Thuật toán: Liệt Kê Các Phân Hệ Được Cấp Quyền Theo Thứ Tự Ưu Tiên (`getAccessiblePortals`)
 */
export function getAccessiblePortals(
  user: PermissionPrincipalLike | null | undefined,
): SystemRoleType[] {
  return PORTAL_PRIORITY_ORDER.filter((portal) => canAccessPortal(user, portal));
}

/**
 * Thuật toán: Suy Diễn Cổng Làm Việc Mặc Định Từ Quyền Thực Tế Của Tài Khoản (`resolveDefaultPortalForUser`)
 * Mục đích: Đưa tài khoản Custom Role (như `HR_MANAGER`) vào đúng phân hệ được cấp (`/admin`), trả về `'/'` nếu tài khoản không còn quyền vào bất kỳ phân hệ nào.
 */
export function resolveDefaultPortalForUser(
  user: PermissionPrincipalLike | null | undefined,
): string {
  const portals = getAccessiblePortals(user);
  const firstPortal = portals[0];
  return firstPortal ? PORTAL_PATHS[firstPortal] : '/';
}

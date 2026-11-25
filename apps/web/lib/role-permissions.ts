/**
 * Thuật toán: Ánh Xạ Ma Trận Quyền RBAC Chuẩn & Đối Chiếu Thẩm Quyền Hiệu Lực (`ROLE_DEFAULT_PERMISSIONS`, `checkEffectivePermission`)
 * Mục đích:
 *   - Đồng bộ 1-1 tập quyền `${resource}:${action}` của 5 vai trò hệ thống từ `seed-catalog.ts` / `UsersService.currentUser`.
 *   - Khi `/users/me` trả về danh sách `user.permissions` tường minh (môi trường thực tế, bao gồm vai trò tùy biến RBAC), đối chiếu trực tiếp trên `user.permissions`.
 *   - Khi `user.permissions` rỗng (ví dụ giả lập phiên E2E chỉ gán `roles: [role]`), suy diễn tập quyền tối thiểu từ `ROLE_DEFAULT_PERMISSIONS` của các vai trò hệ thống được gán.
 */

export type SystemRoleType =
  'SYSTEM_ADMIN' | 'DOCUMENT_OWNER' | 'DOCUMENT_READER' | 'SECURITY_OFFICER' | 'AUDITOR';

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

function normalizePermissionToken(token: string): string {
  return token.trim().toUpperCase().replaceAll(':', '_');
}

/**
 * Thuật toán: Kiểm Tra Quyền Hiệu Lực Chuẩn Hóa Ký Hiệu (`checkEffectivePermission`)
 * Cơ chế:
 *   - Chuẩn hóa ký hiệu `RESOURCE:ACTION` và `RESOURCE_ACTION` về cùng dạng khóa so khớp bất biến chữ hoa.
 *   - Ưu tiên tuyệt đối mảng `user.permissions` từ máy chủ nếu có phần tử; chỉ tra cứu bảng `ROLE_DEFAULT_PERMISSIONS` khi mảng quyền rỗng.
 */
export function checkEffectivePermission(
  user: { roles: readonly string[]; permissions: readonly string[] } | null | undefined,
  permission: string,
): boolean {
  if (!user) return false;
  const target = normalizePermissionToken(permission);
  if (!target) return false;

  if (user.permissions.length > 0) {
    return user.permissions.some((granted) => normalizePermissionToken(granted) === target);
  }

  for (const role of user.roles) {
    const defaults = ROLE_DEFAULT_PERMISSIONS[role as SystemRoleType];
    if (defaults?.some((granted) => normalizePermissionToken(granted) === target)) {
      return true;
    }
  }
  return false;
}

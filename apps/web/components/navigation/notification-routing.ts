/**
 * @module NotificationRouting
 * Thuật toán: Định Tuyến Thông Báo Nội Bộ Theo Loại Sự Kiện & Quyền Phân Hệ Thực Tế (`resolveNotificationHref`)
 * và Cập Nhật Nguyên Tử Bộ Nhớ Đệm Hộp Thư SSE Chống Tăng Kép Trong React StrictMode (`applyIncomingNotificationToCache`).
 * Mục đích:
 *   - Đảm bảo Chủ sở hữu (`DOCUMENT_OWNER`) khi bấm "Xem chi tiết" thông báo yêu cầu truy cập mới, hủy yêu cầu, hạn lưu trữ hoặc chuyển giao sở hữu sẽ điều hướng thẳng tới `/owner?tab=...` thay vì bị đẩy nhầm sang `/reader` và nhận lỗi `403`.
 *   - Tuyệt đối không tạo đường dẫn tới phân hệ mà người dùng không được cấp quyền (`canAccessOwner` / `canAccessReader`).
 */

export const WORKSPACE_TAB_EVENT = 'sda:workspace-tab';

export interface NotificationPortalCapabilities {
  canAccessOwner: boolean;
  canAccessReader: boolean;
  canAccessSecurity?: boolean | undefined;
  canAccessAuditor?: boolean | undefined;
  hasPermission?: ((permission: string) => boolean) | undefined;
}

export interface RoutableNotificationLike {
  notificationType?: string | null | undefined;
  relatedObjectType?: string | null | undefined;
}

export interface NotificationCacheSnapshot<T extends { id: string; status: string }> {
  items: T[];
  unreadCount: number;
  page: number;
  hasMore: boolean;
}

const OWNER_REQUEST_TYPES = new Set(['ACCESS_REQUEST_CREATED', 'ACCESS_REQUEST_CANCELLED']);
const OWNER_DOCUMENT_TYPES = new Set([
  'RETENTION_EXPIRATION_WARNING',
  'DOCUMENT_OWNERSHIP_TRANSFERRED',
]);
const INCIDENT_NOTIFICATION_TYPES = new Set([
  'INCIDENT_REPORT_SUBMITTED',
  'INCIDENT_REPORT_UPDATED',
  'INCIDENT_REPORT_CLOSED',
  'INCIDENT_REPORT_CREATED',
  'INCIDENT_REPORT_IN_REVIEW',
]);
const SECURITY_ALERT_TYPES = new Set([
  'SECURITY_ALERT_CREATED',
  'SECURITY_ALERT_UPDATED',
  'SECURITY_DIGEST',
]);
const AUDITOR_EXPORT_TYPES = new Set([
  'EXPORT_JOB_COMPLETED',
  'EXPORT_JOB_FAILED',
  'EXPORT_JOB_UPDATED',
  'REPORT_EXPORT_READY',
  'REPORT_EXPORT_COMPLETED',
]);
const READER_REQUEST_TYPES = new Set(['ACCESS_REQUEST_REJECTED', 'ACCESS_REQUEST_APPROVED']);
const READER_GRANT_TYPES = new Set([
  'ACCESS_GRANT_ISSUED',
  'ACCESS_GRANT_REVOKED',
  'ACCESS_GRANTED',
]);

/**
 * Thuật toán: Ánh xạ loại thông báo + đối tượng liên quan sang tuyến đường đích hợp lệ với cả phân hệ lẫn quyền mở từng tab đích.
 */
export function resolveNotificationHref(
  item: RoutableNotificationLike,
  capabilities: NotificationPortalCapabilities,
): string | null {
  const notifType = (item.notificationType ?? '').trim().toUpperCase();
  const objType = (item.relatedObjectType ?? '').trim().toUpperCase();

  const checkPerm = capabilities.hasPermission;
  const hasAnyTabPerm = (candidates: readonly string[]): boolean =>
    checkPerm ? candidates.some((perm) => checkPerm(perm)) : true;

  const canOpenOwnerDocuments =
    capabilities.canAccessOwner &&
    hasAnyTabPerm(['DOCUMENT:DISCOVER', 'DOCUMENT:VIEW', 'DOCUMENT:MANAGE', 'DOCUMENT:UPLOAD']);
  const canOpenOwnerRequests =
    capabilities.canAccessOwner &&
    hasAnyTabPerm(['ACCESS_REQUEST:DECIDE', 'ACCESS_REQUEST:VIEW_OWN']);
  const canOpenOwnerGrants =
    capabilities.canAccessOwner &&
    hasAnyTabPerm(['ACCESS_GRANT:VIEW', 'ACCESS_GRANT:CREATE', 'ACCESS_GRANT:REVOKE']);
  const canOpenOwnerHistory = capabilities.canAccessOwner && hasAnyTabPerm(['AUDIT_LOG:VIEW']);

  const canOpenReaderDocs = capabilities.canAccessReader && hasAnyTabPerm(['DOCUMENT:VIEW']);
  const canOpenReaderRequests =
    capabilities.canAccessReader && hasAnyTabPerm(['ACCESS_REQUEST:VIEW_OWN']);

  const canOpenSecurityAlerts =
    Boolean(capabilities.canAccessSecurity) && hasAnyTabPerm(['SECURITY_ALERT:VIEW']);
  const canOpenSecurityIncidents =
    Boolean(capabilities.canAccessSecurity) &&
    hasAnyTabPerm(['SECURITY_ALERT:VIEW', 'INCIDENT_REPORT:CREATE', 'INCIDENT_REPORT:MANAGE']);
  const canOpenSecuritySessions =
    Boolean(capabilities.canAccessSecurity) && hasAnyTabPerm(['ACCESS_SESSION:TERMINATE']);

  const canOpenAuditorLogs =
    Boolean(capabilities.canAccessAuditor) && hasAnyTabPerm(['AUDIT_LOG:VIEW']);
  const canOpenAuditorExports =
    Boolean(capabilities.canAccessAuditor) &&
    hasAnyTabPerm(['AUDIT_LOG:EXPORT', 'SYSTEM_REPORT:EXPORT']);

  if (OWNER_REQUEST_TYPES.has(notifType)) {
    return canOpenOwnerRequests ? '/owner?tab=requests' : null;
  }
  if (OWNER_DOCUMENT_TYPES.has(notifType)) {
    return canOpenOwnerDocuments ? '/owner?tab=documents' : null;
  }
  if (INCIDENT_NOTIFICATION_TYPES.has(notifType)) {
    if (canOpenSecurityIncidents) return '/security?tab=incidents';
    return canOpenOwnerHistory ? '/owner?tab=history' : null;
  }
  if (SECURITY_ALERT_TYPES.has(notifType)) {
    return canOpenSecurityAlerts ? '/security?tab=alerts' : null;
  }
  if (AUDITOR_EXPORT_TYPES.has(notifType)) {
    return canOpenAuditorExports ? '/auditor?tab=exports' : null;
  }
  if (READER_REQUEST_TYPES.has(notifType)) {
    return canOpenReaderRequests ? '/reader?tab=my-requests' : null;
  }
  if (READER_GRANT_TYPES.has(notifType)) {
    return canOpenReaderDocs ? '/reader?tab=my-docs' : null;
  }

  if (objType === 'ACCESS_REQUEST') {
    if (capabilities.canAccessOwner && !capabilities.canAccessReader) {
      return canOpenOwnerRequests ? '/owner?tab=requests' : null;
    }
    if (canOpenReaderRequests) return '/reader?tab=my-requests';
    return canOpenOwnerRequests ? '/owner?tab=requests' : null;
  }
  if (objType === 'DOCUMENT') {
    if (capabilities.canAccessOwner && !capabilities.canAccessReader) {
      return canOpenOwnerDocuments ? '/owner?tab=documents' : null;
    }
    if (canOpenReaderDocs) return '/reader?tab=my-docs';
    return canOpenOwnerDocuments ? '/owner?tab=documents' : null;
  }
  if (objType === 'ACCESS_GRANT') {
    if (canOpenReaderDocs) return '/reader?tab=my-docs';
    return canOpenOwnerGrants ? '/owner?tab=grants' : null;
  }
  if (objType === 'ACCESS_SESSION') {
    if (canOpenSecuritySessions) return '/security?tab=sessions';
    if (canOpenReaderDocs) return '/reader?tab=my-docs';
    return canOpenOwnerHistory ? '/owner?tab=history' : null;
  }
  if (objType === 'INCIDENT_REPORT') {
    if (canOpenSecurityIncidents) return '/security?tab=incidents';
    return canOpenOwnerHistory ? '/owner?tab=history' : null;
  }
  if (objType === 'SECURITY_ALERT') {
    return canOpenSecurityAlerts ? '/security?tab=alerts' : null;
  }
  if (objType === 'ASYNC_EXPORT_JOB' || objType === 'EXPORT_JOB') {
    return canOpenAuditorExports ? '/auditor?tab=exports' : null;
  }
  if (objType === 'AUDIT_LOG') {
    if (canOpenAuditorLogs) return '/auditor?tab=logs';
    return canOpenOwnerHistory ? '/owner?tab=history' : null;
  }
  return null;
}

/**
 * Thuật toán: Tách cặp `{ path, tab }` từ URL dạng `/owner?tab=requests` phục vụ chuyển tab tức thì trên cùng trang.
 */
export function parseWorkspaceTabTarget(href: string): { path: string; tab: string } | null {
  const qIndex = href.indexOf('?');
  if (qIndex < 0) return null;
  const path = href.slice(0, qIndex);
  const params = new URLSearchParams(href.slice(qIndex + 1));
  const tab = params.get('tab');
  if (!path || !tab) return null;
  return { path, tab };
}

/**
 * Thuật toán: Chèn thông báo SSE mới vào đầu danh sách, khử trùng theo `id` và tính `unreadCount` trong một phép biến đổi thuần duy nhất.
 */
export function applyIncomingNotificationToCache<T extends { id: string; status: string }>(
  prev: NotificationCacheSnapshot<T>,
  incoming: T,
): NotificationCacheSnapshot<T> {
  const existed = prev.items.some((entry) => entry.id === incoming.id);
  const nextItems = [incoming, ...prev.items.filter((entry) => entry.id !== incoming.id)];
  const nextUnread =
    !existed && incoming.status === 'UNREAD' ? prev.unreadCount + 1 : prev.unreadCount;
  return {
    ...prev,
    items: nextItems,
    unreadCount: nextUnread,
  };
}

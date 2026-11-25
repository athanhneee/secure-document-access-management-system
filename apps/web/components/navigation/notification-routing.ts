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
const OWNER_HISTORY_TYPES = new Set(['INCIDENT_REPORT_SUBMITTED']);
const READER_REQUEST_TYPES = new Set(['ACCESS_REQUEST_REJECTED', 'ACCESS_REQUEST_APPROVED']);
const READER_GRANT_TYPES = new Set([
  'ACCESS_GRANT_ISSUED',
  'ACCESS_GRANT_REVOKED',
  'ACCESS_GRANTED',
]);

/**
 * Thuật toán: Ánh xạ loại thông báo + đối tượng liên quan sang tuyến đường đích hợp lệ với phân hệ người dùng được phép truy cập.
 */
export function resolveNotificationHref(
  item: RoutableNotificationLike,
  capabilities: NotificationPortalCapabilities,
): string | null {
  const notifType = (item.notificationType ?? '').trim().toUpperCase();
  const objType = (item.relatedObjectType ?? '').trim().toUpperCase();

  if (OWNER_REQUEST_TYPES.has(notifType)) {
    return capabilities.canAccessOwner ? '/owner?tab=requests' : null;
  }
  if (OWNER_DOCUMENT_TYPES.has(notifType)) {
    return capabilities.canAccessOwner ? '/owner?tab=documents' : null;
  }
  if (OWNER_HISTORY_TYPES.has(notifType)) {
    return capabilities.canAccessOwner ? '/owner?tab=history' : null;
  }
  if (READER_REQUEST_TYPES.has(notifType)) {
    return capabilities.canAccessReader ? '/reader?tab=my-requests' : null;
  }
  if (READER_GRANT_TYPES.has(notifType)) {
    return capabilities.canAccessReader ? '/reader?tab=my-docs' : null;
  }

  if (objType === 'ACCESS_REQUEST') {
    if (capabilities.canAccessOwner && !capabilities.canAccessReader) {
      return '/owner?tab=requests';
    }
    return capabilities.canAccessReader ? '/reader?tab=my-requests' : null;
  }
  if (objType === 'DOCUMENT') {
    if (capabilities.canAccessOwner && !capabilities.canAccessReader) {
      return '/owner?tab=documents';
    }
    return capabilities.canAccessReader ? '/reader?tab=my-docs' : null;
  }
  if (objType === 'ACCESS_GRANT') {
    if (capabilities.canAccessReader) return '/reader?tab=my-docs';
    return capabilities.canAccessOwner ? '/owner?tab=grants' : null;
  }
  if (objType === 'ACCESS_SESSION') {
    if (capabilities.canAccessReader) return '/reader?tab=my-docs';
    return capabilities.canAccessOwner ? '/owner?tab=history' : null;
  }
  if (objType === 'INCIDENT_REPORT') {
    return capabilities.canAccessOwner ? '/owner?tab=history' : null;
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

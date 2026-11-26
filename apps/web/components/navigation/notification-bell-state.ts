/**
 * Thuật toán: Biến Đổi Thuần Hộp Thư Thông Báo & Hoàn Tác Theo Mục Đích Danh (`notification-bell-state`)
 * Mục đích:
 *   - Thay thế hoàn tác ảnh chụp cứng (`prevSnapshot`) bằng các hàm cập nhật thuần (`pure functional updater`) chỉ khôi phục đúng `targetId` hoặc tập `changedIds` bị lỗi.
 *   - Đảm bảo các thao tác đọc song song, phân trang "Tải thêm" và thông báo thời gian thực SSE đến trong lúc chờ mạng không bao giờ bị ghi đè mất.
 *   - Tách riêng việc đồng bộ `sessionStorage` + bộ đệm RAM sang `useEffect` nằm ngoài hàm cập nhật trạng thái thuần của React.
 */
export interface InAppNotificationItem {
  id: string;
  notificationType: string;
  title: string;
  body: string;
  relatedObjectType: string | null;
  relatedObjectId: string | null;
  status: string;
  createdAt: string;
  readAt: string | null;
}

export interface NotificationListResponse {
  data?: InAppNotificationItem[];
  unreadCount?: number;
  hasMore?: boolean;
  page?: number;
}

export interface NotificationCacheEntry {
  items: InAppNotificationItem[];
  unreadCount: number;
  page: number;
  hasMore: boolean;
}

export const NOTIFICATION_PAGE_SIZE = 15;
const SESSION_STORAGE_PREFIX = 'sda:notifications:';
const notificationMemoryCache = new Map<string, NotificationCacheEntry>();

export function readCachedNotificationInbox(userId: string): NotificationCacheEntry | null {
  const inMemory = notificationMemoryCache.get(userId);
  if (inMemory) return inMemory;
  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      const raw = window.sessionStorage.getItem(`${SESSION_STORAGE_PREFIX}${userId}`);
      if (raw) {
        const parsed = JSON.parse(raw) as Partial<NotificationCacheEntry>;
        if (Array.isArray(parsed.items) && typeof parsed.unreadCount === 'number') {
          const restored: NotificationCacheEntry = {
            items: parsed.items,
            unreadCount: Math.max(0, parsed.unreadCount),
            page: typeof parsed.page === 'number' && parsed.page > 0 ? parsed.page : 1,
            hasMore: Boolean(parsed.hasMore),
          };
          notificationMemoryCache.set(userId, restored);
          return restored;
        }
      }
    }
  } catch {
    // Bỏ qua nếu sessionStorage bị vô hiệu hóa hoặc dữ liệu cũ không hợp lệ
  }
  return null;
}

export function writeCachedNotificationInbox(userId: string, entry: NotificationCacheEntry): void {
  notificationMemoryCache.set(userId, entry);
  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      window.sessionStorage.setItem(`${SESSION_STORAGE_PREFIX}${userId}`, JSON.stringify(entry));
    }
  } catch {
    // Bỏ qua lỗi hạn ngạch lưu trữ trình duyệt
  }
}

export function hasCachedNotificationInbox(userId: string): boolean {
  return readCachedNotificationInbox(userId) !== null;
}

/**
 * Thuật toán: Xóa Toàn Bộ Bộ Nhớ Đệm Thông Báo RAM & `sessionStorage` Khi Đăng Xuất / Hết Phiên (`clearNotificationCaches`).
 */
export function clearNotificationCaches(): void {
  notificationMemoryCache.clear();
  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      const keysToRemove: string[] = [];
      for (let i = 0; i < window.sessionStorage.length; i += 1) {
        const key = window.sessionStorage.key(i);
        if (key && key.startsWith(SESSION_STORAGE_PREFIX)) {
          keysToRemove.push(key);
        }
      }
      for (const key of keysToRemove) {
        window.sessionStorage.removeItem(key);
      }
    }
  } catch {
    // Bỏ qua khi chạy ngoài môi trường trình duyệt
  }
}

export function parseNotificationResponse(
  res: NotificationListResponse | InAppNotificationItem[],
): {
  list: InAppNotificationItem[];
  unreadCount: number;
  hasMore: boolean;
} {
  const list = Array.isArray(res) ? res : Array.isArray(res?.data) ? res.data : [];
  const fallbackUnread = list.reduce((acc, item) => acc + (item.status === 'UNREAD' ? 1 : 0), 0);
  const unreadCount =
    !Array.isArray(res) && typeof res?.unreadCount === 'number' ? res.unreadCount : fallbackUnread;
  const hasMore =
    !Array.isArray(res) && typeof res?.hasMore === 'boolean'
      ? res.hasMore
      : list.length >= NOTIFICATION_PAGE_SIZE;
  return { list, unreadCount, hasMore };
}

/**
 * Thuật toán: Cập nhật lạc quan thuần túy cho một mục `targetId` sang trạng thái `READ`.
 */
export function applyOptimisticMarkRead(
  prev: NotificationCacheEntry,
  targetId: string,
  readAtIso: string,
): NotificationCacheEntry {
  const existing = prev.items.find((entry) => entry.id === targetId);
  if (existing && existing.status !== 'UNREAD') {
    return prev;
  }
  return {
    ...prev,
    items: prev.items.map((entry) =>
      entry.id === targetId ? { ...entry, status: 'READ', readAt: readAtIso } : entry,
    ),
    unreadCount: Math.max(0, prev.unreadCount - 1),
  };
}

/**
 * Thuật toán: Hoàn tác thuần túy chỉ riêng mục `targetId` khi API đánh dấu đã đọc thất bại, bảo toàn SSE & phân trang.
 */
export function rollbackOptimisticMarkRead(
  prev: NotificationCacheEntry,
  targetId: string,
  previousReadAt: string | null,
): NotificationCacheEntry {
  const existing = prev.items.find((entry) => entry.id === targetId);
  if (existing && existing.status === 'UNREAD') {
    return prev;
  }
  return {
    ...prev,
    items: prev.items.map((entry) =>
      entry.id === targetId ? { ...entry, status: 'UNREAD', readAt: previousReadAt } : entry,
    ),
    unreadCount: prev.unreadCount + 1,
  };
}

/**
 * Thuật toán: Cập nhật lạc quan thuần túy cho tập `changedIds` khi bấm "Đọc tất cả", giữ nguyên thông báo SSE mới đến sau thời điểm bấm.
 */
export function applyOptimisticMarkAllRead(
  prev: NotificationCacheEntry,
  changedIds: ReadonlySet<string>,
  readAtIso: string,
): NotificationCacheEntry {
  const nextItems = prev.items.map((entry) =>
    changedIds.has(entry.id) && entry.status === 'UNREAD'
      ? { ...entry, status: 'READ', readAt: readAtIso }
      : entry,
  );
  const remainingUnreadInLoaded = nextItems.reduce(
    (acc, entry) => acc + (entry.status === 'UNREAD' ? 1 : 0),
    0,
  );
  return {
    ...prev,
    items: nextItems,
    unreadCount: remainingUnreadInLoaded,
  };
}

/**
 * Thuật toán: Hoàn tác thuần túy chỉ cho tập `changedIds` khi `PATCH /notifications/read-all` thất bại.
 */
export function rollbackOptimisticMarkAllRead(
  prev: NotificationCacheEntry,
  changedIds: ReadonlySet<string>,
  previousReadAtById: ReadonlyMap<string, string | null>,
  unloadedUnreadDelta: number,
): NotificationCacheEntry {
  let restoredLoadedCount = 0;
  const nextItems = prev.items.map((entry) => {
    if (changedIds.has(entry.id) && entry.status === 'READ') {
      restoredLoadedCount += 1;
      return {
        ...entry,
        status: 'UNREAD',
        readAt: previousReadAtById.get(entry.id) ?? null,
      };
    }
    return entry;
  });
  return {
    ...prev,
    items: nextItems,
    unreadCount: prev.unreadCount + restoredLoadedCount + Math.max(0, unloadedUnreadDelta),
  };
}

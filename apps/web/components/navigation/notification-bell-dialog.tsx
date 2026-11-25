'use client';

/**
 * Thuật toán: Hộp Thư Chuông Thông Báo Nội Bộ `<dialog>.showModal()` Có Phân Trang, Đọc Tất Cả, Điều Hướng Ngữ Cảnh & Xóa Bộ Nhớ Đệm Khi Đăng Xuất (`NotificationBellDialog`)
 * Mục đích:
 *   - Hiển thị chuông `Bell` kèm `aria-label` nêu rõ số lượng chưa đọc thực từ CSDL (`unreadCount`, `V-37`, `V-65`).
 *   - Hỗ trợ tải thêm trang (`hasMore`), đánh dấu đã đọc độc lập từng mục (`markingIds: Set<string>`), đánh dấu tất cả đã đọc (`PATCH /notifications/read-all`), điều hướng tới tài liệu/yêu cầu liên quan (`V-28`, `V-53`) và xóa bộ đệm RAM khi đăng xuất (`V-11`).
 */
import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AlertCircle, ArrowUpRight, Bell, Check, CheckCheck, RefreshCw } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { useAuth, type RoleType } from '@/lib/auth-context';
import { subscribeRealtimeEvent } from '@/lib/realtime-events';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  applyIncomingNotificationToCache,
  resolveNotificationHref as resolveNotificationHrefByCapabilities,
  WORKSPACE_TAB_EVENT,
} from './notification-routing';

export { WORKSPACE_TAB_EVENT };

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

interface NotificationListResponse {
  data?: InAppNotificationItem[];
  unreadCount?: number;
  hasMore?: boolean;
  page?: number;
}

interface NotificationCacheEntry {
  items: InAppNotificationItem[];
  unreadCount: number;
  page: number;
  hasMore: boolean;
}

const PAGE_SIZE = 15;
const notificationMemoryCache = new Map<string, NotificationCacheEntry>();

/**
 * Thuật toán: Xóa Toàn Bộ Bộ Nhớ Đệm Thông Báo Khi Đăng Xuất / Hết Phiên (`clearNotificationMemoryCache`, V-11).
 * Mục đích: Đảm bảo phiên đăng nhập kế tiếp trên cùng trình duyệt không bao giờ đọc nhầm thông báo của tài khoản trước.
 */
export function clearNotificationMemoryCache(): void {
  notificationMemoryCache.clear();
}

function formatNotificationTime(iso: string): string {
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime()) ? '—' : parsed.toLocaleString('vi-VN');
}

/**
 * Thuật toán: Ánh Xạ Đường Dẫn Chi Tiết Thông Báo Theo Loại Sự Kiện & Phân Hệ Được Cấp Quyền (`resolveNotificationHref`)
 * Mục đích: Ưu tiên đúng ngữ cảnh `notificationType` (phân biệt sự kiện dành cho Chủ sở hữu và Người đọc ngay cả khi tài khoản có cả 2 phân hệ) và chỉ trả về liên kết tới phân hệ người dùng có quyền truy cập.
 */
export function resolveNotificationHref(
  item: Pick<InAppNotificationItem, 'relatedObjectType'> & { notificationType?: string | null },
  canAccessPortal: (portal: RoleType) => boolean,
): string | null {
  return resolveNotificationHrefByCapabilities(item, {
    canAccessOwner: canAccessPortal('DOCUMENT_OWNER'),
    canAccessReader: canAccessPortal('DOCUMENT_READER'),
  });
}

function parseNotificationResponse(res: NotificationListResponse | InAppNotificationItem[]): {
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
      : list.length >= PAGE_SIZE;
  return { list, unreadCount, hasMore };
}

export function NotificationBellDialog({
  userId,
  canViewNotifications = true,
}: {
  userId: string;
  canViewNotifications?: boolean;
}) {
  if (!canViewNotifications) return null;
  return <NotificationBellDialogInner key={userId} userId={userId} />;
}

function NotificationBellDialogInner({ userId }: { userId: string }) {
  const router = useRouter();
  const { canAccessPortal } = useAuth();
  const cached = notificationMemoryCache.get(userId);
  const [open, setOpen] = useState(false);
  const [inbox, setInbox] = useState<NotificationCacheEntry>(
    () =>
      cached ?? {
        items: [],
        unreadCount: 0,
        page: 1,
        hasMore: false,
      },
  );
  const { items, unreadCount, page, hasMore } = inbox;
  const [isLoading, setIsLoading] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [isMarkingAll, setIsMarkingAll] = useState(false);
  const [markingIds, setMarkingIds] = useState<Set<string>>(() => new Set());
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const persistCache = useCallback(
    (entry: NotificationCacheEntry) => {
      notificationMemoryCache.set(userId, entry);
    },
    [userId],
  );

  const fetchNotifications = useCallback(
    async (options?: { silent?: boolean; targetPage?: number; append?: boolean }) => {
      const silent = options?.silent ?? false;
      const targetPage = options?.targetPage ?? 1;
      const append = options?.append ?? false;
      if (append) {
        setIsLoadingMore(true);
      } else if (!silent) {
        setIsLoading(true);
      }
      setErrorMessage(null);
      try {
        const res = await apiClient<NotificationListResponse | InAppNotificationItem[]>(
          `/notifications?page=${targetPage}&pageSize=${PAGE_SIZE}`,
        );
        const parsed = parseNotificationResponse(res);
        setInbox((prev) => {
          const nextItems = append
            ? [
                ...prev.items,
                ...parsed.list.filter((incoming) => !prev.items.some((p) => p.id === incoming.id)),
              ]
            : parsed.list;
          const nextEntry: NotificationCacheEntry = {
            items: nextItems,
            unreadCount: parsed.unreadCount,
            page: targetPage,
            hasMore: parsed.hasMore,
          };
          persistCache(nextEntry);
          return nextEntry;
        });
      } catch (err) {
        if (!silent) {
          setErrorMessage(
            err instanceof ApiError ? err.message : 'Không thể tải danh sách thông báo nội bộ.',
          );
        }
      } finally {
        if (append) {
          setIsLoadingMore(false);
        } else if (!silent) {
          setIsLoading(false);
        }
      }
    },
    [persistCache],
  );

  useEffect(() => {
    if (notificationMemoryCache.has(userId)) return;
    let cancelled = false;
    apiClient<NotificationListResponse | InAppNotificationItem[]>(
      `/notifications?page=1&pageSize=${PAGE_SIZE}`,
    )
      .then((res) => {
        if (cancelled) return;
        const parsed = parseNotificationResponse(res);
        const entry: NotificationCacheEntry = {
          items: parsed.list,
          unreadCount: parsed.unreadCount,
          page: 1,
          hasMore: parsed.hasMore,
        };
        persistCache(entry);
        setInbox(entry);
      })
      .catch(() => {
        /* Tải nền im lặng: không bật banner lỗi trên chuông header */
      });
    return () => {
      cancelled = true;
    };
  }, [userId, persistCache]);

  useEffect(() => {
    return subscribeRealtimeEvent<Partial<InAppNotificationItem> & { id?: string }>(
      'NOTIFICATION_CREATED',
      (event) => {
        const p = event.payload;
        if (p?.id && p.title && p.body) {
          const incoming: InAppNotificationItem = {
            id: String(p.id),
            notificationType: p.notificationType ?? 'SYSTEM',
            title: p.title,
            body: p.body,
            relatedObjectType: p.relatedObjectType ?? null,
            relatedObjectId: p.relatedObjectId ?? null,
            status: p.status ?? 'UNREAD',
            createdAt: p.createdAt ?? event.timestamp,
            readAt: p.readAt ?? null,
          };
          setInbox((prev) => {
            const next = applyIncomingNotificationToCache(prev, incoming);
            persistCache(next);
            return next;
          });
          return;
        }
        void fetchNotifications({ silent: true, targetPage: 1, append: false });
      },
    );
  }, [fetchNotifications, persistCache]);

  async function handleMarkAsRead(target: InAppNotificationItem) {
    if (target.status !== 'UNREAD' || markingIds.has(target.id)) return;
    const prevSnapshot = inbox;
    const nextSnapshot: NotificationCacheEntry = {
      ...inbox,
      items: inbox.items.map((entry) =>
        entry.id === target.id
          ? { ...entry, status: 'READ', readAt: new Date().toISOString() }
          : entry,
      ),
      unreadCount: Math.max(0, inbox.unreadCount - 1),
    };

    setMarkingIds((prev) => new Set(prev).add(target.id));
    setErrorMessage(null);
    setInbox(nextSnapshot);
    persistCache(nextSnapshot);
    try {
      await apiClient(`/notifications/${encodeURIComponent(target.id)}/read`, { method: 'PATCH' });
    } catch (err) {
      setInbox(prevSnapshot);
      persistCache(prevSnapshot);
      setErrorMessage(
        err instanceof ApiError ? err.message : 'Không thể cập nhật trạng thái thông báo.',
      );
    } finally {
      setMarkingIds((prev) => {
        const next = new Set(prev);
        next.delete(target.id);
        return next;
      });
    }
  }

  async function handleMarkAllRead() {
    if (unreadCount === 0 || isMarkingAll) return;
    const prevSnapshot = inbox;
    const nowIso = new Date().toISOString();
    const nextSnapshot: NotificationCacheEntry = {
      ...inbox,
      items: inbox.items.map((entry) =>
        entry.status === 'UNREAD' ? { ...entry, status: 'READ', readAt: nowIso } : entry,
      ),
      unreadCount: 0,
    };

    setIsMarkingAll(true);
    setErrorMessage(null);
    setInbox(nextSnapshot);
    persistCache(nextSnapshot);
    try {
      await apiClient('/notifications/read-all', { method: 'PATCH' });
    } catch (err) {
      setInbox(prevSnapshot);
      persistCache(prevSnapshot);
      setErrorMessage(
        err instanceof ApiError ? err.message : 'Không thể đánh dấu tất cả thông báo đã đọc.',
      );
    } finally {
      setIsMarkingAll(false);
    }
  }

  function handleNavigateNotification(item: InAppNotificationItem, href: string) {
    if (item.status === 'UNREAD') {
      void handleMarkAsRead(item);
    }
    setOpen(false);
    if (typeof window !== 'undefined') {
      const parsed = new URL(href, window.location.origin);
      const tab = parsed.searchParams.get('tab');
      if (tab) {
        window.dispatchEvent(
          new CustomEvent(WORKSPACE_TAB_EVENT, { detail: { path: parsed.pathname, tab } }),
        );
      }
    }
    router.push(href);
  }

  const bellAriaLabel =
    unreadCount > 0 ? `Thông báo hệ thống (${unreadCount} chưa đọc)` : 'Thông báo hệ thống';

  return (
    <>
      <button
        type="button"
        onClick={() => {
          setOpen(true);
          void fetchNotifications({ silent: items.length > 0, targetPage: 1, append: false });
        }}
        aria-label={bellAriaLabel}
        title={bellAriaLabel}
        className="relative flex h-11 w-11 sm:h-9 sm:w-9 shrink-0 items-center justify-center rounded-full border border-[#ebebeb] bg-[#ffffff] text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors cursor-pointer shadow-2xs"
      >
        <Bell size={20} strokeWidth={1.75} aria-hidden="true" />
        {unreadCount > 0 && (
          <span
            className="absolute right-2.5 top-2.5 sm:right-1.5 sm:top-1.5 h-2 w-2 rounded-full bg-[#FF385C] ring-2 ring-[#ffffff]"
            aria-hidden="true"
          />
        )}
      </button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg border-[#ebebeb] bg-[#ffffff] text-[#222222] p-4 sm:p-6">
          <DialogHeader className="mb-3">
            <div className="flex flex-wrap items-center gap-2.5">
              <DialogTitle className="text-base font-bold text-[#222222]">
                Thông báo hệ thống
              </DialogTitle>
              <span
                className={`staff-badge bg-transparent border-0 p-0 inline-flex items-center gap-1.5 text-xs font-semibold ${unreadCount > 0 ? 'text-[#E31C5F]' : 'text-[#008A05]'}`}
              >
                <span
                  className={`dot ${unreadCount > 0 ? 'dot-primary' : 'dot-success'}`}
                  aria-hidden="true"
                />
                <span>{unreadCount > 0 ? `${unreadCount} chưa đọc` : 'Đã đọc hết'}</span>
              </span>
            </div>
            <DialogDescription className="text-xs text-[#717171]">
              Cập nhật yêu cầu truy cập mới, trạng thái cấp quyền, từ chối, thu hồi quyền truy cập
              và thông báo vận hành nội bộ.
            </DialogDescription>
          </DialogHeader>

          {errorMessage && (
            <Alert variant="destructive" className="mb-3">
              <AlertCircle size={16} strokeWidth={1.75} aria-hidden="true" />
              <AlertDescription>{errorMessage}</AlertDescription>
            </Alert>
          )}

          <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-[#ebebeb]">
            <span className="text-xs text-[#717171]">
              Đang hiển thị {items.length} mục{hasMore ? '+' : ''}
            </span>
            <div className="flex flex-wrap items-center gap-1.5">
              {unreadCount > 0 && (
                <InteractiveHoverButton
                  type="button"
                  variant="secondary"
                  size="sm"
                  isLoading={isMarkingAll}
                  disabled={isMarkingAll}
                  icon={<CheckCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
                  text="Đọc tất cả"
                  onClick={() => void handleMarkAllRead()}
                />
              )}
              <InteractiveHoverButton
                type="button"
                variant="secondary"
                size="sm"
                isLoading={isLoading}
                disabled={isLoading}
                icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
                text="Làm mới"
                onClick={() =>
                  void fetchNotifications({ silent: false, targetPage: 1, append: false })
                }
              />
            </div>
          </div>

          <div className="mt-3 max-h-[56dvh] space-y-2.5 overflow-y-auto pr-1">
            {isLoading && items.length === 0 ? (
              <div className="py-8 text-center text-xs text-[#717171]">
                Đang tải hộp thư thông báo…
              </div>
            ) : items.length === 0 ? (
              <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-5 text-center text-xs text-[#717171]">
                Hiện chưa có thông báo nào trong hộp thư của bạn.
              </div>
            ) : (
              <>
                {items.map((item) => {
                  const isUnread = item.status === 'UNREAD';
                  const isMarkingThis = markingIds.has(item.id);
                  const targetHref = resolveNotificationHref(item, canAccessPortal);
                  return (
                    <article
                      key={item.id}
                      className={`rounded-[20px] border p-3.5 text-xs ${isUnread ? 'border-[#FF385C]/30 bg-[#ffffff] shadow-2xs' : 'border-[#ebebeb] bg-[#f7f7f7]'}`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-1.5 min-w-0">
                          <span
                            className={`dot ${isUnread ? 'dot-primary' : 'dot-neutral'}`}
                            aria-hidden="true"
                          />
                          <h3 className="font-bold text-[#222222] break-words">{item.title}</h3>
                        </div>
                        {isUnread ? (
                          <button
                            type="button"
                            disabled={isMarkingThis}
                            onClick={() => void handleMarkAsRead(item)}
                            aria-label={`Đánh dấu đã đọc: ${item.title}`}
                            className="shrink-0 min-h-11 sm:min-h-8 inline-flex items-center gap-1 rounded-full border border-[#dddddd] bg-[#ffffff] hover:bg-[#f7f7f7] px-3 py-1 text-xs font-semibold text-[#222222] cursor-pointer disabled:opacity-50"
                          >
                            <Check
                              size={16}
                              strokeWidth={2}
                              className="text-[#008A05]"
                              aria-hidden="true"
                            />
                            <span>Đánh dấu đã đọc</span>
                          </button>
                        ) : (
                          <span className="staff-badge bg-transparent border-0 p-0 shrink-0 inline-flex items-center gap-1 text-xs font-semibold text-[#717171]">
                            <Check
                              size={16}
                              strokeWidth={2}
                              className="text-[#008A05]"
                              aria-hidden="true"
                            />
                            <span>Đã đọc</span>
                          </span>
                        )}
                      </div>
                      <p className="mt-1.5 text-xs text-[#717171] leading-relaxed break-words">
                        {item.body}
                      </p>
                      <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs text-[#717171]">
                        <span>{formatNotificationTime(item.createdAt)}</span>
                        {targetHref && (
                          <button
                            type="button"
                            onClick={() => handleNavigateNotification(item, targetHref)}
                            className="inline-flex min-h-11 sm:min-h-7 items-center gap-1 rounded-full px-2.5 text-xs font-semibold text-[#E31C5F] hover:bg-[#f7f7f7] cursor-pointer"
                          >
                            <span>Xem chi tiết</span>
                            <ArrowUpRight size={16} strokeWidth={1.75} aria-hidden="true" />
                          </button>
                        )}
                      </div>
                    </article>
                  );
                })}

                {hasMore && (
                  <div className="pt-1 text-center">
                    <InteractiveHoverButton
                      type="button"
                      variant="secondary"
                      size="sm"
                      isLoading={isLoadingMore}
                      disabled={isLoadingMore}
                      text="Tải thêm thông báo"
                      onClick={() =>
                        void fetchNotifications({
                          silent: false,
                          targetPage: page + 1,
                          append: true,
                        })
                      }
                      className="w-full sm:w-auto"
                    />
                  </div>
                )}
              </>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

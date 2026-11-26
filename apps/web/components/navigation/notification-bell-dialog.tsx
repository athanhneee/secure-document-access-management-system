'use client';

/**
 * Thuật toán: Hộp Thư Chuông Thông Báo Nội Bộ `<dialog>.showModal()` Có Phân Trang, Đọc Tất Cả, Hoàn Tác Thuần & Xóa Bộ Đệm Khi Đăng Xuất (`NotificationBellDialog`)
 * Mục đích:
 *   - Hiển thị chuông `Bell` kèm `aria-label` nêu rõ số lượng chưa đọc thực từ CSDL (`unreadCount`).
 *   - Sử dụng hàm cập nhật thuần (`pure functional updater`) khôi phục đúng `item.id` hoặc tập `changedIds` khi lỗi mạng, bảo toàn tuyệt đối các thao tác đọc song song, trang "Tải thêm" và thông báo SSE mới đến.
 *   - Đồng bộ bộ đệm RAM và `sessionStorage` trong `useEffect` bên ngoài hàm cập nhật trạng thái thuần.
 */
import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AlertCircle, ArrowUpRight, Bell, Check, CheckCheck, RefreshCw } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { useAuth, type RoleType } from '@/lib/auth-context';
import { subscribeRealtimeEvent } from '@/lib/realtime-events';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  applyOptimisticMarkAllRead,
  applyOptimisticMarkRead,
  clearNotificationCaches,
  hasCachedNotificationInbox,
  NOTIFICATION_PAGE_SIZE,
  parseNotificationResponse,
  readCachedNotificationInbox,
  rollbackOptimisticMarkAllRead,
  rollbackOptimisticMarkRead,
  writeCachedNotificationInbox,
  type InAppNotificationItem,
  type NotificationCacheEntry,
  type NotificationListResponse,
} from './notification-bell-state';
import {
  applyIncomingNotificationToCache,
  resolveNotificationHref as resolveNotificationHrefByCapabilities,
  WORKSPACE_TAB_EVENT,
} from './notification-routing';

export { WORKSPACE_TAB_EVENT, type InAppNotificationItem };

export function clearNotificationMemoryCache(): void {
  clearNotificationCaches();
}

function formatNotificationTime(iso: string): string {
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime()) ? '—' : parsed.toLocaleString('vi-VN');
}

export function resolveNotificationHref(
  item: Pick<InAppNotificationItem, 'relatedObjectType'> & { notificationType?: string | null },
  canAccessPortal: (portal: RoleType) => boolean,
  hasPermission?: (permission: string) => boolean,
): string | null {
  return resolveNotificationHrefByCapabilities(item, {
    canAccessOwner: canAccessPortal('DOCUMENT_OWNER'),
    canAccessReader: canAccessPortal('DOCUMENT_READER'),
    canAccessSecurity: canAccessPortal('SECURITY_OFFICER'),
    canAccessAuditor: canAccessPortal('AUDITOR'),
    hasPermission,
  });
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
  const { canAccessPortal, hasPermission } = useAuth();
  const [open, setOpen] = useState(false);
  const [hasHydrated, setHasHydrated] = useState<boolean>(() => hasCachedNotificationInbox(userId));
  const [inbox, setInbox] = useState<NotificationCacheEntry>(
    () =>
      readCachedNotificationInbox(userId) ?? {
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

  // HIGH-17: Chỉ ghi vào bộ đệm sau khi hộp thư đã được nạp từ API hoặc cập nhật thực tế, tránh tự ghi đè trạng thái rỗng ban đầu khiến fetch nền bị bỏ qua (BUG-088).
  useEffect(() => {
    if (!hasHydrated) return;
    writeCachedNotificationInbox(userId, inbox);
  }, [userId, inbox, hasHydrated]);

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
          `/notifications?page=${targetPage}&pageSize=${NOTIFICATION_PAGE_SIZE}`,
        );
        const parsed = parseNotificationResponse(res);
        setHasHydrated(true);
        setInbox((prev) => ({
          items: append
            ? [
                ...prev.items,
                ...parsed.list.filter((incoming) => !prev.items.some((p) => p.id === incoming.id)),
              ]
            : parsed.list,
          unreadCount: parsed.unreadCount,
          page: targetPage,
          hasMore: parsed.hasMore,
        }));
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
    [],
  );

  useEffect(() => {
    if (hasCachedNotificationInbox(userId)) return;
    let cancelled = false;
    apiClient<NotificationListResponse | InAppNotificationItem[]>(
      `/notifications?page=1&pageSize=${NOTIFICATION_PAGE_SIZE}`,
    )
      .then((res) => {
        if (cancelled) return;
        const parsed = parseNotificationResponse(res);
        setHasHydrated(true);
        setInbox({
          items: parsed.list,
          unreadCount: parsed.unreadCount,
          page: 1,
          hasMore: parsed.hasMore,
        });
      })
      .catch(() => {
        /* Tải nền im lặng: không bật banner lỗi trên chuông header */
      });
    return () => {
      cancelled = true;
    };
  }, [userId]);

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
          setHasHydrated(true);
          setInbox((prev) => applyIncomingNotificationToCache(prev, incoming));
          return;
        }
        void fetchNotifications({ silent: true, targetPage: 1, append: false });
      },
    );
  }, [fetchNotifications]);

  async function handleMarkAsRead(target: InAppNotificationItem) {
    if (target.status !== 'UNREAD' || markingIds.has(target.id)) return;
    const targetId = target.id;
    const previousReadAt = target.readAt;
    const nowIso = new Date().toISOString();

    setMarkingIds((prev) => new Set(prev).add(targetId));
    setErrorMessage(null);
    setInbox((prev) => applyOptimisticMarkRead(prev, targetId, nowIso));
    try {
      await apiClient(`/notifications/${encodeURIComponent(targetId)}/read`, { method: 'PATCH' });
    } catch (err) {
      setInbox((prev) => rollbackOptimisticMarkRead(prev, targetId, previousReadAt));
      setErrorMessage(
        err instanceof ApiError ? err.message : 'Không thể cập nhật trạng thái thông báo.',
      );
    } finally {
      setMarkingIds((prev) => {
        const next = new Set(prev);
        next.delete(targetId);
        return next;
      });
    }
  }

  async function handleMarkAllRead() {
    if (unreadCount === 0 || isMarkingAll) return;
    const unreadEntries = items.filter((entry) => entry.status === 'UNREAD');
    const changedIds = new Set(unreadEntries.map((entry) => entry.id));
    const previousReadAtById = new Map(unreadEntries.map((entry) => [entry.id, entry.readAt]));
    const unloadedUnreadDelta = Math.max(0, unreadCount - changedIds.size);
    const nowIso = new Date().toISOString();

    setIsMarkingAll(true);
    setErrorMessage(null);
    setInbox((prev) => applyOptimisticMarkAllRead(prev, changedIds, nowIso));
    try {
      await apiClient('/notifications/read-all', { method: 'PATCH' });
    } catch (err) {
      setInbox((prev) =>
        rollbackOptimisticMarkAllRead(prev, changedIds, previousReadAtById, unloadedUnreadDelta),
      );
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
        className="relative flex h-11 w-11 sm:h-9 sm:w-9 shrink-0 items-center justify-center rounded-full sm:border sm:border-[#ebebeb] sm:bg-[#ffffff] text-[#717171] hover:bg-[#f7f7f7] hover:text-[#222222] transition-colors cursor-pointer sm:shadow-2xs"
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
                  onClick={() => handleMarkAllRead()}
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
                onClick={() => fetchNotifications({ silent: false, targetPage: 1, append: false })}
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
                  const targetHref = resolveNotificationHref(item, canAccessPortal, hasPermission);
                  return (
                    <article
                      key={item.id}
                      className={`rounded-[20px] border p-3.5 text-xs ${isUnread ? 'border-[#dddddd] bg-[#ffffff] shadow-2xs' : 'border-[#ebebeb] bg-[#f7f7f7]'}`}
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
                            className="shrink-0 min-h-11 sm:min-h-9 inline-flex items-center gap-1 rounded-full border border-[#dddddd] bg-[#ffffff] hover:bg-[#f7f7f7] px-3 py-1 text-xs font-semibold text-[#222222] cursor-pointer disabled:opacity-50"
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
                            className="inline-flex min-h-11 sm:min-h-9 items-center gap-1 rounded-full px-2.5 text-xs font-semibold text-[#E31C5F] hover:bg-[#f7f7f7] cursor-pointer"
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
                        fetchNotifications({
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

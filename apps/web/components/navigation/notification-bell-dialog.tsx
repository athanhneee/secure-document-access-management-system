'use client';

/**
 * Thuật toán: Hộp Thư Chuông Thông Báo Nội Bộ `<dialog>.showModal()` Kèm Đánh Dấu Đã Đọc Lạc Quan (`NotificationBellDialog`)
 * Mục đích: Hiển thị chuông `Bell` kèm chấm đỏ `#FF385C` khi `unreadCount > 0`, mở tức thì `<dialog>` `.showModal()` từ `GET /api/v1/notifications?page=1&pageSize=15` và cập nhật lạc quan `PATCH /api/v1/notifications/:id/read` có hoàn tác khi lỗi mạng.
 */
import { useCallback, useEffect, useState } from 'react';
import { AlertCircle, Bell, Check, RefreshCw } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

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

const notificationMemoryCache = new Map<string, InAppNotificationItem[]>();

function formatNotificationTime(iso: string): string {
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime()) ? '—' : parsed.toLocaleString('vi-VN');
}

export function NotificationBellDialog({
  userId,
  canViewNotifications,
}: {
  userId: string;
  canViewNotifications: boolean;
}) {
  return (
    <NotificationBellDialogInner
      key={userId}
      userId={userId}
      canViewNotifications={canViewNotifications}
    />
  );
}

function NotificationBellDialogInner({
  userId,
  canViewNotifications,
}: {
  userId: string;
  canViewNotifications: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<InAppNotificationItem[]>(
    () => notificationMemoryCache.get(userId) ?? [],
  );
  const [isLoading, setIsLoading] = useState(false);
  const [markingId, setMarkingId] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchNotifications = useCallback(
    async (silent = false) => {
      if (!canViewNotifications) return;
      if (!silent) setIsLoading(true);
      setErrorMessage(null);
      try {
        const res = await apiClient<{ data?: InAppNotificationItem[] } | InAppNotificationItem[]>(
          '/notifications?page=1&pageSize=15',
        );
        const list = Array.isArray(res) ? res : Array.isArray(res?.data) ? res.data : [];
        notificationMemoryCache.set(userId, list);
        setItems(list);
      } catch (err) {
        if (!silent) {
          setErrorMessage(
            err instanceof ApiError ? err.message : 'Không thể tải danh sách thông báo nội bộ.',
          );
        }
      } finally {
        if (!silent) setIsLoading(false);
      }
    },
    [userId, canViewNotifications],
  );

  useEffect(() => {
    if (notificationMemoryCache.has(userId) || !canViewNotifications) return;
    let cancelled = false;
    apiClient<{ data?: InAppNotificationItem[] } | InAppNotificationItem[]>(
      '/notifications?page=1&pageSize=15',
    )
      .then((res) => {
        if (cancelled) return;
        const list = Array.isArray(res) ? res : Array.isArray(res?.data) ? res.data : [];
        notificationMemoryCache.set(userId, list);
        setItems(list);
      })
      .catch(() => {
        /* Tải nền im lặng: không bật banner lỗi trên chuông header */
      });
    return () => {
      cancelled = true;
    };
  }, [userId, canViewNotifications]);

  async function handleMarkAsRead(target: InAppNotificationItem) {
    if (target.status !== 'UNREAD' || markingId) return;
    const snapshot = items;
    const next = items.map((entry) =>
      entry.id === target.id
        ? { ...entry, status: 'READ', readAt: new Date().toISOString() }
        : entry,
    );
    setMarkingId(target.id);
    setErrorMessage(null);
    setItems(next);
    notificationMemoryCache.set(userId, next);
    try {
      await apiClient(`/notifications/${encodeURIComponent(target.id)}/read`, { method: 'PATCH' });
    } catch (err) {
      setItems(snapshot);
      notificationMemoryCache.set(userId, snapshot);
      setErrorMessage(
        err instanceof ApiError ? err.message : 'Không thể cập nhật trạng thái thông báo.',
      );
    } finally {
      setMarkingId(null);
    }
  }

  const unreadCount = items.reduce((acc, item) => acc + (item.status === 'UNREAD' ? 1 : 0), 0);

  return (
    <>
      <button
        type="button"
        onClick={() => {
          setOpen(true);
          if (canViewNotifications) void fetchNotifications(items.length > 0);
        }}
        aria-label="Thông báo hệ thống"
        title="Thông báo hệ thống"
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
              Cập nhật trạng thái cấp quyền, thu hồi giấy phép và thông báo vận hành nội bộ
            </DialogDescription>
          </DialogHeader>

          {errorMessage && (
            <Alert variant="destructive" className="mb-3">
              <AlertCircle size={16} strokeWidth={1.75} aria-hidden="true" />
              <AlertDescription>{errorMessage}</AlertDescription>
            </Alert>
          )}

          <div className="flex items-center justify-between gap-2 pb-3 border-b border-[#ebebeb]">
            <span className="text-xs text-[#717171]">Hiển thị {items.length} mục gần nhất</span>
            {canViewNotifications && (
              <InteractiveHoverButton
                type="button"
                variant="secondary"
                size="sm"
                isLoading={isLoading}
                disabled={isLoading}
                icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
                text="Làm mới"
                onClick={() => void fetchNotifications(false)}
              />
            )}
          </div>

          <div className="mt-3 max-h-[56dvh] space-y-2.5 overflow-y-auto pr-1">
            {!canViewNotifications ? (
              <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-4 text-xs text-[#717171] leading-relaxed">
                Vai trò hiện tại tách biệt khỏi hộp thư tài liệu nghiệp vụ theo Phân tách nhiệm vụ
                (SoD).
              </div>
            ) : isLoading && items.length === 0 ? (
              <div className="py-8 text-center text-xs text-[#717171]">
                Đang đồng bộ hộp thư thông báo…
              </div>
            ) : items.length === 0 ? (
              <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-5 text-center text-xs text-[#717171]">
                Hiện chưa có thông báo nội bộ nào trong hộp thư của bạn.
              </div>
            ) : (
              items.map((item) => {
                const isUnread = item.status === 'UNREAD';
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
                          disabled={markingId === item.id}
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
                          <span>Đã đọc</span>
                        </button>
                      ) : (
                        <span className="staff-badge bg-transparent border-0 p-0 shrink-0 inline-flex items-center gap-1 text-xs font-semibold text-[#717171]">
                          <Check
                            size={16}
                            strokeWidth={2}
                            className="text-[#008A05]"
                            aria-hidden="true"
                          />
                          <span>Đã xem</span>
                        </span>
                      )}
                    </div>
                    <p className="mt-1.5 text-xs text-[#717171] leading-relaxed break-words">
                      {item.body}
                    </p>
                    <div className="mt-2 text-[12px] text-[#717171]">
                      {formatNotificationTime(item.createdAt)}
                    </div>
                  </article>
                );
              })
            )}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

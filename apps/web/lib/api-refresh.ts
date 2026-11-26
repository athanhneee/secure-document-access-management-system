/**
 * Thuật toán: Khóa Đơn Luồng Làm Mới Phiên Kết Hợp Phối Hợp Liên Tab (`attemptSessionRefresh`)
 * Mục đích:
 *   - Hợp nhất toàn bộ các yêu cầu nhận mã HTTP `401` đồng thời (ví dụ 8 yêu cầu `GET` song song khi mở bảng điều khiển) vào đúng **1** lời gọi `POST /api/v1/auth/refresh` duy nhất.
 *   - Phối hợp trạng thái xoay vòng phiên giữa nhiều tab trình duyệt qua kênh `BroadcastChannel('sda_auth_refresh')` và cửa sổ dấu thời gian `lastRefreshSuccessAt`, triệt tiêu hoàn toàn hiện tượng gửi lại `sda_refresh` vừa xoay vòng gây cảnh báo giả `REFRESH_TOKEN_REUSE` trên SOC.
 * Cơ chế hoạt động:
 *   - Tầng 0 (Kiểm tra điều kiện biên): Bỏ qua trên SSR hoặc khi trình duyệt chưa có cookie `sda_csrf`.
 *   - Tầng 1 (Cửa sổ kế thừa kết quả): Nếu một luồng khác vừa làm mới phiên thành công sau thời điểm yêu cầu hiện tại bắt đầu (`lastRefreshSuccessAt >= requestStartedAt`) hoặc trong khoảng đệm `1200ms`, trả về `true` tức thì để yêu cầu tự thử lại bằng cookie mới.
 *   - Tầng 2 (Khóa Promise trong tiến trình tab): Dùng chung một `inFlightRefreshPromise` duy nhất cho mọi yêu cầu đồng thời trong cùng tab.
 *   - Tầng 3 (Khóa phối hợp liên tab): Nếu tab khác đang phát tín hiệu `REFRESH_STARTED` còn hiệu lực, xếp hàng chờ thông điệp `REFRESH_COMPLETED` tối đa `4000ms` trước khi tự đứng ra xoay vòng.
 */

const REFRESH_CHANNEL_NAME = 'sda_auth_refresh';
const RECENT_REFRESH_WINDOW_MS = 1_200;
const PEER_LOCK_TTL_MS = 4_000;

interface RefreshBroadcastMessage {
  type: 'REFRESH_STARTED' | 'REFRESH_COMPLETED';
  senderId: string;
  timestamp: number;
  ok?: boolean;
}

let inFlightRefreshPromise: Promise<boolean> | null = null;
let lastRefreshSuccessAt = 0;
let peerRefreshActiveUntil = 0;
let peerWaiters: Array<(ok: boolean) => void> = [];
let refreshChannel: BroadcastChannel | null = null;
let channelInitialized = false;

const tabInstanceId =
  typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `tab-${Date.now()}`;

function settlePeerWaiters(ok: boolean): void {
  if (peerWaiters.length === 0) return;
  const pending = peerWaiters;
  peerWaiters = [];
  for (const resolve of pending) {
    resolve(ok);
  }
}

function getRefreshBroadcastChannel(): BroadcastChannel | null {
  if (typeof window === 'undefined' || typeof BroadcastChannel === 'undefined') {
    return null;
  }
  if (channelInitialized) {
    return refreshChannel;
  }
  channelInitialized = true;
  try {
    const channel = new BroadcastChannel(REFRESH_CHANNEL_NAME);
    channel.onmessage = (event: MessageEvent<RefreshBroadcastMessage>) => {
      const payload = event.data;
      if (!payload || typeof payload !== 'object' || payload.senderId === tabInstanceId) {
        return;
      }
      if (payload.type === 'REFRESH_STARTED') {
        peerRefreshActiveUntil = Math.max(
          peerRefreshActiveUntil,
          payload.timestamp + PEER_LOCK_TTL_MS,
        );
      } else if (payload.type === 'REFRESH_COMPLETED') {
        peerRefreshActiveUntil = 0;
        if (payload.ok) {
          lastRefreshSuccessAt = Math.max(lastRefreshSuccessAt, payload.timestamp);
        }
        settlePeerWaiters(Boolean(payload.ok));
      }
    };
    refreshChannel = channel;
  } catch {
    refreshChannel = null;
  }
  return refreshChannel;
}

function broadcastRefreshSignal(message: RefreshBroadcastMessage): void {
  const channel = getRefreshBroadcastChannel();
  if (!channel) return;
  try {
    channel.postMessage(message);
  } catch {
    // Bỏ qua lỗi phát sóng liên tab nếu kênh bị đóng bởi trình duyệt
  }
}

function waitForPeerRefreshResult(timeoutMs: number): Promise<boolean | null> {
  return new Promise((resolve) => {
    let settled = false;
    const onPeerDone = (ok: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(ok);
    };
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      peerWaiters = peerWaiters.filter((fn) => fn !== onPeerDone);
      resolve(null);
    }, timeoutMs);
    peerWaiters.push(onPeerDone);
  });
}

export function isRefreshExcludedEndpoint(endpoint: string): boolean {
  const clean = endpoint
    .replace(/^https?:\/\/[^/]+/iu, '')
    .replace(/[?#].*$/u, '')
    .replace(/^\/api\/v1(?=\/|$)/u, '');
  const normalized = clean.startsWith('/') ? clean : `/${clean}`;
  return (
    normalized.startsWith('/auth/login') ||
    normalized.startsWith('/auth/refresh') ||
    normalized.startsWith('/auth/logout') ||
    normalized === '/auth/change-password' ||
    normalized.startsWith('/auth/change-password/') ||
    normalized === '/auth/mfa' ||
    normalized.startsWith('/auth/mfa/') ||
    normalized.startsWith('/auth/password-reset/') ||
    normalized.startsWith('/auth/forgot-password') ||
    normalized.startsWith('/auth/reset-password') ||
    normalized.startsWith('/auth/webauthn/')
  );
}

export async function attemptSessionRefresh(
  resolveSafeApiUrl: (endpoint: string) => string,
  getCsrfToken: () => string,
  requestStartedAt?: number,
): Promise<boolean> {
  if (typeof window === 'undefined') return false;

  getRefreshBroadcastChannel();

  const now = Date.now();
  if (
    lastRefreshSuccessAt > 0 &&
    ((requestStartedAt !== undefined && lastRefreshSuccessAt >= requestStartedAt) ||
      now - lastRefreshSuccessAt < RECENT_REFRESH_WINDOW_MS)
  ) {
    return true;
  }

  if (!getCsrfToken()) {
    return false;
  }

  if (inFlightRefreshPromise) {
    return inFlightRefreshPromise;
  }

  inFlightRefreshPromise = (async () => {
    try {
      const currentNow = Date.now();
      if (peerRefreshActiveUntil > currentNow) {
        const waitBudget = Math.min(PEER_LOCK_TTL_MS, peerRefreshActiveUntil - currentNow + 150);
        const peerResult = await waitForPeerRefreshResult(waitBudget);
        if (peerResult !== null) {
          return peerResult;
        }
        if (requestStartedAt !== undefined && lastRefreshSuccessAt >= requestStartedAt) {
          return true;
        }
      }

      const csrf = getCsrfToken();
      if (!csrf) {
        return false;
      }

      broadcastRefreshSignal({
        type: 'REFRESH_STARTED',
        senderId: tabInstanceId,
        timestamp: Date.now(),
      });

      const refreshUrl = resolveSafeApiUrl('/auth/refresh');
      const res = await fetch(refreshUrl, {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'x-csrf-token': csrf,
        },
      });

      const completedAt = Date.now();
      if (res.ok) {
        lastRefreshSuccessAt = completedAt;
      }
      broadcastRefreshSignal({
        type: 'REFRESH_COMPLETED',
        senderId: tabInstanceId,
        timestamp: completedAt,
        ok: res.ok,
      });
      return res.ok;
    } catch {
      broadcastRefreshSignal({
        type: 'REFRESH_COMPLETED',
        senderId: tabInstanceId,
        timestamp: Date.now(),
        ok: false,
      });
      return false;
    } finally {
      inFlightRefreshPromise = null;
    }
  })();

  return inFlightRefreshPromise;
}

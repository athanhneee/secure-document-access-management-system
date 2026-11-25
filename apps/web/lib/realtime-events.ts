'use client';

import { API_BASE_URL, getCsrfToken } from './api-client';
import { attemptSessionRefresh } from './api-refresh';

export type RealtimeEventType =
  | 'NOTIFICATION_CREATED'
  | 'EXPORT_JOB_UPDATED'
  | 'ACCESS_REQUEST_UPDATED'
  | 'ACCESS_GRANT_UPDATED'
  | 'SECURITY_ALERT_UPDATED'
  | 'INCIDENT_REPORT_UPDATED'
  | 'DETECTION_RULE_UPDATED'
  | 'ACCESS_SESSION_UPDATED'
  | 'USER_SESSION_REVOKED';

export interface RealtimeEventEnvelope<T = Record<string, unknown>> {
  type: RealtimeEventType;
  timestamp: string;
  payload: T;
}

export type RealtimeEventHandler<T = Record<string, unknown>> = (
  event: RealtimeEventEnvelope<T>,
) => void;

type ConnectionStatusHandler = (connected: boolean) => void;

const ALL_EVENT_TYPES: readonly RealtimeEventType[] = [
  'NOTIFICATION_CREATED',
  'EXPORT_JOB_UPDATED',
  'ACCESS_REQUEST_UPDATED',
  'ACCESS_GRANT_UPDATED',
  'SECURITY_ALERT_UPDATED',
  'INCIDENT_REPORT_UPDATED',
  'DETECTION_RULE_UPDATED',
  'ACCESS_SESSION_UPDATED',
  'USER_SESSION_REVOKED',
];

const INITIAL_RETRY_MS = 1_500;
const MAX_RETRY_MS = 25_000;
// CONFLICT-RESOLVED: Kế thừa API_BASE_URL động thay vì hardcode '/api/v1/events/stream' (V-56).
const STREAM_URL = `${API_BASE_URL.replace(/\/+$/u, '')}/events/stream`;

/**
 * Thuật toán: Bộ Quản Lý Kênh SSE Đơn Thể Toàn Tab Kèm Backoff Mũ & Tự Động Ngắt Khi Đăng Xuất (`realtime-events`)
 * Mục đích:
 *   - Duy trì duy nhất 1 kết nối `EventSource` (`GET /api/v1/events/stream`) cho cả tab trình duyệt, phân phối sự kiện theo `type` tới nhiều component cùng lúc (chuông thông báo, `/auditor`, `/owner`, `/reader`, `/security`).
 *   - Chỉ mở kết nối khi có ít nhất 1 subscriber đang hoạt động và trình duyệt có cookie phiên `sda_csrf`; tự động đóng khi không còn subscriber hoặc khi người dùng đăng xuất.
 *   - Khi mất kết nối tạm thời, tự động thử kết nối lại theo hàm mũ có nhiễu (`1.5s -> 25s`) và phục hồi tức thì khi sự kiện `online` của trình duyệt kích hoạt.
 */
class RealtimeEventsClient {
  private source: EventSource | null = null;
  private connected = false;
  private retryDelayMs = INITIAL_RETRY_MS;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private onlineBound = false;

  private readonly eventListeners = new Map<RealtimeEventType, Set<RealtimeEventHandler>>();
  private readonly statusListeners = new Set<ConnectionStatusHandler>();

  private readonly handleWindowOnline = () => {
    if (!this.connected && this.hasActiveEventListeners()) {
      this.retryDelayMs = INITIAL_RETRY_MS;
      this.clearReconnectTimer();
      this.ensureConnected();
    }
  };

  isConnected(): boolean {
    return this.connected;
  }

  subscribe<T = Record<string, unknown>>(
    eventType: RealtimeEventType,
    handler: RealtimeEventHandler<T>,
  ): () => void {
    let bucket = this.eventListeners.get(eventType);
    if (!bucket) {
      bucket = new Set();
      this.eventListeners.set(eventType, bucket);
    }
    const typedHandler = handler as RealtimeEventHandler;
    bucket.add(typedHandler);
    this.ensureConnected();

    return () => {
      bucket?.delete(typedHandler);
      if (bucket && bucket.size === 0) {
        this.eventListeners.delete(eventType);
      }
      if (!this.hasActiveEventListeners()) {
        this.disconnect();
      }
    };
  }

  subscribeConnectionStatus(listener: ConnectionStatusHandler): () => void {
    this.statusListeners.add(listener);
    try {
      listener(this.connected);
    } catch {
      // Bỏ qua lỗi từ subscriber trạng thái đơn lẻ
    }
    return () => {
      this.statusListeners.delete(listener);
    };
  }

  disconnect(): void {
    this.clearReconnectTimer();
    this.retryDelayMs = INITIAL_RETRY_MS;
    if (this.source) {
      try {
        this.source.close();
      } catch {
        // Bỏ qua lỗi khi đóng EventSource
      }
      this.source = null;
    }
    this.setConnected(false);
    this.unbindOnlineListener();
  }

  private hasActiveEventListeners(): boolean {
    for (const bucket of this.eventListeners.values()) {
      if (bucket.size > 0) return true;
    }
    return false;
  }

  private setConnected(next: boolean): void {
    if (this.connected === next) return;
    this.connected = next;
    for (const listener of this.statusListeners) {
      try {
        listener(next);
      } catch {
        // Cô lập lỗi giữa các listener trạng thái
      }
    }
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private bindOnlineListener(): void {
    if (this.onlineBound || typeof window === 'undefined') return;
    window.addEventListener('online', this.handleWindowOnline);
    this.onlineBound = true;
  }

  private unbindOnlineListener(): void {
    if (!this.onlineBound || typeof window === 'undefined') return;
    window.removeEventListener('online', this.handleWindowOnline);
    this.onlineBound = false;
  }

  private ensureConnected(): void {
    if (typeof window === 'undefined' || typeof EventSource === 'undefined') return;
    if (!this.hasActiveEventListeners()) return;
    if (this.source || this.reconnectTimer !== null) return;
    if (!getCsrfToken()) return;

    this.bindOnlineListener();
    try {
      const es = new EventSource(STREAM_URL, { withCredentials: true });
      this.source = es;

      es.onopen = () => {
        if (this.source !== es) return;
        this.retryDelayMs = INITIAL_RETRY_MS;
        this.setConnected(true);
      };

      for (const eventType of ALL_EVENT_TYPES) {
        es.addEventListener(eventType, (rawEvent) => {
          if (this.source !== es) return;
          const messageEvent = rawEvent as MessageEvent<string>;
          this.dispatch(eventType, messageEvent.data);
          if (eventType === 'USER_SESSION_REVOKED') {
            this.disconnect();
          }
        });
      }

      es.onerror = () => {
        if (this.source !== es) return;
        try {
          es.close();
        } catch {
          // Bỏ qua lỗi khi đóng kết nối hỏng
        }
        this.source = null;
        this.setConnected(false);
        // Thuật toán: Tự động thử làm mới Access Token một lần khi SSE gặp lỗi (401 hết hạn TTL) trước khi lùi theo backoff mũ để tránh lặp 401 vô hạn (V-15).
        void attemptSessionRefresh(
          (endpoint) => `${API_BASE_URL.replace(/\/+$/u, '')}${endpoint}`,
          getCsrfToken,
          Date.now(),
        )
          .catch(() => false)
          .then((refreshed) => {
            if (refreshed && this.hasActiveEventListeners() && !this.source) {
              this.retryDelayMs = INITIAL_RETRY_MS;
              this.clearReconnectTimer();
              this.ensureConnected();
              return;
            }
            this.scheduleReconnect();
          });
      };
    } catch {
      this.source = null;
      this.setConnected(false);
      this.scheduleReconnect();
    }
  }

  private dispatch(eventType: RealtimeEventType, rawData: string): void {
    const bucket = this.eventListeners.get(eventType);
    if (!bucket || bucket.size === 0) return;

    let parsed: RealtimeEventEnvelope | null = null;
    try {
      const data = JSON.parse(rawData) as Partial<RealtimeEventEnvelope> & {
        occurredAt?: string;
      };
      parsed = {
        type: (data.type as RealtimeEventType) ?? eventType,
        timestamp:
          typeof data.occurredAt === 'string'
            ? data.occurredAt
            : typeof data.timestamp === 'string'
              ? data.timestamp
              : new Date().toISOString(),
        payload:
          data.payload && typeof data.payload === 'object'
            ? (data.payload as Record<string, unknown>)
            : {},
      };
    } catch {
      return;
    }

    for (const handler of bucket) {
      try {
        handler(parsed);
      } catch {
        // Cô lập lỗi của một subscriber để không ảnh hưởng toàn kênh SSE
      }
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer !== null) return;
    if (!this.hasActiveEventListeners() || !getCsrfToken()) return;

    const jitter = Math.floor(Math.random() * 500);
    const delay = Math.min(MAX_RETRY_MS, this.retryDelayMs) + jitter;
    this.retryDelayMs = Math.min(MAX_RETRY_MS, this.retryDelayMs * 2);

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.ensureConnected();
    }, delay);
  }
}

const singletonClient = new RealtimeEventsClient();

export function subscribeRealtimeEvent<T = Record<string, unknown>>(
  eventType: RealtimeEventType,
  handler: RealtimeEventHandler<T>,
): () => void {
  return singletonClient.subscribe(eventType, handler);
}

export function subscribeRealtimeConnectionStatus(listener: ConnectionStatusHandler): () => void {
  return singletonClient.subscribeConnectionStatus(listener);
}

export function isRealtimeStreamConnected(): boolean {
  return singletonClient.isConnected();
}

export function disconnectRealtimeStream(): void {
  singletonClient.disconnect();
}

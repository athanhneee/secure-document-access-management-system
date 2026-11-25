/**
 * @module RealtimeEventsService
 * Thuật toán: Trung Tâm Phát Sóng Server-Sent Events (SSE) Phân Tán Qua Redis Pub/Sub Có Kiểm Soát Phạm Vi Đích Zero-Trust.
 *   1. Duy trì bảng kết nối SSE đang mở theo định danh phiên kết nối và người dùng (giới hạn tối đa 10 kết nối/tài khoản chống cạn kiệt socket).
 *   2. Lắng nghe kênh `sda:realtime:events` trên `DistributedStateService` để tiếp nhận đồng thời sự kiện từ mọi bản sao API và từ `@sda/worker`.
 *   3. Cưỡng chế nguyên tắc Mặc Định Từ Chối (Fail-Closed Audience Scoping): chỉ phát khung `event: <type>` cho các client có `userId` thuộc `targetUserIds` hoặc sở hữu vai trò nằm trong `targetRoles`, tuyệt đối bóc tách danh sách đích trước khi gửi ra trình duyệt.
 *   4. Gửi nhịp tim `: heartbeat\n\n` mỗi 20 giây để giữ kết nối sống ổn định qua reverse proxy và dọn sạch mọi socket khi tắt tiến trình.
 */
import { Injectable, Logger, Optional, type OnModuleDestroy } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { REALTIME_EVENTS_CHANNEL } from '../concurrency/distributed-state-pubsub.helper.js';
import { DistributedStateService } from '../concurrency/distributed-state.service.js';
import type {
  PublishRealtimeEventInput,
  RealtimeEventEnvelope,
  RealtimeWirePayload,
} from './realtime-events.types.js';

export interface SseClientRegistration {
  userId: string;
  sessionId?: string | undefined;
  roles: readonly string[];
  writeFrame: (frame: string) => boolean;
  close: () => void;
}

interface ActiveSseClient {
  id: string;
  userId: string;
  sessionId?: string | undefined;
  roles: Set<string>;
  writeFrame: (frame: string) => boolean;
  close: () => void;
}

const MAX_CONNECTIONS_PER_USER = 10;
const HEARTBEAT_INTERVAL_MS = 20_000;

@Injectable()
export class RealtimeEventsService implements OnModuleDestroy {
  private readonly logger = new Logger(RealtimeEventsService.name);
  private readonly clients = new Map<string, ActiveSseClient>();
  private readonly clientsByUser = new Map<string, Set<string>>();
  private readonly unsubscribeChannel: (() => void) | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  constructor(@Optional() private readonly stateStore?: DistributedStateService) {
    if (this.stateStore && typeof this.stateStore.subscribeChannel === 'function') {
      this.unsubscribeChannel = this.stateStore.subscribeChannel(
        REALTIME_EVENTS_CHANNEL,
        (rawMessage) => {
          this.handleBrokerMessage(rawMessage);
        },
      );
    }
  }

  /**
   * Thuật toán: Đăng ký luồng SSE mới của người dùng đã xác thực, cưỡng chế trần `MAX_CONNECTIONS_PER_USER` (LRU eviction) và khởi động nhịp tim giữ kết nối.
   */
  registerClient(registration: SseClientRegistration): string {
    const clientId = randomUUID();
    const userConnections = this.clientsByUser.get(registration.userId) ?? new Set<string>();

    if (userConnections.size >= MAX_CONNECTIONS_PER_USER) {
      const oldestId = userConnections.values().next().value;
      if (oldestId !== undefined) {
        const oldest = this.clients.get(oldestId);
        this.unregisterClient(oldestId);
        try {
          oldest?.close();
        } catch {
          // Ignore close error on evicted socket
        }
      }
    }

    const client: ActiveSseClient = {
      id: clientId,
      userId: registration.userId,
      ...(registration.sessionId ? { sessionId: registration.sessionId } : {}),
      roles: new Set(registration.roles),
      writeFrame: registration.writeFrame,
      close: registration.close,
    };

    this.clients.set(clientId, client);
    userConnections.add(clientId);
    this.clientsByUser.set(registration.userId, userConnections);
    this.ensureHeartbeatRunning();
    return clientId;
  }

  /** Thuật toán: Thu hồi sạch kết nối SSE khi trình duyệt đóng tab hoặc ngắt mạng. */
  unregisterClient(clientId: string): void {
    const client = this.clients.get(clientId);
    if (!client) return;
    this.clients.delete(clientId);
    const userConnections = this.clientsByUser.get(client.userId);
    if (userConnections) {
      userConnections.delete(clientId);
      if (userConnections.size === 0) {
        this.clientsByUser.delete(client.userId);
      }
    }
    if (this.clients.size === 0 && this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  /**
   * Thuật toán: Phát sự kiện thời gian thực phi chặn (Non-Blocking Fire-and-Forget Publish) lên Redis Pub/Sub
   * hoặc phát thẳng cục bộ khi không cấu hình Redis.
   */
  publish<T extends Record<string, unknown>>(input: PublishRealtimeEventInput<T>): void {
    const targetUserIds = input.targetUserIds
      ? [...new Set(input.targetUserIds.filter((id) => id.length > 0))]
      : undefined;
    const targetRoles = input.targetRoles
      ? [...new Set(input.targetRoles.filter((role) => role.length > 0))]
      : undefined;

    const targetSessionIds = input.targetSessionIds
      ? [...new Set(input.targetSessionIds.filter((id) => id.length > 0))]
      : undefined;
    const excludeSessionId = input.excludeSessionId?.trim() || undefined;

    if (
      (!targetUserIds || targetUserIds.length === 0) &&
      (!targetRoles || targetRoles.length === 0)
    ) {
      return;
    }

    const envelope: RealtimeEventEnvelope<T> = {
      id: randomUUID(),
      type: input.type,
      occurredAt: new Date().toISOString(),
      ...(targetUserIds && targetUserIds.length > 0 ? { targetUserIds } : {}),
      ...(targetRoles && targetRoles.length > 0 ? { targetRoles } : {}),
      ...(targetSessionIds && targetSessionIds.length > 0 ? { targetSessionIds } : {}),
      ...(excludeSessionId ? { excludeSessionId } : {}),
      payload: input.payload,
    };

    if (this.stateStore && typeof this.stateStore.publishChannel === 'function') {
      void this.stateStore
        .publishChannel(REALTIME_EVENTS_CHANNEL, JSON.stringify(envelope))
        .catch((err: unknown) => {
          this.logger.debug(
            `Realtime event publish fallback: ${err instanceof Error ? err.message : String(err)}`,
          );
          this.dispatchToMatchingClients(envelope);
        });
      return;
    }

    this.dispatchToMatchingClients(envelope);
  }

  activeConnectionCount(): number {
    return this.clients.size;
  }

  onModuleDestroy(): void {
    this.unsubscribeChannel?.();
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    for (const client of this.clients.values()) {
      try {
        client.close();
      } catch {
        // Ignore teardown errors
      }
    }
    this.clients.clear();
    this.clientsByUser.clear();
  }

  private handleBrokerMessage(rawMessage: string): void {
    try {
      const parsed = JSON.parse(rawMessage) as RealtimeEventEnvelope;
      if (!parsed || typeof parsed !== 'object' || typeof parsed.type !== 'string') {
        return;
      }
      this.dispatchToMatchingClients(parsed);
    } catch {
      // Ignore malformed pub/sub frames
    }
  }

  /**
   * Thuật toán: Lọc phạm vi nhận sự kiện Zero-Trust (`targetUserIds` ∪ `targetRoles`) và đóng gói chuẩn khung SSE RFC 8895.
   */
  private dispatchToMatchingClients(envelope: RealtimeEventEnvelope): void {
    if (this.clients.size === 0) return;

    const userSet =
      Array.isArray(envelope.targetUserIds) && envelope.targetUserIds.length > 0
        ? new Set(envelope.targetUserIds)
        : null;
    const roleSet =
      Array.isArray(envelope.targetRoles) && envelope.targetRoles.length > 0
        ? new Set(envelope.targetRoles)
        : null;

    if (!userSet && !roleSet) return;

    const wirePayload: RealtimeWirePayload = {
      id: envelope.id || randomUUID(),
      type: envelope.type,
      occurredAt: envelope.occurredAt || new Date().toISOString(),
      payload: envelope.payload ?? {},
    };
    const frame = `id: ${wirePayload.id}\nevent: ${wirePayload.type}\ndata: ${JSON.stringify(wirePayload)}\n\n`;

    const staleClientIds: string[] = [];
    const revokedClients: ActiveSseClient[] = [];
    const shouldCloseAfterDelivery = envelope.type === 'USER_SESSION_REVOKED';
    const sessionFilterSet =
      Array.isArray(envelope.targetSessionIds) && envelope.targetSessionIds.length > 0
        ? new Set(envelope.targetSessionIds)
        : null;
    const excludedSessionId = envelope.excludeSessionId ?? null;
    for (const client of this.clients.values()) {
      const matchedUser = userSet !== null && userSet.has(client.userId);
      const matchedRole = roleSet !== null && [...client.roles].some((role) => roleSet.has(role));
      if (!matchedUser && !matchedRole) continue;
      // Thuật toán: Cô lập ngắt kết nối SSE chính xác theo phiên đăng nhập đích (`targetSessionIds` / `excludeSessionId`) để không đóng nhầm thiết bị hiện tại khi đăng xuất thiết bị khác (V-06).
      if (
        sessionFilterSet !== null &&
        (!client.sessionId || !sessionFilterSet.has(client.sessionId))
      ) {
        continue;
      }
      if (excludedSessionId !== null && client.sessionId === excludedSessionId) {
        continue;
      }

      const ok = client.writeFrame(frame);
      if (!ok) {
        staleClientIds.push(client.id);
      } else if (shouldCloseAfterDelivery) {
        revokedClients.push(client);
      }
    }

    for (const staleId of staleClientIds) {
      this.unregisterClient(staleId);
    }
    for (const revoked of revokedClients) {
      this.unregisterClient(revoked.id);
      try {
        revoked.close();
      } catch {
        // Ignore close error on revoked socket
      }
    }
  }

  private ensureHeartbeatRunning(): void {
    if (this.heartbeatTimer) return;
    this.heartbeatTimer = setInterval(() => {
      const stale: string[] = [];
      for (const client of this.clients.values()) {
        if (!client.writeFrame(': heartbeat\n\n')) {
          stale.push(client.id);
        }
      }
      for (const id of stale) {
        this.unregisterClient(id);
      }
    }, HEARTBEAT_INTERVAL_MS);
    this.heartbeatTimer.unref();
  }
}

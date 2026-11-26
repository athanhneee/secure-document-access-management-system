/**
 * @module RealtimeEventsService
 * Thuật toán: Trung Tâm Phát Sóng Server-Sent Events (SSE) Phân Tán Qua Redis Pub/Sub Có Kiểm Soát Phạm Vi Đích Zero-Trust (`BUG-063`).
 *   1. Lắng nghe `stateStore.onInvalidate` (`rbac-user:<id>`, `rbac-global`) để chủ động đóng luồng TCP (`client.close()`) KHÔNG gửi `USER_SESSION_REVOKED`, buộc trình duyệt tự kết nối lại nạp quyền/phòng ban mới mà không bị đăng xuất nhầm ra `/login`.
 *   2. Cưỡng chế hạn sống `expiresAtMs` của từng kết nối SSE trong cả thời điểm phát sự kiện lẫn nhịp tim 20 giây.
 *   3. Cô lập sự kiện SOC theo phòng ban (`targetDepartmentId` đối chiếu `allowedDeptIds` của từng kết nối SSE).
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
  expiresAtMs?: number | undefined;
  allowedDeptIds?: ReadonlySet<string> | readonly string[] | null | undefined;
  allowedSocEvents?: ReadonlySet<string> | readonly string[] | undefined;
  allowedDeptIdsByEvent?: ReadonlyMap<string, ReadonlySet<string> | null> | undefined;
  writeFrame: (frame: string) => boolean;
  close: () => void;
}

interface ActiveSseClient {
  id: string;
  userId: string;
  sessionId?: string | undefined;
  roles: Set<string>;
  expiresAtMs?: number | undefined;
  allowedDeptIds?: Set<string> | null | undefined;
  allowedSocEvents?: Set<string> | undefined;
  allowedDeptIdsByEvent?: Map<string, Set<string> | null> | undefined;
  writeFrame: (frame: string) => boolean;
  close: () => void;
}

const MAX_CONNECTIONS_PER_USER = 10;
const HEARTBEAT_INTERVAL_MS = 20_000;
const SOC_DEPARTMENT_SCOPED_EVENTS = new Set<string>([
  'SECURITY_ALERT_UPDATED',
  'INCIDENT_REPORT_UPDATED',
  'ACCESS_SESSION_UPDATED',
]);

@Injectable()
export class RealtimeEventsService implements OnModuleDestroy {
  private readonly logger = new Logger(RealtimeEventsService.name);
  private readonly clients = new Map<string, ActiveSseClient>();
  private readonly clientsByUser = new Map<string, Set<string>>();
  private readonly unsubscribeChannel: (() => void) | null = null;
  private readonly unsubscribeInvalidate: (() => void) | null = null;
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

    // BUG-063: Khi vai trò/quyền thay đổi (`rbac-user:<id>` hoặc `rbac-global`), chỉ đóng socket TCP (`client.close()`) để trình duyệt tự kết nối lại nạp quyền mới — tuyệt đối KHÔNG phát `USER_SESSION_REVOKED` làm đăng xuất người dùng!
    if (this.stateStore && typeof this.stateStore.onInvalidate === 'function') {
      this.unsubscribeInvalidate = this.stateStore.onInvalidate((event) => {
        if (event.namespace === 'rbac-global') {
          this.disconnectClientsSilently(() => true);
        } else if (event.namespace.startsWith('rbac-user:')) {
          const targetUserId = event.namespace.slice('rbac-user:'.length);
          if (targetUserId) {
            this.disconnectUserClientsSilently(targetUserId);
          }
        }
      });
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

    const normalizedAllowedDepts =
      registration.allowedDeptIds === undefined
        ? undefined
        : registration.allowedDeptIds === null
          ? null
          : new Set(registration.allowedDeptIds);
    const normalizedAllowedSocEvents =
      registration.allowedSocEvents !== undefined
        ? new Set(registration.allowedSocEvents)
        : undefined;
    const normalizedAllowedDeptsByEvent =
      registration.allowedDeptIdsByEvent !== undefined
        ? new Map(
            [...registration.allowedDeptIdsByEvent.entries()].map(([evt, scope]) => [
              evt,
              scope === null ? null : new Set(scope),
            ]),
          )
        : undefined;

    const client: ActiveSseClient = {
      id: clientId,
      userId: registration.userId,
      ...(registration.sessionId ? { sessionId: registration.sessionId } : {}),
      roles: new Set(registration.roles),
      ...(registration.expiresAtMs !== undefined ? { expiresAtMs: registration.expiresAtMs } : {}),
      ...(normalizedAllowedDepts !== undefined ? { allowedDeptIds: normalizedAllowedDepts } : {}),
      ...(normalizedAllowedSocEvents !== undefined
        ? { allowedSocEvents: normalizedAllowedSocEvents }
        : {}),
      ...(normalizedAllowedDeptsByEvent !== undefined
        ? { allowedDeptIdsByEvent: normalizedAllowedDeptsByEvent }
        : {}),
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
    const excludeSessionIds = input.excludeSessionIds
      ? [...new Set(input.excludeSessionIds.map((id) => id.trim()).filter((id) => id.length > 0))]
      : undefined;

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
      ...(input.targetDepartmentId !== undefined
        ? { targetDepartmentId: input.targetDepartmentId }
        : {}),
      ...(targetSessionIds && targetSessionIds.length > 0 ? { targetSessionIds } : {}),
      ...(excludeSessionId ? { excludeSessionId } : {}),
      ...(excludeSessionIds && excludeSessionIds.length > 0 ? { excludeSessionIds } : {}),
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
    this.unsubscribeInvalidate?.();
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

  private disconnectUserClientsSilently(userId: string): void {
    const clientIds = [...(this.clientsByUser.get(userId) ?? [])];
    for (const clientId of clientIds) {
      const client = this.clients.get(clientId);
      this.unregisterClient(clientId);
      try {
        client?.close();
      } catch {
        // Ignore close error on reconnecting client
      }
    }
  }

  private disconnectClientsSilently(predicate: (client: ActiveSseClient) => boolean): void {
    const toClose: ActiveSseClient[] = [];
    for (const client of this.clients.values()) {
      if (predicate(client)) {
        toClose.push(client);
      }
    }
    for (const client of toClose) {
      this.unregisterClient(client.id);
      try {
        client.close();
      } catch {
        // Ignore close error on reconnecting client
      }
    }
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
   * Thuật toán: Lọc phạm vi nhận sự kiện Zero-Trust (`targetUserIds` ∪ `targetRoles`), kiểm tra `expiresAtMs` và phạm vi phòng ban `allowedDeptIds` (`BUG-063`).
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

    const nowMs = Date.now();
    const staleClientIds: string[] = [];
    const expiredClients: ActiveSseClient[] = [];
    const revokedClients: ActiveSseClient[] = [];
    const shouldCloseAfterDelivery = envelope.type === 'USER_SESSION_REVOKED';
    const sessionFilterSet =
      Array.isArray(envelope.targetSessionIds) && envelope.targetSessionIds.length > 0
        ? new Set(envelope.targetSessionIds)
        : null;
    const excludedSessionSet = new Set<string>();
    if (envelope.excludeSessionId) {
      excludedSessionSet.add(envelope.excludeSessionId);
    }
    if (Array.isArray(envelope.excludeSessionIds)) {
      for (const sid of envelope.excludeSessionIds) {
        if (typeof sid === 'string' && sid.length > 0) excludedSessionSet.add(sid);
      }
    }

    const isDeptScopedEvent =
      SOC_DEPARTMENT_SCOPED_EVENTS.has(envelope.type) || envelope.targetDepartmentId !== undefined;

    for (const client of this.clients.values()) {
      if (client.expiresAtMs !== undefined && nowMs >= client.expiresAtMs) {
        expiredClients.push(client);
        continue;
      }

      const matchedUser = userSet !== null && userSet.has(client.userId);
      const matchedExplicitRole =
        roleSet !== null && [...client.roles].some((role) => roleSet.has(role));
      const matchedSocCapability =
        roleSet !== null &&
        roleSet.has('SECURITY_OFFICER') &&
        client.allowedSocEvents !== undefined &&
        client.allowedSocEvents.has(envelope.type);
      const matchedRole = matchedExplicitRole || matchedSocCapability;
      if (!matchedUser && !matchedRole) continue;

      // HIGH-10: Nếu client chỉ khớp qua vai trò/năng lực SOC (không nằm trong `targetUserIds` cá nhân), cưỡng chế lọc chính xác theo từng loại sự kiện SOC và phạm vi phòng ban `allowedDeptIdsByEvent` / `allowedDeptIds`.
      if (!matchedUser && matchedRole && isDeptScopedEvent) {
        const scopedDepts = client.allowedDeptIdsByEvent?.has(envelope.type)
          ? client.allowedDeptIdsByEvent.get(envelope.type)
          : client.allowedDeptIds;
        if (scopedDepts !== undefined && scopedDepts !== null) {
          if (!envelope.targetDepartmentId || !scopedDepts.has(envelope.targetDepartmentId)) {
            continue;
          }
        }
      }

      if (
        sessionFilterSet !== null &&
        (!client.sessionId || !sessionFilterSet.has(client.sessionId))
      ) {
        continue;
      }
      if (client.sessionId && excludedSessionSet.has(client.sessionId)) {
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
    for (const expired of expiredClients) {
      this.unregisterClient(expired.id);
      try {
        expired.close();
      } catch {
        // Ignore close error on expired socket
      }
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
      const nowMs = Date.now();
      const stale: string[] = [];
      const expired: ActiveSseClient[] = [];
      for (const client of this.clients.values()) {
        if (client.expiresAtMs !== undefined && nowMs >= client.expiresAtMs) {
          expired.push(client);
          continue;
        }
        if (!client.writeFrame(': heartbeat\n\n')) {
          stale.push(client.id);
        }
      }
      for (const id of stale) {
        this.unregisterClient(id);
      }
      for (const client of expired) {
        this.unregisterClient(client.id);
        try {
          client.close();
        } catch {
          // Ignore close error on expired socket
        }
      }
    }, HEARTBEAT_INTERVAL_MS);
    this.heartbeatTimer.unref();
  }
}

/**
 * Module: NotificationsService — Điều phối thông báo đa kênh (`IN_APP`, `EMAIL`, `BOTH`) kết hợp hộp thư đi giao dịch (Transactional Outbox Pattern) chống gửi trùng lặp.
 */
import { Injectable, NotFoundException, Logger, Optional } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { getDatabaseClient, type Prisma } from '@sda/database';
import { AppErrorCode, type QueryNotificationsInput } from '@sda/contracts';
import { enqueueNotificationOutbox } from './notification-outbox.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface SendNotificationOptions {
  recipientId: bigint;
  notificationType: string;
  title: string;
  body: string;
  relatedObjectType?: string;
  relatedObjectId?: string;
  channel?: 'IN_APP' | 'EMAIL' | 'BOTH';
  deduplicationKey?: string;
  payload?: Record<string, unknown>;
}

export interface SendNotificationResult {
  notificationId?: string | undefined;
  outboxId?: string | undefined;
  isDuplicate: boolean;
}

@Injectable()
export class NotificationsService {
  private readonly logger = new Logger(NotificationsService.name);
  private readonly database: PrismaClient;

  constructor(@Optional() databaseClient?: PrismaClient) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Thuật toán: Phân nhánh thông báo đa kênh kèm khóa khử trùng lặp tổ hợp (Dual-Channel Fan-Out with Composite Deduplication Key)
   * Mục đích: Đồng thời lưu thông báo nội bộ trong ứng dụng và xếp hàng gửi thư điện tử tin cậy mà không phát sinh thư rác lặp lại khi thử lại.
   * Cơ chế hoạt động:
   *   - Tổng hợp khóa định danh duy nhất `dedupKey = <type>:<recipientId>:<objectType>:<objectId>` (hoặc nhận khóa truyền vào).
   *   - Nhánh `IN_APP`/`BOTH`: tạo bản ghi trạng thái `UNREAD` chịu lỗi cô lập (không làm gãy luồng nghiệp vụ chính nếu lỗi ghi thông báo).
   *   - Nhánh `EMAIL`/`BOTH`: đẩy vào hộp thư đi lũy đẳng qua `enqueueNotificationOutbox` gắn ràng buộc duy nhất trên `deduplication_key`.
   *
   * Algorithm: Dual-Channel Notification Fan-Out with Deduplication Key.
   * Persists in-app notification state when channel includes IN_APP and delegates
   * idempotent email queuing to the transactional outbox helper when channel includes EMAIL.
   */
  async sendNotification(options: SendNotificationOptions): Promise<SendNotificationResult> {
    const channel = options.channel ?? 'BOTH';
    const dedupKey =
      options.deduplicationKey ??
      `${options.notificationType}:${options.recipientId}:${options.relatedObjectType ?? 'none'}:${options.relatedObjectId ?? 'none'}`;

    let notificationId: string | undefined;
    let outboxId: string | undefined;
    let isDuplicate = false;

    if (channel === 'IN_APP' || channel === 'BOTH') {
      notificationId = randomUUID();
      try {
        await this.database.notification.create({
          data: {
            id: notificationId,
            recipient_id: options.recipientId,
            notification_type: options.notificationType,
            title: options.title,
            body: options.body,
            related_object_type: options.relatedObjectType ?? null,
            related_object_id: options.relatedObjectId ?? null,
            status: 'UNREAD',
          },
        });
      } catch (err) {
        this.logger.warn(`Failed to create in-app notification:`, err);
      }
    }

    if (channel === 'EMAIL' || channel === 'BOTH') {
      const outbox = await enqueueNotificationOutbox(this.database, this.logger, {
        recipientId: options.recipientId,
        notificationType: options.notificationType,
        title: options.title,
        body: options.body,
        ...(options.payload !== undefined ? { payload: options.payload } : {}),
        dedupKey,
      });
      outboxId = outbox.outboxId;
      isDuplicate = outbox.isDuplicate;
    }

    return { notificationId, outboxId, isDuplicate };
  }

  /**
   * Thuật toán: Phân trang đọc trước N+1 hộp thư thông báo người dùng (Lookahead N+1 Notification Pagination)
   * Mục đích: Liệt kê thông báo của riêng người dùng sắp xếp mới nhất trước mà không tốn truy vấn đếm tổng `COUNT(*)`.
   * Cơ chế hoạt động:
   *   - Truy vấn `take = pageSize + 1` và `skip = (page - 1) * pageSize`; nếu số bản ghi trả về lớn hơn `pageSize` thì xác định `hasMore = true` và cắt đúng `pageSize` phần tử.
   *
   * Algorithm: Lookahead Paginated Notification Query (`pageSize + 1` slice).
   * Queries one extra row beyond `pageSize` to compute `hasMore` without a separate COUNT(*) query.
   */
  async listUserNotifications(
    userId: bigint,
    query: QueryNotificationsInput,
  ): Promise<{
    data: Array<{
      id: string;
      notificationType: string;
      title: string;
      body: string;
      relatedObjectType: string | null;
      relatedObjectId: string | null;
      status: string;
      createdAt: string;
      readAt: string | null;
    }>;
    page: number;
    pageSize: number;
    hasMore: boolean;
  }> {
    const where: Prisma.NotificationWhereInput = {
      recipient_id: userId,
      ...(query.status ? { status: query.status } : {}),
    };

    const take = query.pageSize + 1;
    const skip = (query.page - 1) * query.pageSize;

    const items = await this.database.notification.findMany({
      where,
      orderBy: { created_at: 'desc' },
      take,
      skip,
    });

    const hasMore = items.length > query.pageSize;
    const resultItems = hasMore ? items.slice(0, query.pageSize) : items;

    return {
      data: resultItems.map((n) => ({
        id: n.id,
        notificationType: n.notification_type,
        title: n.title,
        body: n.body,
        relatedObjectType: n.related_object_type,
        relatedObjectId: n.related_object_id,
        status: n.status,
        createdAt: n.created_at.toISOString(),
        readAt: n.read_at?.toISOString() ?? null,
      })),
      page: query.page,
      pageSize: query.pageSize,
      hasMore,
    };
  }

  /**
   * Thuật toán: Chuyển trạng thái đã đọc lũy đẳng có kiểm tra quyền sở hữu (Owner-Scoped Idempotent Read Transition)
   * Mục đích: Đánh dấu thông báo từ `UNREAD` sang `READ` và ngăn người dùng thao tác trên thông báo của người khác (chống IDOR).
   * Cơ chế hoạt động:
   *   - Truy vấn kết hợp cặp điều kiện `(id = notificationId AND recipient_id = userId)`; ném `404` nếu không khớp, và chỉ cập nhật `status = 'READ'` kèm `read_at` khi trạng thái hiện tại là `UNREAD`.
   *
   * Algorithm: Owner-Scoped Idempotent Read-State Transition.
   * Verifies recipient ownership before transitioning UNREAD -> READ with timestamp.
   */
  async markAsRead(notificationId: string, userId: bigint): Promise<void> {
    const item = await this.database.notification.findFirst({
      where: { id: notificationId, recipient_id: userId },
    });

    if (!item) {
      throw new NotFoundException({
        errorCode: AppErrorCode.NOTIFICATION_NOT_FOUND,
        message: `Notification ${notificationId} was not found.`,
      });
    }

    if (item.status === 'UNREAD') {
      await this.database.notification.update({
        where: { id: notificationId },
        data: {
          status: 'READ',
          read_at: new Date(),
        },
      });
    }
  }
}
